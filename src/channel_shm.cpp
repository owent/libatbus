/**
 * @brief 所有channel文件的模式均为 c + channel<br />
 *        使用c的模式是为了简单、结构清晰并且避免异常<br />
 *        附带c++的部分是为了避免命名空间污染并且c++的跨平台适配更加简单
 */

#include <assert.h>
#include <stdint.h>
#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <map>
#include <memory>
#include <string>

#include "detail/libatbus_adapter_libuv.h"

#include "lock/atomic_int_type.h"
#include "lock/spin_lock.h"

#include "detail/libatbus_channel_export.h"
#include "detail/libatbus_error.h"

// spin_lock and lock_holder will include Windows.h, which should be included after Winsock2.h
#include "common/string_oprs.h"
#include "lock/lock_holder.h"
#include "lock/spin_lock.h"

#ifdef WIN32
#  include <Windows.h>

#  ifdef _MSC_VER
#    include <atlconv.h>
#  endif

#  ifdef UNICODE
#    define ATBUS_VC_TEXT(x) A2W(x)
#  else
#    define ATBUS_VC_TEXT(x) x
#  endif

#else
#  include <fcntl.h> /* For O_* constants */
#  include <sys/mman.h>
#  include <sys/stat.h> /* For mode constants */
#  include <sys/types.h>
#  include <unistd.h>
#endif
#ifdef ATBUS_CHANNEL_SHM

namespace atbus {
namespace channel {

struct shm_channel {};

struct shm_conf {};

union shm_channel_switcher {
  shm_channel *shm;
  mem_channel *mem;
};

union shm_conf_cswitcher {
  const shm_conf *shm;
  const mem_conf *mem;
};

#  ifdef WIN32
struct shm_mapped_handle_info {
  HANDLE handle;
  LPCTSTR buffer;
  size_t size;
};
#  else
struct shm_mapped_handle_info {
  int shm_id;
  int shm_fd;
  std::string shm_path;
  void *buffer;
  size_t size;
};
#  endif
struct shm_mapped_record_type {
  shm_mapped_handle_info handle;
  util::lock::atomic_int_type<size_t> reference_count;
};

using shm_mapped_by_key_t = ATBUS_ADVANCE_TYPE_MAP(std::string, std::shared_ptr<shm_mapped_record_type>);
static shm_mapped_by_key_t shm_mapped_by_key_records;
static ::util::lock::spin_lock shm_mapped_records_lock;

static std::pair<std::string, int64_t> shm_normalize_path(const char *in) {
  std::pair<std::string, int64_t> ret;
  ret.second = 0;

  if (nullptr == in || 0 == *in) {
    return ret;
  }

  if ('/' == *in || '\\' == *in) {
    ret.first.push_back('/');
    ret.first += &in[1];
  } else {
    util::string::str2int(ret.second, in);
    char key_buf[32] = {0};
    util::string::int2str(key_buf, 31, ret.second);
    ret.first = &key_buf[0];
  }

#  ifdef WIN32
  std::transform(ret.first.begin(), ret.first.end(), ret.first.begin(), util::string::tolower<char>);
#  endif
  return ret;
}

static bool shm_verify_path(const std::string &shm_path) {
  if (shm_path.empty()) {
    return false;
  }
#  ifdef WIN32
  // 248 = 255 - strlen("Global\")
  if (shm_path.size() > 248) {
    return false;
  }
#  else
  if (shm_path.size() > NAME_MAX) {
    return false;
  }
#  endif
  if (shm_path[0] != '/') {
    return true;
  }

  for (std::string::size_type i = 1; i < shm_path.size(); ++i) {
    if (!shm_path[i] || shm_path[i] == '/') {
      return false;
    }
  }

  return true;
}

static int shm_close_buffer(const char *input_path) {
  std::pair<std::string, int64_t> shm_path = shm_normalize_path(input_path);
  // check path
  if (!shm_verify_path(shm_path.first)) {
    return EN_ATBUS_ERR_SHM_PATH_INVALID;
  }

  ::util::lock::lock_holder< ::util::lock::spin_lock> lock_guard(shm_mapped_records_lock);

  shm_mapped_by_key_t::iterator iter = shm_mapped_by_key_records.find(shm_path.first);
  if (shm_mapped_by_key_records.end() == iter) return EN_ATBUS_ERR_SHM_NOT_FOUND;

  assert(iter->second);
  assert(iter->second->reference_count.load() > 0);
  if ((--iter->second->reference_count) > 0) {
    return EN_ATBUS_ERR_SUCCESS;
  } else {
    iter->second->reference_count = 0;
  }

  shm_mapped_handle_info handle = iter->second->handle;
  shm_mapped_by_key_records.erase(iter);

#  ifdef WIN32
  UnmapViewOfFile(handle.buffer);
  CloseHandle(handle.handle);
#  else
  if (handle.shm_path.empty()) {
    // record with shmget/shmat/shmdt mode
    int res = shmdt(handle.buffer);
    if (-1 == res) {
      return EN_ATBUS_ERR_SHM_CLOSE_FAILED;
    }
  } else {
    if (0 != munmap(handle.buffer, handle.size)) {
      shm_unlink(handle.shm_path.c_str());
      return EN_ATBUS_ERR_SHM_CLOSE_FAILED;
    }
    shm_unlink(handle.shm_path.c_str());
  }
#  endif

  return EN_ATBUS_ERR_SUCCESS;
}

static int shm_open_buffer(const char *input_path, size_t len, void **data, size_t *real_size, bool create) {
  std::pair<std::string, int64_t> shm_path = shm_normalize_path(input_path);
  // check path
  if (!shm_verify_path(shm_path.first)) {
    return EN_ATBUS_ERR_SHM_PATH_INVALID;
  }

  ::util::lock::lock_holder< ::util::lock::spin_lock> lock_guard(shm_mapped_records_lock);

  std::shared_ptr<shm_mapped_record_type> shm_record = std::make_shared<shm_mapped_record_type>();
  if (!shm_record) {
    return EN_ATBUS_ERR_MALLOC;
  }

  // 已经映射则直接返回
  {
    shm_mapped_by_key_t::iterator iter = shm_mapped_by_key_records.find(shm_path.first);
    if (shm_mapped_by_key_records.end() != iter) {
      if (data) *data = (void *)iter->second->handle.buffer;
      if (real_size) *real_size = iter->second->handle.size;
      ++iter->second->reference_count;
      return EN_ATBUS_ERR_SUCCESS;
    }
  }

#  ifdef _WIN32
#    ifdef _MSC_VER
  USES_CONVERSION;
#    endif
  memset(&shm_record->handle, 0, sizeof(shm_record->handle));
  SYSTEM_INFO si;
  ::GetSystemInfo(&si);
  // size_t page_size = static_cast<std::size_t>(si.dwPageSize);

  char shm_file_name[256] = {0};
  // Use Global\\ prefix requires the SeCreateGlobalPrivilege privilege, so we do not use it
  UTIL_STRFUNC_SNPRINTF(shm_file_name, sizeof(shm_file_name), "Global\\%s",
                        '/' == shm_path.first[0] ? &shm_path.first[1] : &shm_path.first[0]);

  // 首先尝试直接打开
  shm_record->handle.handle = OpenFileMapping(FILE_MAP_ALL_ACCESS,          // read/write access
                                              FALSE,                        // do not inherit the name
                                              ATBUS_VC_TEXT(shm_file_name)  // name of mapping object
  );
  if (nullptr != shm_record->handle.handle) {
    shm_record->handle.buffer = (LPTSTR)MapViewOfFile(shm_record->handle.handle,  // handle to map object
                                                      FILE_MAP_ALL_ACCESS,        // read/write permission
                                                      0, 0, len);

    if (nullptr == shm_record->handle.buffer) {
      CloseHandle(shm_record->handle.handle);
      return EN_ATBUS_ERR_SHM_GET_FAILED;
    }

    if (data) *data = (void *)shm_record->handle.buffer;
    if (real_size) *real_size = len;

    shm_record->handle.size = len;
    shm_record->reference_count.store(1);
    shm_mapped_by_key_records[shm_path.first] = shm_record;
    return EN_ATBUS_ERR_SUCCESS;
  }

  // 如果允许创建则创建
  if (!create) return EN_ATBUS_ERR_SHM_GET_FAILED;

  shm_record->handle.handle = CreateFileMapping(INVALID_HANDLE_VALUE,         // use paging file
                                                nullptr,                      // default security
                                                PAGE_READWRITE,               // read/write access
                                                0,                            // maximum object size (high-order DWORD)
                                                static_cast<DWORD>(len),      // maximum object size (low-order DWORD)
                                                ATBUS_VC_TEXT(shm_file_name)  // name of mapping object
  );

  if (nullptr == shm_record->handle.handle) return EN_ATBUS_ERR_SHM_GET_FAILED;

  shm_record->handle.buffer = (LPTSTR)MapViewOfFile(shm_record->handle.handle,  // handle to map object
                                                    FILE_MAP_ALL_ACCESS,        // read/write permission
                                                    0, 0, len);

  if (nullptr == shm_record->handle.buffer) return EN_ATBUS_ERR_SHM_GET_FAILED;

  shm_record->handle.size = len;
  shm_record->reference_count.store(1);
  shm_mapped_by_key_records[shm_path.first] = shm_record;

  if (data) *data = (void *)shm_record->handle.buffer;
  if (real_size) *real_size = len;

#  else
  // len 长度对齐到分页大小
  size_t page_size = static_cast<size_t>(::sysconf(_SC_PAGESIZE));
  len = (len + page_size - 1) & (~(page_size - 1));

  int shmflag = 0666;
  if (create) shmflag |= IPC_CREAT;

#    ifdef __linux__
  // linux下阻止从交换分区分配物理页
  shmflag |= SHM_NORESERVE;

  // 临时关闭大页表功能，等后续增加了以下判定之后再看情况加回来
  // 使用大页表要先判定 /proc/meminfo 内的一些字段内容，再配置大页表
  // -- Hugepagesize: 大页表的分页大小，如果ATBUS_MACRO_HUGETLB_SIZE小于这个值，要对齐到这个值
  // -- HugePages_Total: 大页表总大小
  // -- HugePages_Free: 大页表可用大小，如果可用值小于需要分配的空间，也不能用大页表
  // #ifdef ATBUS_MACRO_HUGETLB_SIZE
  //            // 如果大于4倍的大页表，则对齐到大页表并使用大页表
  //            if (len > (4 * ATBUS_MACRO_HUGETLB_SIZE)) {
  //                len = (len + (ATBUS_MACRO_HUGETLB_SIZE)-1) & (~((ATBUS_MACRO_HUGETLB_SIZE)-1));
  //                shmflag |= SHM_HUGETLB;
  //            }
  // #endif

#    endif
  // create record with shmget/shmat/shmdt mode
  if (0 == shm_path.second) {
    shm_record->handle.shm_id = 0;
    shm_record->handle.shm_path = shm_path.first;

    int open_flag = O_RDWR;
    if (create) {
      open_flag |= O_CREAT;
    }
    shm_record->handle.shm_fd =
        shm_open(shm_path.first.c_str(), open_flag, S_IRWXU | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
    if (-1 == shm_record->handle.shm_fd) return EN_ATBUS_ERR_SHM_GET_FAILED;
    struct stat statbuf;
    if (0 != fstat(shm_record->handle.shm_fd, &statbuf)) {
      shm_unlink(shm_path.first.c_str());
      return EN_ATBUS_ERR_SHM_GET_FAILED;
    }

    if (statbuf.st_size <= 0) {
      if (0 != ftruncate(shm_record->handle.shm_fd, (off_t)len)) {
        shm_unlink(shm_path.first.c_str());
        return EN_ATBUS_ERR_SHM_GET_FAILED;
      }

      if (0 != fstat(shm_record->handle.shm_fd, &statbuf)) {
        shm_unlink(shm_path.first.c_str());
        return EN_ATBUS_ERR_SHM_GET_FAILED;
      }

      shm_record->handle.size = static_cast<size_t>(statbuf.st_size);
    } else {
      shm_record->handle.size = static_cast<size_t>(statbuf.st_size);
    }

    int shm_map_flag = MAP_SHARED;
#    ifdef __linux__
    shm_map_flag |= MAP_NORESERVE;
#    endif
    shm_record->handle.buffer =
        mmap(nullptr, shm_record->handle.size, PROT_READ | PROT_WRITE, shm_map_flag, shm_record->handle.shm_fd, 0);
    if (MAP_FAILED == shm_record->handle.buffer) {
      shm_unlink(shm_path.first.c_str());
      return EN_ATBUS_ERR_SHM_MAP_FAILED;
    }
  } else {
    shm_record->handle.shm_id = shmget(static_cast<key_t>(shm_path.second), len, shmflag);
    shm_record->handle.shm_fd = 0;
    shm_record->handle.shm_path.clear();
    if (-1 == shm_record->handle.shm_id) return EN_ATBUS_ERR_SHM_GET_FAILED;

    // 获取实际长度
    {
      struct shmid_ds shm_info;
      if (shmctl(shm_record->handle.shm_id, IPC_STAT, &shm_info)) return EN_ATBUS_ERR_SHM_GET_FAILED;

      shm_record->handle.size = shm_info.shm_segsz;
    }

    // 获取地址
    shm_record->handle.buffer = shmat(shm_record->handle.shm_id, nullptr, 0);
    shm_record->reference_count.store(1);
  }

  shm_mapped_by_key_records[shm_path.first] = shm_record;

  if (data) *data = shm_record->handle.buffer;
  if (real_size) {
    *real_size = shm_record->handle.size;
  }

#  endif

  return EN_ATBUS_ERR_SUCCESS;
}

ATBUS_MACRO_API int shm_configure_set_write_timeout(shm_channel *channel, uint64_t ms) {
  shm_channel_switcher switcher;
  switcher.shm = channel;
  return mem_configure_set_write_timeout(switcher.mem, ms);
}

ATBUS_MACRO_API uint64_t shm_configure_get_write_timeout(shm_channel *channel) {
  shm_channel_switcher switcher;
  switcher.shm = channel;
  return mem_configure_get_write_timeout(switcher.mem);
}

ATBUS_MACRO_API int shm_configure_set_write_retry_times(shm_channel *channel, size_t times) {
  shm_channel_switcher switcher;
  switcher.shm = channel;
  return mem_configure_set_write_retry_times(switcher.mem, times);
}

ATBUS_MACRO_API size_t shm_configure_get_write_retry_times(shm_channel *channel) {
  shm_channel_switcher switcher;
  switcher.shm = channel;
  return mem_configure_get_write_retry_times(switcher.mem);
}

ATBUS_MACRO_API uint16_t shm_info_get_version(shm_channel *channel) {
  shm_channel_switcher switcher;
  switcher.shm = channel;
  return mem_info_get_version(switcher.mem);
}

ATBUS_MACRO_API uint16_t shm_info_get_align_size(shm_channel *channel) {
  shm_channel_switcher switcher;
  switcher.shm = channel;
  return mem_info_get_align_size(switcher.mem);
}

ATBUS_MACRO_API uint16_t shm_info_get_host_size(shm_channel *channel) {
  shm_channel_switcher switcher;
  switcher.shm = channel;
  return mem_info_get_host_size(switcher.mem);
}

ATBUS_MACRO_API int shm_attach(const char *shm_path, size_t len, shm_channel **channel, const shm_conf *conf) {
  shm_channel_switcher channel_s;
  shm_conf_cswitcher conf_s;
  conf_s.shm = conf;

  size_t real_size;
  void *buffer;
  int ret = shm_open_buffer(shm_path, len, &buffer, &real_size, false);
  if (ret < 0) return ret;

  ret = mem_attach(buffer, real_size, &channel_s.mem, conf_s.mem);
  if (ret < 0) {
    shm_close_buffer(shm_path);
    return ret;
  }

  if (channel) *channel = channel_s.shm;

  return ret;
}

ATBUS_MACRO_API int shm_init(const char *shm_path, size_t len, shm_channel **channel, const shm_conf *conf) {
  shm_channel_switcher channel_s;
  shm_conf_cswitcher conf_s;
  conf_s.shm = conf;

  size_t real_size;
  void *buffer;
  int ret = shm_open_buffer(shm_path, len, &buffer, &real_size, true);
  if (ret < 0) return ret;

  ret = mem_init(buffer, real_size, &channel_s.mem, conf_s.mem);
  if (ret < 0) {
    shm_close_buffer(shm_path);
    return ret;
  }

  if (channel) *channel = channel_s.shm;

  return ret;
}

ATBUS_MACRO_API int shm_close(const char *shm_path) { return shm_close_buffer(shm_path); }

ATBUS_MACRO_API int shm_send(shm_channel *channel, const void *buf, size_t len) {
  shm_channel_switcher switcher;
  switcher.shm = channel;
  return mem_send(switcher.mem, buf, len);
}

ATBUS_MACRO_API int shm_recv(shm_channel *channel, void *buf, size_t len, size_t *recv_size) {
  shm_channel_switcher switcher;
  switcher.shm = channel;
  return mem_recv(switcher.mem, buf, len, recv_size);
}

ATBUS_MACRO_API std::pair<size_t, size_t> shm_last_action() { return mem_last_action(); }

ATBUS_MACRO_API void shm_show_channel(shm_channel *channel, std::ostream &out, bool need_node_status,
                                      size_t need_node_data) {
  shm_channel_switcher switcher;
  switcher.shm = channel;
  mem_show_channel(switcher.mem, out, need_node_status, need_node_data);
}

ATBUS_MACRO_API void shm_stats_get_error(shm_channel *channel, shm_stats_block_error &out) {
  shm_channel_switcher switcher;
  switcher.shm = channel;
  mem_stats_get_error(switcher.mem, out);
}

}  // namespace channel
}  // namespace atbus

#endif
