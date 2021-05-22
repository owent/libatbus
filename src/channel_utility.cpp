/**
 * @brief 所有channel文件的模式均为 c + channel<br />
 *        使用c的模式是为了简单、结构清晰并且避免异常<br />
 *        附带c++的部分是为了避免命名空间污染并且c++的跨平台适配更加简单
 */

#include <cstdio>

#include "common/string_oprs.h"

#include "detail/libatbus_channel_export.h"

namespace atbus {
namespace channel {
ATBUS_MACRO_API bool make_address(const char *in, channel_address_t &addr) {
  addr.address = in;

  // 获取协议
  size_t scheme_end = addr.address.find_first_of("://");
  if (addr.address.npos == scheme_end) {
    return false;
  }

  addr.scheme = addr.address.substr(0, scheme_end);
  size_t port_end = addr.address.find_last_of(":");
  addr.port = 0;
  if (addr.address.npos != port_end && port_end >= scheme_end + 3) {
    UTIL_STRFUNC_SSCANF(addr.address.c_str() + port_end + 1, "%d", &addr.port);
  }

  // 截取域名
  addr.host =
      addr.address.substr(scheme_end + 3, (port_end == addr.address.npos) ? port_end : port_end - scheme_end - 3);

  return true;
}

ATBUS_MACRO_API void make_address(const char *scheme, const char *host, int port, channel_address_t &addr) {
  addr.scheme = scheme;
  addr.host = host;
  addr.port = port;
  addr.address.reserve(addr.scheme.size() + addr.host.size() + 4 + 8);
  addr.address = addr.scheme + "://" + addr.host;

  if (port > 0) {
    char port_str[16] = {0};
    UTIL_STRFUNC_SNPRINTF(port_str, sizeof(port_str), "%d", port);
    addr.address += ":";
    addr.address += &port_str[0];
  }
}

ATBUS_MACRO_API bool is_duplex_address(const char *in) {
  if (NULL == in || !(*in)) {
    return false;
  }

  return false == is_simplex_address(in);
}

ATBUS_MACRO_API bool is_simplex_address(const char *in) {
  if (NULL == in || !(*in)) {
    return false;
  }

  if (0 == UTIL_STRFUNC_STRNCASE_CMP("mem:", in, 4)) {
    return true;
  }

  if (0 == UTIL_STRFUNC_STRNCASE_CMP("shm:", in, 4)) {
    return true;
  }

  return false;
}

ATBUS_MACRO_API bool is_local_host_address(const char *in) {
  if (NULL == in || !(*in)) {
    return false;
  }

  if (is_local_process_address(in)) {
    return true;
  }

  if (0 == UTIL_STRFUNC_STRNCASE_CMP("shm:", in, 4)) {
    return true;
  }

  if (0 == UTIL_STRFUNC_STRNCASE_CMP("unix:", in, 5)) {
    return true;
  }

  return false;
}

ATBUS_MACRO_API bool is_local_process_address(const char *in) {
  if (NULL == in || !(*in)) {
    return false;
  }

  if (0 == UTIL_STRFUNC_STRNCASE_CMP("mem:", in, 4)) {
    return true;
  }

  return false;
}
}  // namespace channel
}  // namespace atbus
