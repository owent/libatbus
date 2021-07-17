#include <errno.h>
#include <fcntl.h> /* For O_* constants */
#include <sys/mman.h>
#include <sys/stat.h> /* For mode constants */
#include <sys/types.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>

int main() {
  // GNU libc (>=2.19) validates the shared memory name. Specifically, the shared memory object MUST now be at the root
  // of the shmfs mount point.
  // @see
  // https://stackoverflow.com/questions/23145458/shm-open-fails-with-einval-when-creating-shared-memory-in-subdirectory-of-dev
  // @see https://sourceware.org/git/?p=glibc.git;a=commit;h=b20de2c3d9d751eb259c321426188eefc64fcbe9
  // @see https://sourceware.org/bugzilla/show_bug.cgi?id=16274
  // link with -lrt
  // int test_fd = shm_open("/dev/shm/libatbus-test-shm.bus", O_RDWR | O_CREAT, S_IRWXU | S_IRGRP | S_IWGRP | S_IROTH |
  // S_IWOTH); glibc接口的shm_unlink不允许子目录
#if

  mkdir("/dev/shm/libatbus", S_IRWXU | S_IRWXG | S_IRWXO);
  mkdir("/dev/shm/libatbus/test", S_IRWXU | S_IRWXG | S_IRWXO);
  int test_fd = openat(AT_FDCWD, "/dev/shm/libatbus/test/shm.bus", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC,
                       S_IRWXU | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
  if (test_fd < 0) {
    printf("shm_open failed, err: %d, %s\n", errno, strerror(errno));
    return 1;
  }

  struct stat statbuf;
  if (0 != fstat(test_fd, &statbuf)) {
    printf("fstat failed, err: %d, %s\n", errno, strerror(errno));
    close(test_fd);
    return 1;
  }

  puts("================================ read ================================");
  printf("stat.dev %lld\n", static_cast<long long>(statbuf.st_dev));         /* ID of device containing file */
  printf("stat.ino %lld\n", static_cast<long long>(statbuf.st_ino));         /* Inode number */
  printf("stat.mode %lld\n", static_cast<long long>(statbuf.st_mode));       /* File type and mode */
  printf("stat.nlink %lld\n", static_cast<long long>(statbuf.st_nlink));     /* Number of hard links */
  printf("stat.uid %lld\n", static_cast<long long>(statbuf.st_uid));         /* User ID of owner */
  printf("stat.gid %lld\n", static_cast<long long>(statbuf.st_gid));         /* Group ID of owner */
  printf("stat.dev %lld\n", static_cast<long long>(statbuf.st_rdev));        /* Device ID (if special file) */
  printf("stat.off %lld\n", static_cast<long long>(statbuf.st_size));        /* Total size, in bytes */
  printf("stat.blksize %lld\n", static_cast<long long>(statbuf.st_blksize)); /* Block size for filesystem I/O */
  printf("stat.blkcnt %lld\n", static_cast<long long>(statbuf.st_blocks));   /* Number of 512B blocks allocated */

  if (statbuf.st_size <= 0) {
    if (0 != ftruncate(test_fd, 2 * 1024 * 1024)) {
      printf("ftruncate failed, err: %d, %s\n", errno, strerror(errno));
      close(test_fd);
      return 1;
    }

    if (0 != fstat(test_fd, &statbuf)) {
      printf("fstat failed, err: %d, %s\n", errno, strerror(errno));
      close(test_fd);
      return 1;
    }

    puts("================================ create ================================");
    printf("stat.dev %lld\n", static_cast<long long>(statbuf.st_dev));         /* ID of device containing file */
    printf("stat.ino %lld\n", static_cast<long long>(statbuf.st_ino));         /* Inode number */
    printf("stat.mode %lld\n", static_cast<long long>(statbuf.st_mode));       /* File type and mode */
    printf("stat.nlink %lld\n", static_cast<long long>(statbuf.st_nlink));     /* Number of hard links */
    printf("stat.uid %lld\n", static_cast<long long>(statbuf.st_uid));         /* User ID of owner */
    printf("stat.gid %lld\n", static_cast<long long>(statbuf.st_gid));         /* Group ID of owner */
    printf("stat.dev %lld\n", static_cast<long long>(statbuf.st_rdev));        /* Device ID (if special file) */
    printf("stat.off %lld\n", static_cast<long long>(statbuf.st_size));        /* Total size, in bytes */
    printf("stat.blksize %lld\n", static_cast<long long>(statbuf.st_blksize)); /* Block size for filesystem I/O */
    printf("stat.blkcnt %lld\n", static_cast<long long>(statbuf.st_blocks));   /* Number of 512B blocks allocated */
  }

  int shmflag = MAP_SHARED;

#  ifdef __linux__
  shmflag |= MAP_NORESERVE;
#  endif

  puts("================================ mmap ================================");
  void* access_data = mmap(nullptr, statbuf.st_size, PROT_READ | PROT_WRITE, shmflag, test_fd, 0);
  if (MAP_FAILED == access_data) {
    printf("mmap failed, err: %d, %s\n", errno, strerror(errno));
    close(test_fd);
    return 1;
  }

  for (unsigned int i = 0; i < statbuf.st_size; ++i) {
    (*((unsigned char*)access_data + i)) = (unsigned char)(i & 0xFF);
  }

  if (0 != munmap(access_data, statbuf.st_size)) {
    printf("munmap failed, err: %d, %s\n", errno, strerror(errno));
    close(test_fd);
    return 1;
  }

  close(test_fd);
  return 0;
}
