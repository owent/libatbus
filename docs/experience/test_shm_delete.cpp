// Copyright 2026 atframework

#include <errno.h>
#include <fcntl.h> /* For O_* constants */
#include <sys/mman.h>
#include <sys/stat.h> /* For mode constants */

#include <cstdio>
#include <cstdlib>
#include <cstring>

int main() {
  // glibc接口的shm_unlink不允许子目录
  // int res = shm_unlink("/libatbus-test-shm.bus");
  int res = unlink("/dev/shm/libatbus/test/shm.bus");
  if (res < 0) {
    printf("shm_unlink failed, err: %d, %s", errno, strerror(errno));
    return 1;
  }

  return 0;
}

