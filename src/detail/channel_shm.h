// Copyright 2026 atframework

#pragma once

#include "detail/libatbus_channel_export.h"

#ifdef ATBUS_CHANNEL_SHM
ATBUS_MACRO_NAMESPACE_BEGIN
namespace channel {
ATFW_UTIL_SYMBOL_LOCAL int shm_attach_or_init(const char *path, size_t len, shm_channel **channel,
                                              const shm_conf *conf);
}
ATBUS_MACRO_NAMESPACE_END
#endif
