// Copyright 2025 atframework
// Created by owent on 2025/12/16.
//

#include "detail/libatbus_error.h"

#include <common/string_oprs.h>

#include <string>
#include <system_error>
#include <unordered_map>

namespace {

// Maintain a single source of truth for known errors.
#define LIBATBUS_ERROR_MESSAGE_MAP(XX)                                                   \
  XX(EN_ATBUS_ERR_SUCCESS, "success")                                                    \
  XX(EN_ATBUS_ERR_PARAMS, "ATBUS parameter error")                                       \
  XX(EN_ATBUS_ERR_INNER, "ATBUS inner error")                                            \
  XX(EN_ATBUS_ERR_NO_DATA, "no data")                                                    \
  XX(EN_ATBUS_ERR_BUFF_LIMIT, "buffer limit")                                            \
  XX(EN_ATBUS_ERR_MALLOC, "memory allocation failed")                                    \
  XX(EN_ATBUS_ERR_SCHEME, "protocol error")                                              \
  XX(EN_ATBUS_ERR_BAD_DATA, "bad data")                                                  \
  XX(EN_ATBUS_ERR_INVALID_SIZE, "invalid size")                                          \
  XX(EN_ATBUS_ERR_NOT_INITED, "not initialized")                                         \
  XX(EN_ATBUS_ERR_ALREADY_INITED, "already initialized")                                 \
  XX(EN_ATBUS_ERR_ACCESS_DENY, "access denied")                                          \
  XX(EN_ATBUS_ERR_UNPACK, "unpack failed")                                               \
  XX(EN_ATBUS_ERR_PACK, "pack failed")                                                   \
  XX(EN_ATBUS_ERR_UNSUPPORTED_VERSION, "unsupported version")                            \
  XX(EN_ATBUS_ERR_CLOSING, "closing")                                                    \
  XX(EN_ATBUS_ERR_ALGORITHM_NOT_SUPPORT, "algorithm not supported")                      \
  XX(EN_ATBUS_ERR_MESSAGE_NOT_FINISH_YET, "message not finished yet")                    \
  XX(EN_ATBUS_ERR_ATNODE_NOT_FOUND, "target node not found")                             \
  XX(EN_ATBUS_ERR_ATNODE_INVALID_ID, "invalid node id")                                  \
  XX(EN_ATBUS_ERR_ATNODE_NO_CONNECTION, "no connection")                                 \
  XX(EN_ATBUS_ERR_ATNODE_FAULT_TOLERANT, "exceeded fault tolerant")                      \
  XX(EN_ATBUS_ERR_ATNODE_INVALID_MSG, "invalid message")                                 \
  XX(EN_ATBUS_ERR_ATNODE_BUS_ID_NOT_MATCH, "bus id not match")                           \
  XX(EN_ATBUS_ERR_ATNODE_TTL, "ttl limited")                                             \
  XX(EN_ATBUS_ERR_ATNODE_MASK_CONFLICT, "mask conflict")                                 \
  XX(EN_ATBUS_ERR_ATNODE_ID_CONFLICT, "id conflict")                                     \
  XX(EN_ATBUS_ERR_ATNODE_SRC_DST_IS_SAME, "source and destination are the same")         \
  XX(EN_ATBUS_ERR_CHANNEL_SIZE_TOO_SMALL, "channel size too small")                      \
  XX(EN_ATBUS_ERR_CHANNEL_BUFFER_INVALID, "channel buffer invalid")                      \
  XX(EN_ATBUS_ERR_CHANNEL_ADDR_INVALID, "channel address invalid")                       \
  XX(EN_ATBUS_ERR_CHANNEL_CLOSING, "channel closing")                                    \
  XX(EN_ATBUS_ERR_CHANNEL_NOT_SUPPORT, "channel not supported")                          \
  XX(EN_ATBUS_ERR_CHANNEL_UNSUPPORTED_VERSION, "channel unsupported version")            \
  XX(EN_ATBUS_ERR_CHANNEL_ALIGN_SIZE_MISMATCH, "channel align size mismatch")            \
  XX(EN_ATBUS_ERR_CHANNEL_ARCH_SIZE_T_MISMATCH, "channel architecture size_t mismatch")  \
  XX(EN_ATBUS_ERR_NODE_BAD_BLOCK_NODE_NUM, "corrupted node block - node count error")    \
  XX(EN_ATBUS_ERR_NODE_BAD_BLOCK_BUFF_SIZE, "corrupted node block - buffer size error")  \
  XX(EN_ATBUS_ERR_NODE_BAD_BLOCK_WSEQ_ID, "corrupted node block - write sequence error") \
  XX(EN_ATBUS_ERR_NODE_BAD_BLOCK_CSEQ_ID, "corrupted node block - check sequence error") \
  XX(EN_ATBUS_ERR_NODE_TIMEOUT, "operation timeout")                                     \
  XX(EN_ATBUS_ERR_SHM_GET_FAILED, "shared memory get failed")                            \
  XX(EN_ATBUS_ERR_SHM_NOT_FOUND, "shared memory not found")                              \
  XX(EN_ATBUS_ERR_SHM_CLOSE_FAILED, "shared memory close failed")                        \
  XX(EN_ATBUS_ERR_SHM_PATH_INVALID, "shared memory path invalid")                        \
  XX(EN_ATBUS_ERR_SHM_MAP_FAILED, "shared memory map failed")                            \
  XX(EN_ATBUS_ERR_SOCK_BIND_FAILED, "socket bind failed")                                \
  XX(EN_ATBUS_ERR_SOCK_LISTEN_FAILED, "socket listen failed")                            \
  XX(EN_ATBUS_ERR_SOCK_CONNECT_FAILED, "socket connect failed")                          \
  XX(EN_ATBUS_ERR_PIPE_BIND_FAILED, "pipe bind failed")                                  \
  XX(EN_ATBUS_ERR_PIPE_LISTEN_FAILED, "pipe listen failed")                              \
  XX(EN_ATBUS_ERR_PIPE_CONNECT_FAILED, "pipe connect failed")                            \
  XX(EN_ATBUS_ERR_PIPE_ADDR_TOO_LONG, "pipe address too long")                           \
  XX(EN_ATBUS_ERR_PIPE_REMOVE_FAILED, "pipe remove old socket failed")                   \
  XX(EN_ATBUS_ERR_PIPE_PATH_EXISTS, "pipe path already exists")                          \
  XX(EN_ATBUS_ERR_PIPE_LOCK_PATH_FAILED, "pipe lock path failed")                        \
  XX(EN_ATBUS_ERR_DNS_GETADDR_FAILED, "dns getaddr failed")                              \
  XX(EN_ATBUS_ERR_CONNECTION_NOT_FOUND, "connection not found")                          \
  XX(EN_ATBUS_ERR_WRITE_FAILED, "write failed")                                          \
  XX(EN_ATBUS_ERR_READ_FAILED, "read failed")                                            \
  XX(EN_ATBUS_ERR_EV_RUN, "event loop run failed")                                       \
  XX(EN_ATBUS_ERR_NO_LISTEN, "no listen")                                                \
  XX(EN_ATBUS_ERR_NOT_READY, "not ready")

inline const char *libatbus_error_name(ATBUS_ERROR_TYPE errcode) noexcept {
  switch (errcode) {
#define LIBATBUS_ERROR_NAME_CASE(CODE, MESSAGE) \
  case CODE:                                    \
    return #CODE;
    LIBATBUS_ERROR_MESSAGE_MAP(LIBATBUS_ERROR_NAME_CASE)
#undef LIBATBUS_ERROR_NAME_CASE
    default:
      return "ATBUS_ERROR_TYPE";
  }
}

template <class CharT>
inline void libatbus_append_ascii(std::basic_string<CharT> &out, const char *s) {
  if (nullptr == s) {
    return;
  }
  for (; '\0' != *s; ++s) {
    out.push_back(static_cast<CharT>(*s));
  }
}

template <class CharT>
inline void libatbus_append_int(std::basic_string<CharT> &out, int v) {
  char buf[32] = {0};
  size_t buf_size = ::atfw::util::string::int2str(buf, sizeof(buf), v);
  for (const char *p = buf; p < buf + buf_size; ++p) {
    out.push_back(static_cast<CharT>(*p));
  }
}

template <class CharT>
inline std::basic_string<CharT> libatbus_build_error_string(ATBUS_ERROR_TYPE code, const char *name,
                                                            const char *message) {
  std::basic_string<CharT> ret;
  ret.reserve(64);
  libatbus_append_ascii(ret, name);
  libatbus_append_ascii(ret, "(");
  libatbus_append_int(ret, static_cast<int>(code));
  libatbus_append_ascii(ret, "): ");
  libatbus_append_ascii(ret, message);
  return ret;
}

template <class CharT>
inline const std::basic_string<CharT> &libatbus_strerror_cached(ATBUS_ERROR_TYPE errcode) noexcept {
  // Known error cache:
  // - immutable after initialization (C++11 static init is thread-safe)
  // - lock-free concurrent reads.
  static const std::unordered_map<int, std::basic_string<CharT>> known_cache = []() {
    std::unordered_map<int, std::basic_string<CharT>> m;
    m.reserve(128);

#define LIBATBUS_ERROR_CACHE_INSERT(CODE, MESSAGE) \
  m.emplace(static_cast<int>(CODE), libatbus_build_error_string<CharT>(CODE, #CODE, MESSAGE));
    LIBATBUS_ERROR_MESSAGE_MAP(LIBATBUS_ERROR_CACHE_INSERT)
#undef LIBATBUS_ERROR_CACHE_INSERT
    return m;
  }();

  const int key = static_cast<int>(errcode);
  auto known_iter = known_cache.find(key);
  if (known_iter != known_cache.end()) {
    return known_iter->second;
  }

  // Unknown error cache is thread-local to avoid any global locking.
  // This preserves stable references for repeated lookups within the same thread.
  thread_local std::basic_string<CharT> unknown_cache;
  const char *name = libatbus_error_name(errcode);
  unknown_cache = libatbus_build_error_string<CharT>(errcode, name, "unknown");
  return unknown_cache;
}

#undef LIBATBUS_ERROR_MESSAGE_MAP

}  // namespace

ATBUS_MACRO_API const std::basic_string<char> &libatbus_strerror(ATBUS_ERROR_TYPE errcode) noexcept {
  return libatbus_strerror_cached<char>(errcode);
}

ATBUS_MACRO_API const std::basic_string<wchar_t> &libatbus_wstrerror(ATBUS_ERROR_TYPE errcode) noexcept {
  return libatbus_strerror_cached<wchar_t>(errcode);
}

#ifdef __cpp_unicode_characters
ATBUS_MACRO_API const std::basic_string<char16_t> &libatbus_u16strerror(ATBUS_ERROR_TYPE errcode) noexcept {
  return libatbus_strerror_cached<char16_t>(errcode);
}

ATBUS_MACRO_API const std::basic_string<char32_t> &libatbus_u32strerror(ATBUS_ERROR_TYPE errcode) noexcept {
  return libatbus_strerror_cached<char32_t>(errcode);
}
#endif

#if defined(__cpp_char8_t) && (__cpp_char8_t >= 201811L) && (!defined(_HAS_CHAR8_T) || _HAS_CHAR8_T)
ATBUS_MACRO_API const std::basic_string<char8_t> &libatbus_u8strerror(ATBUS_ERROR_TYPE errcode) noexcept {
  return libatbus_strerror_cached<char8_t>(errcode);
}
#endif
