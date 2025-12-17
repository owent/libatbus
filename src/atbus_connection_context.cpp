// Copyright 2025 atframework

#include "atbus_connection_context.h"

#include "detail/libatbus_error.h"
#include "libatbus_protocol.h"

ATBUS_MACRO_NAMESPACE_BEGIN

ATBUS_MACRO_API connection_context::connection_context(ctor_guard_type &) {}

ATBUS_MACRO_API connection_context::~connection_context() {}

ATBUS_MACRO_API connection_context::ptr_t connection_context::create() {
  ctor_guard_type guard;
  return atfw::util::memory::make_strong_rc<connection_context>(guard);
}

ATBUS_MACRO_API size_t connection_context::padding_size(size_t origin_size) const noexcept {
  // TODO: cipher padding
  // TODO: compress padding
  return origin_size;
}

ATBUS_MACRO_API int connection_context::pack_body(const protocol::message_body &body, size_t expect_size,
                                                  gsl::span<unsigned char> buffer, size_t &used_size) noexcept {
  if (expect_size > buffer.size()) {
    return EN_ATBUS_ERR_BUFF_LIMIT;
  }

  used_size = body.ByteSizeLong();
  if (used_size != expect_size) {
    return EN_ATBUS_ERR_INVALID_SIZE;
  }

  // TODO: cipher encrypt
  // TODO: compress

  body.SerializeWithCachedSizesToArray(reinterpret_cast<uint8_t *>(buffer.data()));
  return EN_ATBUS_ERR_SUCCESS;
}

ATBUS_MACRO_API int connection_context::unpack_body(protocol::message_body &body, size_t expect_size,
                                                    gsl::span<const unsigned char> buffer) noexcept {
  if (expect_size > buffer.size()) {
    return EN_ATBUS_ERR_BUFF_LIMIT;
  }

  // TODO: uncompress

  // TODO: cipher decrypt

  if (!body.ParseFromArray(reinterpret_cast<const void *>(buffer.data()), static_cast<int>(expect_size))) {
    return EN_ATBUS_ERR_UNPACK;
  }

  return EN_ATBUS_ERR_SUCCESS;
}

ATBUS_MACRO_NAMESPACE_END
