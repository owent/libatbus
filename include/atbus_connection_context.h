// Copyright 2026 atframework

#pragma once

#include <design_pattern/nomovable.h>
#include <design_pattern/noncopyable.h>
#include <gsl/select-gsl.h>
#include <memory/rc_ptr.h>

#include "detail/libatbus_config.h"

namespace atframework {
namespace atbus {
namespace protocol {
class message_body;
}  // namespace protocol
}  // namespace atbus
}  // namespace atframework

ATBUS_MACRO_NAMESPACE_BEGIN

class ATFW_UTIL_SYMBOL_VISIBLE connection_context final {
  UTIL_DESIGN_PATTERN_NOCOPYABLE(connection_context)
  UTIL_DESIGN_PATTERN_NOMOVABLE(connection_context)

 public:
  using ptr_t = atfw::util::memory::strong_rc_ptr<connection_context>;

 private:
  struct ctor_guard_type {};

 public:
  ATBUS_MACRO_API connection_context(ctor_guard_type &);
  ATBUS_MACRO_API ~connection_context();

  static ATBUS_MACRO_API ptr_t create();

  ATBUS_MACRO_API size_t padding_size(size_t origin_size) const noexcept;

  ATBUS_MACRO_API int pack_body(const protocol::message_body &body, size_t expect_size, gsl::span<unsigned char> buffer,
                                size_t &used_size) noexcept;

  ATBUS_MACRO_API int unpack_body(protocol::message_body &body, size_t expect_size,
                                  gsl::span<const unsigned char> buffer) noexcept;

 private:
};
ATBUS_MACRO_NAMESPACE_END
