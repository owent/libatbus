/**
 * libatbus.h
 *
 *  Created on: 2014年8月11日
 *      Author: owent
 */

#pragma once

#include <config/compile_optimize.h>
#include <gsl/select-gsl.h>
#include <nostd/nullability.h>

#include <memory>
#include <utility>

#include "detail/libatbus_config.h"

// clang-format off
#  include "config/compiler/protobuf_prefix.h"
// clang-format on

#include "google/protobuf/arena.h"

#include "libatbus_protocol.pb.h"  // NOLINT

// clang-format off
#  include "config/compiler/protobuf_suffix.h"
// clang-format on

ATBUS_MACRO_NAMESPACE_BEGIN
struct ATFW_UTIL_SYMBOL_VISIBLE message_inplace {
  ::atframework::atbus::protocol::message_head head;
  ::atframework::atbus::protocol::message_body body;

  message_inplace(const message_inplace&) = delete;
  message_inplace& operator=(const message_inplace&) = delete;

  message_inplace() = default;
  message_inplace(message_inplace&&) = default;
  message_inplace& operator=(message_inplace&&) = default;
};

using message_body_type = ::atframework::atbus::protocol::message_body::MessageTypeCase;
class ATFW_UTIL_SYMBOL_VISIBLE message {
 public:
  ATBUS_MACRO_API message(const ::google::protobuf::ArenaOptions& options);
  ATBUS_MACRO_API message(std::unique_ptr<::google::protobuf::Arena>&& input_arena);

  ATBUS_MACRO_API message(message&&);
  ATBUS_MACRO_API message& operator=(message&&);
  ATBUS_MACRO_API ~message();

  message(const message&) = delete;
  message& operator=(const message&) = delete;

  ATBUS_MACRO_API ::atframework::atbus::protocol::message_head& mutable_head();

  ATBUS_MACRO_API ::atframework::atbus::protocol::message_body& mutable_body();

  ATBUS_MACRO_API ::atfw::util::nostd::nullable<const ::atframework::atbus::protocol::message_head*> get_head()
      const noexcept;

  ATBUS_MACRO_API ::atfw::util::nostd::nullable<const ::atframework::atbus::protocol::message_body*> get_body()
      const noexcept;

  ATBUS_MACRO_API const ::atframework::atbus::protocol::message_head& head() const noexcept;

  ATBUS_MACRO_API const ::atframework::atbus::protocol::message_body& body() const noexcept;

  ATBUS_MACRO_API std::string get_head_debug_string() const;

  ATBUS_MACRO_API std::string get_body_debug_string() const;

  ATBUS_MACRO_API message_body_type get_body_type() const noexcept;

  ATBUS_MACRO_API std::string get_unpack_error_message() const noexcept;

 private:
  std::unique_ptr<::google::protobuf::Arena> arena_;
  std::unique_ptr<message_inplace> inplace_cache_;
  ::atfw::util::nostd::nullable<::atframework::atbus::protocol::message_head*> head_;
  ::atfw::util::nostd::nullable<::atframework::atbus::protocol::message_body*> body_;
};
ATBUS_MACRO_NAMESPACE_END

#define ATBUS_MACRO_RESERVED_SIZE 1024

#ifndef ATBUS_MACRO_PROTOBUF_NAMESPACE_ID
#  define ATBUS_MACRO_PROTOBUF_NAMESPACE_ID google::protobuf
#endif
