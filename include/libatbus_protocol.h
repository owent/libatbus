/**
 * libatbus.h
 *
 *  Created on: 2014年8月11日
 *      Author: owent
 */

#pragma once

#include <config/compile_optimize.h>
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

namespace atbus {
using msg_t = ::atbus::protocol::msg;

struct ATFW_UTIL_SYMBOL_VISIBLE message {
  std::unique_ptr<::google::protobuf::Arena> arena;
  ::atfw::util::nostd::nullable<::atbus::protocol::message_head*> head;
  ::atfw::util::nostd::nullable<::atbus::protocol::message_body*> body;

  ATFW_UTIL_FORCEINLINE message(const ::google::protobuf::ArenaOptions& options)
      : arena(std::make_unique<::google::protobuf::Arena>(options)), head(nullptr), body(nullptr) {}
  ATFW_UTIL_FORCEINLINE message(std::unique_ptr<::google::protobuf::Arena>&& input_arena)
      : arena(std::move(input_arena)), head(nullptr), body(nullptr) {}

  ~message() = default;

  message(const message&) = delete;
  message& operator=(const message&) = delete;

  message(message&&) = default;
  message& operator=(message&&) = default;
};

}  // namespace atbus

#define ATBUS_MACRO_RESERVED_SIZE 1024

#ifndef ATBUS_MACRO_PROTOBUF_NAMESPACE_ID
#  define ATBUS_MACRO_PROTOBUF_NAMESPACE_ID google::protobuf
#endif
