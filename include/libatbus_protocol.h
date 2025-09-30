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

namespace atbus {
struct ATFW_UTIL_SYMBOL_VISIBLE message_inplace {
  ::atbus::protocol::message_head head;
  ::atbus::protocol::message_body body;

  message_inplace(const message_inplace&) = delete;
  message_inplace& operator=(const message_inplace&) = delete;

  message_inplace(message_inplace&&) = default;
  message_inplace& operator=(message_inplace&&) = default;
};

class ATFW_UTIL_SYMBOL_VISIBLE message {
 public:
  ATBUS_MACRO_API message(const ::google::protobuf::ArenaOptions& options);
  ATBUS_MACRO_API message(std::unique_ptr<::google::protobuf::Arena>&& input_arena);

  ATBUS_MACRO_API message(message&&);
  ATBUS_MACRO_API message& operator=(message&&);
  ATBUS_MACRO_API ~message();

  message(const message&) = delete;
  message& operator=(const message&) = delete;

  ATBUS_MACRO_API ::atbus::protocol::message_head& mutable_head();

  ATBUS_MACRO_API ::atbus::protocol::message_body& mutable_body();

 private:
  std::unique_ptr<::google::protobuf::Arena> arena_;
  std::unique_ptr<message_inplace> inplace_cache_;
  ::atfw::util::nostd::nullable<::atbus::protocol::message_head*> head_;
  ::atfw::util::nostd::nullable<::atbus::protocol::message_body*> body_;
};
}  // namespace atbus

#define ATBUS_MACRO_RESERVED_SIZE 1024

#ifndef ATBUS_MACRO_PROTOBUF_NAMESPACE_ID
#  define ATBUS_MACRO_PROTOBUF_NAMESPACE_ID google::protobuf
#endif
