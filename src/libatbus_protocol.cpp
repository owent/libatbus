// Copyright 2025 atframework

#include "libatbus_protocol.h"

// clang-format off
#include <config/compiler/protobuf_prefix.h>
// clang-format on

#include <google/protobuf/text_format.h>

// clang-format off
#include <config/compiler/protobuf_suffix.h>
// clang-format on

#include <memory>

ATBUS_MACRO_NAMESPACE_BEGIN

ATBUS_MACRO_API message::message(const ::google::protobuf::ArenaOptions& options)
    : arena_(std::make_unique<::google::protobuf::Arena>(options)), head_(nullptr), body_(nullptr) {
  // TODO(owent): 可以池化arena的初始block以减少内存分配和碎片
}

ATBUS_MACRO_API message::message(std::unique_ptr<::google::protobuf::Arena>&& input_arena)
    : arena_(std::move(input_arena)), head_(nullptr), body_(nullptr) {}

ATBUS_MACRO_API message::message(message&& other)
    : arena_(std::move(other.arena_)),
      inplace_cache_(std::move(other.inplace_cache_)),
      head_(std::move(other.head_)),
      body_(std::move(other.body_)) {}

ATBUS_MACRO_API message& message::operator=(message&& other) {
  if (this != &other) {
    arena_ = std::move(other.arena_);
    inplace_cache_ = std::move(other.inplace_cache_);
    head_ = std::move(other.head_);
    body_ = std::move(other.body_);
  }

  return *this;
}

ATBUS_MACRO_API message::~message() {}

ATBUS_MACRO_API ::atframework::atbus::protocol::message_head& message::mutable_head() {
  if ATFW_UTIL_LIKELY_CONDITION (head_ != nullptr) {
    return *head_;
  }

  if (arena_ == nullptr) {
    if (!inplace_cache_) {
      inplace_cache_ = std::make_unique<message_inplace>();
    }

    return inplace_cache_->head;
  }

#if defined(PROTOBUF_VERSION) && PROTOBUF_VERSION >= 5027000
  head_ = ::google::protobuf::Arena::Create<::atframework::atbus::protocol::message_head>(arena_.get());
#else
  head_ = ::google::protobuf::Arena::CreateMessage<::atframework::atbus::protocol::message_head>(arena_.get());
#endif
  return *head_;
}

ATBUS_MACRO_API ::atframework::atbus::protocol::message_body& message::mutable_body() {
  if ATFW_UTIL_LIKELY_CONDITION (body_ != nullptr) {
    return *body_;
  }

  if (arena_ == nullptr) {
    if (!inplace_cache_) {
      inplace_cache_ = gsl::make_unique<message_inplace>();
    }

    return inplace_cache_->body;
  }

#if defined(PROTOBUF_VERSION) && PROTOBUF_VERSION >= 5027000
  body_ = ::google::protobuf::Arena::Create<::atframework::atbus::protocol::message_body>(arena_.get());
#else
  body_ = ::google::protobuf::Arena::CreateMessage<::atframework::atbus::protocol::message_body>(ararena_ena.get());
#endif
  return *body_;
}

ATBUS_MACRO_API ::atfw::util::nostd::nullable<const ::atframework::atbus::protocol::message_head*> message::get_head()
    const noexcept {
  return head_;
}

ATBUS_MACRO_API ::atfw::util::nostd::nullable<const ::atframework::atbus::protocol::message_body*> message::get_body()
    const noexcept {
  return body_;
}

ATBUS_MACRO_API const ::atframework::atbus::protocol::message_head& message::head() const noexcept {
  if (head_ == nullptr) {
    return ::atframework::atbus::protocol::message_head::default_instance();
  }

  return *head_;
}

ATBUS_MACRO_API const ::atframework::atbus::protocol::message_body& message::body() const noexcept {
  if (body_ == nullptr) {
    return ::atframework::atbus::protocol::message_body::default_instance();
  }

  return *body_;
}

ATBUS_MACRO_API std::string message::get_head_debug_string() const {
  if (head_ == nullptr) {
    return {};
  }

  std::string debug_string;
  // 16K is in bin of tcache in jemalloc, and MEDIUM_PAGE in mimalloc
  debug_string.reserve(16 * 1024);

  ::google::protobuf::TextFormat::Printer printer;
  printer.SetUseUtf8StringEscaping(true);
  // printer.SetExpandAny(true);
  printer.SetUseShortRepeatedPrimitives(true);
  printer.SetSingleLineMode(false);
  printer.SetTruncateStringFieldLongerThan(2048);
  printer.SetPrintMessageFieldsInIndexOrder(false);

  printer.PrintToString(*head_, &debug_string);

  return debug_string;
}

ATBUS_MACRO_API std::string message::get_body_debug_string() const {
  if (body_ == nullptr) {
    return {};
  }

  std::string debug_string;
  // 16K is in bin of tcache in jemalloc, and MEDIUM_PAGE in mimalloc
  debug_string.reserve(16 * 1024);

  ::google::protobuf::TextFormat::Printer printer;
  printer.SetUseUtf8StringEscaping(true);
  // printer.SetExpandAny(true);
  printer.SetUseShortRepeatedPrimitives(true);
  printer.SetSingleLineMode(false);
  printer.SetTruncateStringFieldLongerThan(2048);
  printer.SetPrintMessageFieldsInIndexOrder(false);

  printer.PrintToString(*body_, &debug_string);

  return debug_string;
}

ATBUS_MACRO_API message_body_type message::get_body_type() const noexcept {
  if (body_ == nullptr) {
    return message_body_type::MESSAGE_TYPE_NOT_SET;
  }

  return body_->message_type_case();
}

ATBUS_MACRO_API std::string message::get_unpack_error_message() const noexcept {
  if (body_ != nullptr) {
    return body_->InitializationErrorString();
  }

  if (head_ != nullptr) {
    return head_->InitializationErrorString();
  }

  return {};
}

ATBUS_MACRO_NAMESPACE_END
