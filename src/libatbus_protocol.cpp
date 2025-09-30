// Copyright 2025 atframework

#include "libatbus_protocol.h"

#include <memory>

namespace atbus {

ATBUS_MACRO_API message::message(const ::google::protobuf::ArenaOptions& options)
    : arena_(std::make_unique<::google::protobuf::Arena>(options)), head_(nullptr), body_(nullptr) {}

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

ATBUS_MACRO_API ::atbus::protocol::message_head& message::mutable_head() {
  if ATFW_UTIL_LIKELY_CONDITION (head_ != nullptr) {
    return *head_;
  }

  if (arena_ == nullptr) {
    if (!inplace_cache_) {
      inplace_cache_ = gsl::make_unique<message_inplace>();
    }

    return inplace_cache_->head;
  }

#if defined(PROTOBUF_VERSION) && PROTOBUF_VERSION >= 5027000
  head_ = ::google::protobuf::Arena::Create<::atbus::protocol::message_head>(arena_.get());
#else
  head_ = ::google::protobuf::Arena::CreateMessage<::atbus::protocol::message_head>(arena_.get());
#endif
  return *head_;
}

ATBUS_MACRO_API ::atbus::protocol::message_body& message::mutable_body() {
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
  body_ = ::google::protobuf::Arena::Create<::atbus::protocol::message_body>(arena_.get());
#else
  body_ = ::google::protobuf::Arena::CreateMessage<::atbus::protocol::message_body>(ararena_ena.get());
#endif
  return *body_;
}

}  // namespace atbus
