//
// Created by owent on 2015/8/11.
//

#ifndef LIBATBUS_BUFFER_H
#define LIBATBUS_BUFFER_H

#pragma once

#include <gsl/select-gsl.h>

#include <stdint.h>
#include <algorithm>
#include <list>
#include <memory>
#include <vector>

#include "detail/libatbus_config.h"

#include "design_pattern/nomovable.h"
#include "design_pattern/noncopyable.h"

ATBUS_MACRO_NAMESPACE_BEGIN
namespace detail {
namespace fn {
ATBUS_MACRO_API void *buffer_next(void *pointer, size_t step);
ATBUS_MACRO_API const void *buffer_next(const void *pointer, size_t step);

ATBUS_MACRO_API void *buffer_prev(void *pointer, size_t step);
ATBUS_MACRO_API const void *buffer_prev(const void *pointer, size_t step);

ATBUS_MACRO_API size_t buffer_offset(const void *l, const void *r);

/**
 * @brief try to read a dynamic int from buffer
 * @param out output integer
 * @param pointer buffer address
 * @param s buffer size
 * @note encoding: like protobuf varint, first bit means more or last byte, big endian, padding right
 * @note can not used with signed integer
 * @return how much bytes the integer cost, 0 if failed
 **/
ATBUS_MACRO_API size_t read_vint(uint64_t &out, const void *pointer, size_t s);

/**
 * @brief try to write a dynamic int to buffer
 * @param in input integer
 * @param pointer buffer address
 * @param s buffer size
 * @note encoding: like protobuf varint, first bit means more or last byte, big endian, padding right
 * @note can not used with signed integer
 * @return how much bytes the integer cost, 0 if failed
 **/
ATBUS_MACRO_API size_t write_vint(uint64_t in, void *pointer, size_t s);
}  // namespace fn

class buffer_manager;

/**
 * @brief buffer block, not thread safe
 */
class buffer_block {
 public:
  ATBUS_MACRO_API void *data();
  ATBUS_MACRO_API const void *data() const;
  ATBUS_MACRO_API void *raw_data();
  ATBUS_MACRO_API const void *raw_data() const;

  ATBUS_MACRO_API size_t size() const;

  ATBUS_MACRO_API size_t raw_size() const;

  ATBUS_MACRO_API void *pop(size_t s);

  ATBUS_MACRO_API size_t instance_size() const;

 public:
  /** alloc and init buffer_block **/
  static ATBUS_MACRO_API buffer_block *malloc(size_t s);

  /** destroy and free buffer_block **/
  static ATBUS_MACRO_API void free(buffer_block *p);

  /**
   * @brief init buffer_block as specify address
   * @param pointer data address
   * @param s data max size
   * @param bs buffer size
   * @return unused data address
   **/
  static ATBUS_MACRO_API void *create(void *pointer, size_t s, size_t bs);

  /** init buffer_block as specify address **/
  static ATBUS_MACRO_API void *destroy(buffer_block *p);

  static ATBUS_MACRO_API size_t padding_size(size_t s);
  static ATBUS_MACRO_API size_t head_size(size_t s);
  static ATBUS_MACRO_API size_t full_size(size_t s);

 private:
  friend class buffer_manager;
  size_t size_;
  size_t used_;
  void *pointer_;
};

/**
 * @brief buffer block manager, not thread safe
 */
class buffer_manager {
 public:
  struct limit_t {
    size_t cost_number_;
    size_t cost_size_;

    size_t limit_number_;
    size_t limit_size_;
  };

  UTIL_DESIGN_PATTERN_NOCOPYABLE(buffer_manager)
  UTIL_DESIGN_PATTERN_NOMOVABLE(buffer_manager)

 public:
  ATBUS_MACRO_API buffer_manager();
  ATBUS_MACRO_API ~buffer_manager();

  ATBUS_MACRO_API const limit_t &limit() const;

  /**
   * @brief set limit when in dynamic mode
   * @param max_size size limit of dynamic, set 0 if unlimited
   * @param max_number number limit of dynamic, set 0 if unlimited
   * @return true on success
   */
  ATBUS_MACRO_API bool set_limit(size_t max_size, size_t max_number);

  ATBUS_MACRO_API buffer_block *front();

  ATBUS_MACRO_API int front(void *&pointer, size_t &nread, size_t &nwrite);

  ATBUS_MACRO_API buffer_block *back();

  ATBUS_MACRO_API int back(void *&pointer, size_t &nread, size_t &nwrite);

  ATBUS_MACRO_API int push_back(void *&pointer, size_t s);

  ATBUS_MACRO_API int push_front(void *&pointer, size_t s);

  ATBUS_MACRO_API int pop_back(size_t s, bool free_unwritable = true);

  ATBUS_MACRO_API int pop_front(size_t s, bool free_unwritable = true);

  /**
   * @brief append buffer and merge to the tail of the last buffer block
   * @note if manager is empty now, just like push_back
   * @param pointer output the writable buffer address
   * @param s buffer size
   * @return 0 or error code
   */
  ATBUS_MACRO_API int merge_back(void *&pointer, size_t s);

  /**
   * @brief append buffer and merge to the tail of the first buffer block
   * @note if manager is empty now, just like push_front
   * @param pointer output the writable buffer address
   * @param s buffer size
   * @return 0 or error code
   */
  ATBUS_MACRO_API int merge_front(void *&pointer, size_t s);

  ATBUS_MACRO_API bool empty() const;

  ATBUS_MACRO_API void reset();

  /**
   * @brief set dynamic mode(use malloc when push buffer) or static mode(malloc a huge buffer at once)
   * @param max_size circle buffer size when static mode, 0 when dynamic mode
   * @param max_number buffer number when static mode
   * @note this api will clear buffer data already exists
   */
  ATBUS_MACRO_API void set_mode(size_t max_size, size_t max_number);

  ATBUS_MACRO_API bool is_static_mode() const;
  ATBUS_MACRO_API bool is_dynamic_mode() const;

 private:
  buffer_block *static_front();

  buffer_block *static_back();

  int static_push_back(void *&pointer, size_t s);

  int static_push_front(void *&pointer, size_t s);

  int static_pop_back(size_t s, bool free_unwritable);

  int static_pop_front(size_t s, bool free_unwritable);

  int static_merge_back(void *&pointer, size_t s);

  int static_merge_front(void *&pointer, size_t s);

  bool static_empty() const;

  buffer_block *dynamic_front();

  buffer_block *dynamic_back();

  int dynamic_push_back(void *&pointer, size_t s);

  int dynamic_push_front(void *&pointer, size_t s);

  int dynamic_pop_back(size_t s, bool free_unwritable);

  int dynamic_pop_front(size_t s, bool free_unwritable);

  int dynamic_merge_back(void *&pointer, size_t s);

  int dynamic_merge_front(void *&pointer, size_t s);

  bool dynamic_empty() const;

 private:
  struct static_buffer_t {
    void *buffer_;
    size_t size_;

    size_t head_;
    size_t tail_;
    std::vector<buffer_block *> circle_index_;
  };

  static_buffer_t static_buffer_;
  std::list<buffer_block *> dynamic_buffer_;

  limit_t limit_;
};
}  // namespace detail

/**
 * @brief static buffer block, not thread safe
 */
class ATFW_UTIL_SYMBOL_VISIBLE static_buffer_block {
 private:
  UTIL_DESIGN_PATTERN_NOCOPYABLE(static_buffer_block)

 public:
  ATFW_UTIL_FORCEINLINE static_buffer_block() noexcept : data_(nullptr), size_(0), used_(0) {}
  ATFW_UTIL_FORCEINLINE static_buffer_block(std::unique_ptr<unsigned char[]> &&in, size_t s, size_t used = 0) noexcept
      : data_(std::move(in)), size_(s), used_(used) {}

  ATFW_UTIL_FORCEINLINE ~static_buffer_block() = default;

  ATFW_UTIL_FORCEINLINE static_buffer_block(static_buffer_block &&other)
      : data_(std::move(other.data_)), size_(other.size_), used_(other.used_) {
    other.size_ = 0;
    other.used_ = 0;
  }

  ATFW_UTIL_FORCEINLINE static_buffer_block &operator=(static_buffer_block &&other) {
    if (this != &other) {
      data_ = std::move(other.data_);
      size_ = other.size_;
      used_ = other.used_;
      other.size_ = 0;
      other.used_ = 0;
    }

    return *this;
  }

  ATFW_UTIL_FORCEINLINE unsigned char *data() noexcept { return data_.get(); }

  ATFW_UTIL_FORCEINLINE const unsigned char *data() const noexcept { return data_.get(); }

  ATFW_UTIL_FORCEINLINE size_t size() const noexcept { return size_; }

  ATFW_UTIL_FORCEINLINE size_t used() const noexcept { return used_; }

  ATFW_UTIL_FORCEINLINE void set_used(size_t used) noexcept {
    if (used > size_) {
      used = size_;
    }
    used_ = used;
  }

  ATFW_UTIL_FORCEINLINE gsl::span<unsigned char> max_span() noexcept UTIL_ATTRIBUTE_LIFETIME_BOUND {
    return gsl::span<unsigned char>{data_.get(), size_};
  }

  ATFW_UTIL_FORCEINLINE gsl::span<const unsigned char> max_span() const noexcept UTIL_ATTRIBUTE_LIFETIME_BOUND {
    return gsl::span<const unsigned char>{data_.get(), size_};
  }

  ATFW_UTIL_FORCEINLINE gsl::span<unsigned char> used_span() noexcept UTIL_ATTRIBUTE_LIFETIME_BOUND {
    return gsl::span<unsigned char>{data_.get(), used_};
  }

  ATFW_UTIL_FORCEINLINE gsl::span<const unsigned char> used_span() const noexcept UTIL_ATTRIBUTE_LIFETIME_BOUND {
    return gsl::span<const unsigned char>{data_.get(), used_};
  }

 private:
  std::unique_ptr<unsigned char[]> data_;
  size_t size_;
  size_t used_;
};

ATBUS_MACRO_NAMESPACE_END

#endif  // LIBATBUS_BUFFER_H
