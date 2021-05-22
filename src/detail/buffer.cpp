//
// Created by 欧文韬 on 2015/8/11.
//

#include <assert.h>
#include <cstdlib>
#include <cstring>

#include "detail/buffer.h"
#include "detail/libatbus_config.h"
#include "detail/libatbus_error.h"

#if (defined(__cplusplus) && __cplusplus >= 201103L) || (defined(_MSC_VER) && _MSC_VER >= 1900)
#  include <type_traits>
#  if (defined(__cplusplus) && __cplusplus >= 201402L) || ((defined(_MSVC_LANG) && _MSVC_LANG >= 201402L))
static_assert(std::is_trivially_copyable<atbus::detail::buffer_block>::value,
              "buffer_block must be trivially copyable");
#  elif (defined(__cplusplus) && __cplusplus >= 201103L) || ((defined(_MSVC_LANG) && _MSVC_LANG >= 201103L))
static_assert(std::is_trivial<atbus::detail::buffer_block>::value, "buffer_block must be trivially");
#  else
static_assert(std::is_pod<atbus::detail::buffer_block>::value, "buffer_block must be a POD type");
#  endif
#endif

namespace atbus {
namespace detail {

namespace fn {
ATBUS_MACRO_API void *buffer_next(void *pointer, size_t step) { return reinterpret_cast<char *>(pointer) + step; }

ATBUS_MACRO_API const void *buffer_next(const void *pointer, size_t step) {
  return reinterpret_cast<const char *>(pointer) + step;
}

ATBUS_MACRO_API void *buffer_prev(void *pointer, size_t step) { return reinterpret_cast<char *>(pointer) - step; }

ATBUS_MACRO_API const void *buffer_prev(const void *pointer, size_t step) {
  return reinterpret_cast<const char *>(pointer) - step;
}

ATBUS_MACRO_API size_t buffer_offset(const void *l, const void *r) {
  const char *lc = reinterpret_cast<const char *>(l);
  const char *rc = reinterpret_cast<const char *>(r);
  return lc < rc ? (rc - lc) : (lc - rc);
}

ATBUS_MACRO_API size_t read_vint(uint64_t &out, const void *pointer, size_t s) {
  out = 0;

  if (s == 0 || NULL == pointer) {
    return 0;
  }

  size_t left = s;
  for (const char *d = reinterpret_cast<const char *>(pointer); left > 0; ++d) {
    --left;

    out <<= 7;
    out |= 0x7F & *d;

    if (0 == (0x80 & *d)) {
      break;
    } else if (0 == left) {
      return 0;
    }
  }

  return s - left;
}

ATBUS_MACRO_API size_t write_vint(uint64_t in, void *pointer, size_t s) {
  if (s == 0 || NULL == pointer) {
    return 0;
  }

  size_t used = 1;
  char *d = reinterpret_cast<char *>(pointer);
  *d = 0x7F & in;
  in >>= 7;

  while (in && used + 1 <= s) {
    ++used;
    ++d;

    *d = 0x80 | (in & 0x7F);
    in >>= 7;
  }

  if (in) {
    return 0;
  }

  char *ss = reinterpret_cast<char *>(pointer);
  if (ss < d) {
    std::reverse(ss, d + 1);
  }

  return used;
}
}  // namespace fn

ATBUS_MACRO_API void *buffer_block::data() { return fn::buffer_next(pointer_, used_); }

ATBUS_MACRO_API const void *buffer_block::data() const { return fn::buffer_next(pointer_, used_); }

ATBUS_MACRO_API void *buffer_block::raw_data() { return pointer_; }

ATBUS_MACRO_API const void *buffer_block::raw_data() const { return pointer_; }

ATBUS_MACRO_API size_t buffer_block::size() const { return size_ - used_; }

ATBUS_MACRO_API size_t buffer_block::raw_size() const { return size_; }

ATBUS_MACRO_API void *buffer_block::pop(size_t s) {
  if (used_ + s > size_) {
    used_ = size_;
  } else {
    used_ += s;
  }

  return data();
}

ATBUS_MACRO_API size_t buffer_block::instance_size() const { return head_size(size_); }

/** alloc and init buffer_block **/
ATBUS_MACRO_API buffer_block *buffer_block::malloc(size_t s) {
  size_t ms = full_size(s);

  void *ret = ::malloc(ms);
  if (NULL != ret) {
    if (NULL == create(ret, ms, s)) {
      ::free(ret);
      return NULL;
    }
  }

  return reinterpret_cast<buffer_block *>(ret);
}

/** destroy and free buffer_block **/
ATBUS_MACRO_API void buffer_block::free(buffer_block *p) {
  if (NULL != p) {
    destroy(p);
    ::free(p);
  }
}

/** init buffer_block as specify address **/
ATBUS_MACRO_API void *buffer_block::create(void *pointer, size_t s, size_t bs) {
  if (NULL == pointer) {
    return NULL;
  }

  size_t fs = full_size(bs);
  size_t hs = head_size(bs);
  if (fs > s) {
    return NULL;
  }

  buffer_block *res = reinterpret_cast<buffer_block *>(pointer);
  res->size_ = bs;
  res->pointer_ = fn::buffer_next(pointer, hs);
  res->used_ = 0;

  assert(fn::buffer_next(pointer, fs) >= fn::buffer_next(res->pointer_, res->size_));
  return fn::buffer_next(pointer, fs);
}

/** init buffer_block as specify address **/
ATBUS_MACRO_API void *buffer_block::destroy(buffer_block *p) {
  if (NULL == p) {
    return NULL;
  }

// debug 版本做内存填充，方便调试
#if !defined(NDEBUG) || defined(_DEBUG)
  memset((void *)p, 0x5e5e5e5e, full_size(p->size_));
#endif

  return fn::buffer_next(p->pointer_, p->size_);
}

ATBUS_MACRO_API size_t buffer_block::padding_size(size_t s) {
  size_t pl = s % ATBUS_MACRO_DATA_ALIGN_SIZE;
  if (0 == pl) {
    return s;
  }

  return s + ATBUS_MACRO_DATA_ALIGN_SIZE - pl;
}

ATBUS_MACRO_API size_t buffer_block::head_size(size_t) { return padding_size(sizeof(buffer_block)); }

ATBUS_MACRO_API size_t buffer_block::full_size(size_t s) { return head_size(s) + padding_size(s); }

// ================= buffer manager =================
ATBUS_MACRO_API buffer_manager::buffer_manager() {
  static_buffer_.buffer_ = NULL;

  reset();
}

ATBUS_MACRO_API buffer_manager::~buffer_manager() { reset(); }

ATBUS_MACRO_API const buffer_manager::limit_t &buffer_manager::limit() const { return limit_; }

ATBUS_MACRO_API bool buffer_manager::set_limit(size_t max_size, size_t max_number) {
  if (NULL == static_buffer_.buffer_) {
    limit_.limit_number_ = max_number;
    limit_.limit_size_ = max_size;
    return true;
  }

  return false;
}

ATBUS_MACRO_API buffer_block *buffer_manager::front() { return is_dynamic_mode() ? dynamic_front() : static_front(); }

ATBUS_MACRO_API int buffer_manager::front(void *&pointer, size_t &nread, size_t &nwrite) {
  buffer_block *res = front();
  if (NULL == res) {
    pointer = NULL;
    nread = nwrite = 0;

    return EN_ATBUS_ERR_NO_DATA;
  }

  pointer = res->data();
  nwrite = res->size();
  nread = res->raw_size() - nwrite;
  return EN_ATBUS_ERR_SUCCESS;
}

ATBUS_MACRO_API buffer_block *buffer_manager::back() { return is_dynamic_mode() ? dynamic_back() : static_back(); }

ATBUS_MACRO_API int buffer_manager::back(void *&pointer, size_t &nread, size_t &nwrite) {
  buffer_block *res = back();
  if (NULL == res) {
    pointer = NULL;
    nread = nwrite = 0;

    return EN_ATBUS_ERR_NO_DATA;
  }

  pointer = res->data();
  nwrite = res->size();
  nread = res->raw_size() - nwrite;
  return EN_ATBUS_ERR_SUCCESS;
}

ATBUS_MACRO_API int buffer_manager::push_back(void *&pointer, size_t s) {
  pointer = NULL;
  if (limit_.limit_number_ > 0 && limit_.cost_number_ >= limit_.limit_number_) {
    return EN_ATBUS_ERR_BUFF_LIMIT;
  }

  if (limit_.limit_size_ > 0 && limit_.cost_size_ + s > limit_.limit_size_) {
    return EN_ATBUS_ERR_BUFF_LIMIT;
  }

  int res = is_dynamic_mode() ? dynamic_push_back(pointer, s) : static_push_back(pointer, s);
  if (res >= 0) {
    ++limit_.cost_number_;
    limit_.cost_size_ += s;
  }

  return res;
}

ATBUS_MACRO_API int buffer_manager::push_front(void *&pointer, size_t s) {
  pointer = NULL;
  if (limit_.limit_number_ > 0 && limit_.cost_number_ >= limit_.limit_number_) {
    return EN_ATBUS_ERR_BUFF_LIMIT;
  }

  if (limit_.limit_size_ > 0 && limit_.cost_size_ + s > limit_.limit_size_) {
    return EN_ATBUS_ERR_BUFF_LIMIT;
  }

  int res = is_dynamic_mode() ? dynamic_push_front(pointer, s) : static_push_front(pointer, s);
  if (res >= 0) {
    ++limit_.cost_number_;
    limit_.cost_size_ += s;
  }

  return res;
}

ATBUS_MACRO_API int buffer_manager::pop_back(size_t s, bool free_unwritable) {
  return is_dynamic_mode() ? dynamic_pop_back(s, free_unwritable) : static_pop_back(s, free_unwritable);
}

ATBUS_MACRO_API int buffer_manager::pop_front(size_t s, bool free_unwritable) {
  return is_dynamic_mode() ? dynamic_pop_front(s, free_unwritable) : static_pop_front(s, free_unwritable);
}

ATBUS_MACRO_API int buffer_manager::merge_back(void *&pointer, size_t s) {
  if (empty()) {
    return push_back(pointer, s);
  }

  pointer = NULL;
  if (limit_.limit_size_ > 0 && limit_.cost_size_ + s > limit_.limit_size_) {
    return EN_ATBUS_ERR_BUFF_LIMIT;
  }

  int res = is_dynamic_mode() ? dynamic_merge_back(pointer, s) : static_merge_back(pointer, s);
  if (res >= 0) {
    limit_.cost_size_ += s;
  }

  return res;
}

ATBUS_MACRO_API int buffer_manager::merge_front(void *&pointer, size_t s) {
  if (empty()) {
    return push_front(pointer, s);
  }

  pointer = NULL;
  if (limit_.limit_size_ > 0 && limit_.cost_size_ + s > limit_.limit_size_) {
    return EN_ATBUS_ERR_BUFF_LIMIT;
  }

  int res = is_dynamic_mode() ? dynamic_merge_front(pointer, s) : static_merge_front(pointer, s);
  if (res >= 0) {
    limit_.cost_size_ += s;
  }

  return res;
}

ATBUS_MACRO_API bool buffer_manager::empty() const { return is_dynamic_mode() ? dynamic_empty() : static_empty(); }

buffer_block *buffer_manager::static_front() {
  if (static_empty()) {
    return NULL;
  }

  return static_buffer_.circle_index_[static_buffer_.head_];
}

buffer_block *buffer_manager::static_back() {
  if (static_empty()) {
    return NULL;
  }

  return static_buffer_.circle_index_[(static_buffer_.tail_ + static_buffer_.circle_index_.size() - 1) %
                                      static_buffer_.circle_index_.size()];
}

int buffer_manager::static_push_back(void *&pointer, size_t s) {
  assert(static_buffer_.circle_index_.size() >= 2);

  pointer = NULL;
  if ((static_buffer_.tail_ + 1) % static_buffer_.circle_index_.size() == static_buffer_.head_) {
    return EN_ATBUS_ERR_BUFF_LIMIT;
  }

#define assign_tail(x) static_buffer_.circle_index_[static_buffer_.tail_] = reinterpret_cast<buffer_block *>(x)
#define add_tail()                                                      \
  pointer = static_buffer_.circle_index_[static_buffer_.tail_]->data(); \
  static_buffer_.tail_ = (static_buffer_.tail_ + 1) % static_buffer_.circle_index_.size()

  buffer_block *head = static_buffer_.circle_index_[static_buffer_.head_];
  buffer_block *tail = static_buffer_.circle_index_[static_buffer_.tail_];

  size_t fs = buffer_block::full_size(s);
  // empty init
  if (NULL == head || NULL == tail) {
    static_buffer_.tail_ = 0;
    static_buffer_.head_ = 0;
    assign_tail(static_buffer_.buffer_);

    head = static_buffer_.circle_index_[static_buffer_.head_];
    tail = static_buffer_.circle_index_[static_buffer_.tail_];
  }

  if (tail >= head) {  // .... head NNNNNN tail ....
    size_t free_len = fn::buffer_offset(tail, fn::buffer_next(static_buffer_.buffer_, static_buffer_.size_));

    if (free_len >= fs) {  // .... head NNNNNN old_tail NN new_tail ....
      void *next_free = buffer_block::create(tail, free_len, s);
      if (NULL == next_free) {
        return EN_ATBUS_ERR_MALLOC;
      }
      assert(fn::buffer_next(static_buffer_.buffer_, static_buffer_.size_) >= next_free);

      add_tail();
      assign_tail(next_free);
    } else {  // NN new_tail ... head NNNNNN old_tail ....
      free_len = fn::buffer_offset(static_buffer_.buffer_, head);

      // 必须预留空区域，不能让new_tail == head
      if (free_len <= fs) {
        return EN_ATBUS_ERR_BUFF_LIMIT;
      }

      void *next_free = buffer_block::create(static_buffer_.buffer_, free_len, s);
      if (NULL == next_free) {
        return EN_ATBUS_ERR_MALLOC;
      }
      assert(next_free <= head);

      assign_tail(static_buffer_.buffer_);
      add_tail();
      assign_tail(next_free);
    }
  } else {  // NNN tail ....  head NNNNNN ....
    size_t free_len = fn::buffer_offset(tail, head);

    // 必须预留空区域，不能让new_tail == head
    if (free_len <= fs) {
      return EN_ATBUS_ERR_BUFF_LIMIT;
    }

    // NNN old_tail NN new_tail ....  head NNNNNN ....
    void *next_free = buffer_block::create(tail, free_len, s);
    if (NULL == next_free) {
      return EN_ATBUS_ERR_MALLOC;
    }
    assert(next_free <= head);

    add_tail();
    assign_tail(next_free);
  }

#undef add_tail
#undef assign_tail

  return EN_ATBUS_ERR_SUCCESS;
}

int buffer_manager::static_push_front(void *&pointer, size_t s) {
  assert(static_buffer_.circle_index_.size() >= 2);

  pointer = NULL;
  if ((static_buffer_.tail_ + 1) % static_buffer_.circle_index_.size() == static_buffer_.head_) {
    return EN_ATBUS_ERR_BUFF_LIMIT;
  }

#define index_pre_head() \
  ((static_buffer_.head_ + static_buffer_.circle_index_.size() - 1) % static_buffer_.circle_index_.size())
#define assign_head(x) static_buffer_.circle_index_[static_buffer_.head_] = reinterpret_cast<buffer_block *>(x)
#define sub_head(d)                        \
  static_buffer_.head_ = index_pre_head(); \
  assign_head(d);                          \
  pointer = static_buffer_.circle_index_[static_buffer_.head_]->data()

  buffer_block *head = static_buffer_.circle_index_[static_buffer_.head_];
  buffer_block *tail = static_buffer_.circle_index_[static_buffer_.tail_];

  size_t fs = buffer_block::full_size(s);
  // empty init
  if (NULL == head || NULL == tail) {
    static_buffer_.tail_ = 0;
    static_buffer_.head_ = 0;
    assign_head(static_buffer_.buffer_);

    head = static_buffer_.circle_index_[static_buffer_.head_];
    tail = static_buffer_.circle_index_[static_buffer_.tail_];
  }

  if (tail >= head) {  // .... head NNNNNN tail ....
    size_t free_len = fn::buffer_offset(head, static_buffer_.buffer_);
    if (free_len >= fs) {  // .... new_head NN old_head NNNNNN tail ....
      void *buffer_start = fn::buffer_next(static_buffer_.buffer_, free_len - fs);
      void *next_free = buffer_block::create(buffer_start, fs, s);
      if (NULL == next_free) {
        return EN_ATBUS_ERR_MALLOC;
      }
      assert(head == next_free);
      sub_head(buffer_start);

    } else {  // ... old_head NNNNNN tail .... new_head NN
      free_len = fn::buffer_offset(tail, fn::buffer_next(static_buffer_.buffer_, static_buffer_.size_));

      // 必须预留空区域，不能让tail == new_head
      if (free_len <= fs) {
        return EN_ATBUS_ERR_BUFF_LIMIT;
      }

      void *buffer_start = fn::buffer_next(tail, free_len - fs);
      void *next_free = buffer_block::create(buffer_start, fs, s);
      if (NULL == next_free) {
        return EN_ATBUS_ERR_MALLOC;
      }
      assert(next_free == fn::buffer_next(static_buffer_.buffer_, static_buffer_.size_));
      sub_head(buffer_start);
    }

  } else {  // NNN tail ....  head NNNNNN ....
    size_t free_len = fn::buffer_offset(tail, head);

    // 必须预留空区域，不能让tail == new_head
    if (free_len <= fs) {
      return EN_ATBUS_ERR_BUFF_LIMIT;
    }

    void *buffer_start = fn::buffer_next(tail, free_len - fs);
    // NNN tail  .... new_head NN head NNNNNN ....
    void *next_free = buffer_block::create(buffer_start, fs, s);
    if (NULL == next_free) {
      return EN_ATBUS_ERR_MALLOC;
    }
    assert(next_free == head);
    sub_head(buffer_start);
  }

#undef sub_head
#undef assign_head
#undef index_pre_head
  return EN_ATBUS_ERR_SUCCESS;
}

int buffer_manager::static_pop_back(size_t s, bool free_unwritable) {
  if (static_empty()) {
    return EN_ATBUS_ERR_NO_DATA;
  }

#define index_tail() \
  ((static_buffer_.tail_ + static_buffer_.circle_index_.size() - 1) % static_buffer_.circle_index_.size())
#define assign_tail(x) static_buffer_.circle_index_[static_buffer_.tail_] = reinterpret_cast<buffer_block *>(x)
#define sub_tail(x) static_buffer_.tail_ = x

  size_t tail_index = index_tail();
  buffer_block *tail = static_buffer_.circle_index_[tail_index];

  if (s > tail->size()) {
    s = tail->size();
  }

  tail->pop(s);
  if (free_unwritable && 0 == tail->size()) {
    buffer_block::destroy(tail);
    assign_tail(NULL);
    sub_tail(tail_index);

    if (limit_.cost_number_ > 0) {
      --limit_.cost_number_;
    }
  }

  // fix limit and reset to init state
  if (static_empty()) {
    static_buffer_.head_ = 0;
    static_buffer_.tail_ = 0;
    static_buffer_.circle_index_[static_buffer_.tail_] = reinterpret_cast<buffer_block *>(static_buffer_.buffer_);

    limit_.cost_size_ = 0;
    limit_.cost_number_ = 0;
  } else {
    limit_.cost_size_ -= limit_.cost_size_ >= s ? s : limit_.cost_size_;
  }

#undef assign_tail
#undef sub_tail
#undef index_tail
  return EN_ATBUS_ERR_SUCCESS;
}

int buffer_manager::static_pop_front(size_t s, bool free_unwritable) {
  if (static_empty()) {
    return EN_ATBUS_ERR_NO_DATA;
  }

#define assign_head(x) static_buffer_.circle_index_[static_buffer_.head_] = reinterpret_cast<buffer_block *>(x)
#define add_head() static_buffer_.head_ = (static_buffer_.head_ + 1) % static_buffer_.circle_index_.size()

  buffer_block *head = static_buffer_.circle_index_[static_buffer_.head_];

  if (s > head->size()) {
    s = head->size();
  }

  head->pop(s);
  if (free_unwritable && 0 == head->size()) {
    buffer_block::destroy(head);
    assign_head(NULL);
    add_head();

    if (limit_.cost_number_ > 0) {
      --limit_.cost_number_;
    }
  }

  // fix limit and reset to init state
  if (static_empty()) {
    static_buffer_.head_ = 0;
    static_buffer_.tail_ = 0;
    static_buffer_.circle_index_[static_buffer_.tail_] = reinterpret_cast<buffer_block *>(static_buffer_.buffer_);

    limit_.cost_size_ = 0;
    limit_.cost_number_ = 0;
  } else {
    limit_.cost_size_ -= limit_.cost_size_ >= s ? s : limit_.cost_size_;
  }

#undef assign_head
#undef add_head
  return EN_ATBUS_ERR_SUCCESS;
}

int buffer_manager::static_merge_back(void *&pointer, size_t s) {
  if (0 == s) {
    return 0;
  }

  buffer_block *head = static_buffer_.circle_index_[static_buffer_.head_];
  buffer_block *tail = static_buffer_.circle_index_[static_buffer_.tail_];
  buffer_block *last_block = static_back();
  if (NULL == head || NULL == tail || NULL == last_block) {
    return EN_ATBUS_ERR_NO_DATA;
  }

#define index_tail() \
  ((static_buffer_.tail_ + static_buffer_.circle_index_.size() - 1) % static_buffer_.circle_index_.size())
#define assign_tail(x) static_buffer_.circle_index_[static_buffer_.tail_] = reinterpret_cast<buffer_block *>(x)

  size_t fs = buffer_block::padding_size(s);

  if (tail >= head || last_block >= head) {  // .... head NNNNNN tail ....
    size_t free_len = fn::buffer_offset(tail, fn::buffer_next(static_buffer_.buffer_, static_buffer_.size_));
    // if tail < head && last_block >= head, tail must be static_buffer_.buffer_
    assert(static_buffer_.size_ == free_len ||
           fn::buffer_next(last_block->raw_data(), buffer_block::padding_size(last_block->raw_size())) == tail);

    if (free_len >= fs && tail >= head) {  // .... head NNNNNN tail NN old_bound NN new_bound ....
      pointer = fn::buffer_next(last_block->pointer_, last_block->size_);
      last_block->size_ += s;

      assert(fn::buffer_next(static_buffer_.buffer_, static_buffer_.size_) >=
             fn::buffer_next(last_block, buffer_block::full_size(last_block->size_)));

      assign_tail(fn::buffer_next(last_block, buffer_block::full_size(last_block->size_)));
    } else {  // NN new_tail ... head NNNNNN old_tail ....
      free_len = fn::buffer_offset(static_buffer_.buffer_, head);
      size_t new_block_sz = buffer_block::full_size(s + last_block->size_);

      // 必须预留空区域，不能让new_tail == head
      if (free_len <= new_block_sz) {
        return EN_ATBUS_ERR_BUFF_LIMIT;
      }

      void *next_free = buffer_block::create(static_buffer_.buffer_, free_len, s + last_block->size_);
      if (NULL == next_free) {
        return EN_ATBUS_ERR_MALLOC;
      }
      assert(next_free < head);
      assign_tail(next_free);

      // memory copy
      {
        size_t tail_index = index_tail();
        buffer_block *relocated_block = reinterpret_cast<buffer_block *>(static_buffer_.buffer_);

        pointer = fn::buffer_next(relocated_block->data(), last_block->raw_size());

        static_buffer_.circle_index_[tail_index] = relocated_block;
        memcpy(relocated_block->data(), last_block->raw_data(), last_block->raw_size());
        relocated_block->pop(last_block->raw_size() - last_block->size());
      }
    }
  } else {  // NNN tail ....  head NNNNNN ....
    size_t free_len = fn::buffer_offset(tail, head);
    assert(fn::buffer_next(last_block, buffer_block::full_size(last_block->raw_size())) == tail);

    // 必须预留空区域，不能让new_tail == head
    if (free_len <= fs) {
      return EN_ATBUS_ERR_BUFF_LIMIT;
    }

    pointer = fn::buffer_next(last_block->pointer_, last_block->size_);
    // NNN tail NN old_bound NN new_bound ....  head NNNNNN ....
    last_block->size_ += s;

    assert(fn::buffer_next(last_block, buffer_block::full_size(last_block->size_)) < head);
    assert(fn::buffer_next(last_block, buffer_block::full_size(last_block->size_)) == fn::buffer_next(tail, fs));
    assign_tail(fn::buffer_next(last_block, buffer_block::full_size(last_block->size_)));
  }

#undef assign_tail
#undef index_tail

  return 0;
}

int buffer_manager::static_merge_front(void *&pointer, size_t s) {
  if (0 == s) {
    return 0;
  }

#define assign_head(x) static_buffer_.circle_index_[static_buffer_.head_] = reinterpret_cast<buffer_block *>(x)

  buffer_block *head = static_buffer_.circle_index_[static_buffer_.head_];
  buffer_block *tail = static_buffer_.circle_index_[static_buffer_.tail_];
  if (NULL == head || NULL == tail) {
    return EN_ATBUS_ERR_NO_DATA;
  }

  size_t fs = buffer_block::padding_size(s);

  // in case of cover buffer when relocate the header of head block
  buffer_block old_head = *head;
  size_t new_head_s = s + old_head.raw_size();
  size_t new_head_fs = buffer_block::full_size(new_head_s);

  if (tail >= head) {  // .... head NNNNNN tail ....
    size_t free_len = fn::buffer_offset(head, static_buffer_.buffer_);
    if (free_len >= fs) {  // .... new_head NN old_head NNNNNN tail ....
      void *buffer_start = fn::buffer_next(static_buffer_.buffer_, free_len - fs);
      void *next_free = buffer_block::create(buffer_start, new_head_fs, new_head_s);
      if (NULL == next_free) {
        return EN_ATBUS_ERR_MALLOC;
      }

      assert(fn::buffer_next(head, buffer_block::full_size(old_head.raw_size())) == next_free);
      head = reinterpret_cast<buffer_block *>(buffer_start);
      assert(buffer_block::full_size(old_head.raw_size()) + fs == new_head_fs);
    } else {  // ... old_head NNNNNN tail .... new_head NN
      free_len = fn::buffer_offset(tail, fn::buffer_next(static_buffer_.buffer_, static_buffer_.size_));

      // 必须预留空区域，不能让tail == new_head
      if (free_len <= new_head_fs) {
        return EN_ATBUS_ERR_BUFF_LIMIT;
      }

      void *buffer_start = fn::buffer_next(tail, free_len - new_head_fs);
      void *next_free = buffer_block::create(buffer_start, new_head_fs, new_head_s);
      if (NULL == next_free) {
        return EN_ATBUS_ERR_MALLOC;
      }
      assert(next_free == fn::buffer_next(static_buffer_.buffer_, static_buffer_.size_));

      head = reinterpret_cast<buffer_block *>(buffer_start);
    }

  } else {  // NNN tail ....  head NNNNNN ....
    size_t free_len = fn::buffer_offset(tail, head);

    // 必须预留空区域，不能让tail == new_head
    if (free_len <= fs) {
      return EN_ATBUS_ERR_BUFF_LIMIT;
    }

    void *buffer_start = fn::buffer_next(tail, free_len - fs);
    // NNN tail  .... new_head NN head NNNNNN ....
    void *next_free = buffer_block::create(buffer_start, new_head_fs, new_head_s);
    if (NULL == next_free) {
      return EN_ATBUS_ERR_MALLOC;
    }

    assert(fn::buffer_next(head, buffer_block::full_size(old_head.raw_size())) == next_free);
    head = reinterpret_cast<buffer_block *>(buffer_start);
    assert(buffer_block::full_size(old_head.raw_size()) + fs == new_head_fs);
  }

  // memory move
  {
    pointer = fn::buffer_next(head->data(), old_head.raw_size());
    memmove(head->data(), old_head.raw_data(), old_head.raw_size());
    head->pop(old_head.raw_size() - old_head.size());
    assign_head(head);
  }

#undef assign_head
  return 0;
}

bool buffer_manager::static_empty() const { return static_buffer_.head_ == static_buffer_.tail_; }

buffer_block *buffer_manager::dynamic_front() {
  if (dynamic_empty()) {
    return NULL;
  }

  return dynamic_buffer_.front();
}

buffer_block *buffer_manager::dynamic_back() {
  if (dynamic_empty()) {
    return NULL;
  }

  return dynamic_buffer_.back();
}

int buffer_manager::dynamic_push_back(void *&pointer, size_t s) {
  buffer_block *res = buffer_block::malloc(s);
  if (NULL == res) {
    pointer = NULL;
    return EN_ATBUS_ERR_MALLOC;
  }

  dynamic_buffer_.push_back(res);
  pointer = res->data();

  return EN_ATBUS_ERR_SUCCESS;
}

int buffer_manager::dynamic_push_front(void *&pointer, size_t s) {
  buffer_block *res = buffer_block::malloc(s);
  if (NULL == res) {
    pointer = NULL;
    return EN_ATBUS_ERR_MALLOC;
  }

  dynamic_buffer_.push_front(res);
  pointer = res->data();

  return EN_ATBUS_ERR_SUCCESS;
}

int buffer_manager::dynamic_pop_back(size_t s, bool free_unwritable) {
  if (dynamic_empty()) {
    return EN_ATBUS_ERR_NO_DATA;
  }

  buffer_block *t = dynamic_buffer_.back();
  if (s > t->size()) {
    s = t->size();
  }

  t->pop(s);
  if (free_unwritable && t->size() <= 0) {
    buffer_block::free(t);
    dynamic_buffer_.pop_back();

    if (limit_.cost_number_ > 0) {
      --limit_.cost_number_;
    }
  }

  // fix limit
  if (dynamic_empty()) {
    limit_.cost_size_ = 0;
    limit_.cost_number_ = 0;
  } else {
    limit_.cost_size_ -= limit_.cost_size_ >= s ? s : limit_.cost_size_;
  }

  return EN_ATBUS_ERR_SUCCESS;
}

int buffer_manager::dynamic_pop_front(size_t s, bool free_unwritable) {
  if (dynamic_empty()) {
    return EN_ATBUS_ERR_NO_DATA;
  }

  buffer_block *t = dynamic_buffer_.front();
  if (s > t->size()) {
    s = t->size();
  }

  t->pop(s);
  if (free_unwritable && t->size() <= 0) {
    buffer_block::free(t);
    dynamic_buffer_.pop_front();

    if (limit_.cost_number_ > 0) {
      --limit_.cost_number_;
    }
  }

  // fix limit
  if (dynamic_empty()) {
    limit_.cost_size_ = 0;
    limit_.cost_number_ = 0;
  } else {
    limit_.cost_size_ -= limit_.cost_size_ >= s ? s : limit_.cost_size_;
  }

  return EN_ATBUS_ERR_SUCCESS;
}

int buffer_manager::dynamic_merge_back(void *&pointer, size_t s) {
  if (0 == s) {
    return 0;
  }

  buffer_block *block = dynamic_back();
  if (NULL == block) {
    return EN_ATBUS_ERR_NO_DATA;
  }

  buffer_block *res = buffer_block::malloc(s + block->raw_size());
  if (NULL == res) {
    return EN_ATBUS_ERR_MALLOC;
  }

  // reset pointer
  pointer = fn::buffer_next(res->data(), block->raw_size());
  assert(dynamic_buffer_.back() == block);
  dynamic_buffer_.back() = res;

  // move data
  memcpy(res->data(), block->raw_data(), block->raw_size());
  res->pop(block->raw_size() - block->size());

  // remove old block
  buffer_block::free(block);
  return EN_ATBUS_ERR_SUCCESS;
}

int buffer_manager::dynamic_merge_front(void *&pointer, size_t s) {
  if (0 == s) {
    return 0;
  }

  buffer_block *block = dynamic_front();
  if (NULL == block) {
    return EN_ATBUS_ERR_NO_DATA;
  }

  buffer_block *res = buffer_block::malloc(s + block->raw_size());
  if (NULL == res) {
    return EN_ATBUS_ERR_MALLOC;
  }

  // reset pointer
  pointer = fn::buffer_next(res->data(), block->raw_size());
  assert(dynamic_buffer_.front() == block);
  dynamic_buffer_.front() = res;

  // move data
  memcpy(res->data(), block->raw_data(), block->raw_size());
  res->pop(block->raw_size() - block->size());

  // remove old block
  buffer_block::free(block);
  return EN_ATBUS_ERR_SUCCESS;
}

bool buffer_manager::dynamic_empty() const { return dynamic_buffer_.empty(); }

ATBUS_MACRO_API void buffer_manager::reset() {
  static_buffer_.head_ = 0;
  static_buffer_.tail_ = 0;
  static_buffer_.size_ = 0;
  static_buffer_.circle_index_.clear();
  if (NULL != static_buffer_.buffer_) {
    ::free(static_buffer_.buffer_);
    static_buffer_.buffer_ = NULL;
  }

  // dynamic buffers
  while (!dynamic_buffer_.empty()) {
    buffer_block::free(dynamic_buffer_.front());
    dynamic_buffer_.pop_front();
  }

  limit_.cost_size_ = 0;
  limit_.cost_number_ = 0;
  limit_.limit_number_ = 0;
  limit_.limit_size_ = 0;
}

ATBUS_MACRO_API void buffer_manager::set_mode(size_t max_size, size_t max_number) {
  reset();

  if (0 != max_size && max_number > 0) {
    // additional one block for keeping different head and tail
    size_t bfs = buffer_block::padding_size(max_size + ATBUS_MACRO_DATA_ALIGN_SIZE);
    static_buffer_.buffer_ = ::malloc(bfs);
    if (NULL != static_buffer_.buffer_) {
      static_buffer_.size_ = bfs;

      // left 1 empty bound
      static_buffer_.circle_index_.resize(max_number + 1, NULL);
      limit_.limit_size_ = max_size;
      limit_.limit_number_ = max_number;
    }
  }
}

ATBUS_MACRO_API bool buffer_manager::is_static_mode() const { return NULL != static_buffer_.buffer_; }
ATBUS_MACRO_API bool buffer_manager::is_dynamic_mode() const { return NULL == static_buffer_.buffer_; }
}  // namespace detail
}  // namespace atbus
