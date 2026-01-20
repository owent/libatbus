// Copyright 2026 Atframework.

#pragma once

#include <gsl/select-gsl.h>

#include <list>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#ifdef __cpp_impl_three_way_comparison
#  include <compare>
#endif

#ifdef _MSC_VER
#  include <WinSock2.h>
#endif

#include <design_pattern/nomovable.h>
#include <design_pattern/noncopyable.h>

#include "detail/libatbus_channel_export.h"
#include "detail/libatbus_config.h"
#include "detail/libatbus_error.h"

#include "atbus_connection.h"

ATBUS_MACRO_NAMESPACE_BEGIN

class node;

class endpoint final : public atfw::util::design_pattern::noncopyable {
 public:
  using ptr_t = ::atfw::util::memory::strong_rc_ptr<endpoint>;

  struct flag_t {
    enum class type : uint32_t {
      RESETTING, /** 正在执行重置（防止递归死循环） **/
      CONNECTION_SORTED,
      DESTRUCTING,     /** 正在执行析构 **/
      HAS_LISTEN_PORC, /** 是否有proc类的listen地址 **/
      HAS_LISTEN_FD,   /** 是否有fd类的listen地址 **/

      MUTABLE_FLAGS,  /** 可动态变化的属性起始边界 **/
      HAS_PING_TIMER, /** 是否设置了ping定时器 **/
      MAX
    };
  };

  using get_connection_fn_t = connection *(endpoint::*)(const endpoint *ep) const;

  UTIL_DESIGN_PATTERN_NOCOPYABLE(endpoint)
  UTIL_DESIGN_PATTERN_NOMOVABLE(endpoint)

 private:
  endpoint();

 public:
  /**
   * @brief 创建端点
   */
  static ATBUS_MACRO_API ptr_t create(node *owner, bus_id_t id, int32_t pid, gsl::string_view hn);
  ATBUS_MACRO_API ~endpoint();

  ATBUS_MACRO_API void reset();

  ATBUS_MACRO_API bus_id_t get_id() const;

  ATBUS_MACRO_API int32_t get_pid() const;
  ATBUS_MACRO_API const std::string &get_hostname() const;
  ATBUS_MACRO_API const std::string &get_hash_code() const;
  ATBUS_MACRO_API void update_hash_code(gsl::string_view);

  ATBUS_MACRO_API bool add_connection(connection *conn, bool force_data);

  ATBUS_MACRO_API bool remove_connection(connection *conn);

  /**
   * @brief 是否处于可用状态
   * @note 可用状态是指同时存在正在运行的命令通道和数据通道
   */
  ATBUS_MACRO_API bool is_available() const;

  /**
   * @brief 获取flag
   * @param f flag的key
   * @return 返回f的值，如果f无效，返回false
   */
  ATBUS_MACRO_API bool get_flag(flag_t::type f) const;

  /**
   * @brief 设置可变flag的值
   * @param f flag的key，这个值必须大于等于flat_t::MUTABLE_FLAGS
   * @param v 值
   * @return 0或错误码
   * @see flat_t
   */
  ATBUS_MACRO_API int set_flag(flag_t::type f, bool v);

  /**
   * @brief 获取所有flag
   * @return 整数表示的flags
   * @see flat_t
   */
  ATBUS_MACRO_API uint32_t get_flags() const;

  /**
   * @breif 获取自身的资源holder
   */
  ATBUS_MACRO_API ptr_t watch() const;

  ATBUS_MACRO_API const std::list<channel::channel_address_t> &get_listen() const;

  ATBUS_MACRO_API void clear_listen();
  ATBUS_MACRO_API void add_listen(gsl::string_view addr);
  ATBUS_MACRO_API void update_supported_schemas(const std::unordered_set<std::string> &&schemas);
  ATBUS_MACRO_API bool is_schema_supported(const std::string &checked) const noexcept;

  ATBUS_MACRO_API void add_ping_timer();
  ATBUS_MACRO_API void clear_ping_timer();

 private:
  static bool sort_connection_cmp_fn(const connection::ptr_t &left, const connection::ptr_t &right);

 public:
  ATBUS_MACRO_API connection *get_ctrl_connection(const endpoint *ep) const;

  ATBUS_MACRO_API connection *get_data_connection(const endpoint *ep) const;
  ATBUS_MACRO_API connection *get_data_connection(const endpoint *ep, bool enable_fallback_ctrl) const;
  ATBUS_MACRO_API size_t get_data_connection_count(bool enable_fallback_ctrl) const noexcept;

  /** 增加错误计数 **/
  ATBUS_MACRO_API size_t add_stat_fault() noexcept;

  /** 清空错误计数 **/
  ATBUS_MACRO_API void clear_stat_fault() noexcept;

  ATBUS_MACRO_API void set_stat_unfinished_ping(uint64_t p) noexcept;

  ATBUS_MACRO_API uint64_t get_stat_unfinished_ping() const noexcept;

  ATBUS_MACRO_API void set_stat_ping_delay(std::chrono::microseconds ping_delay,
                                           std::chrono::system_clock::time_point pong_tm) noexcept;

  ATBUS_MACRO_API std::chrono::microseconds get_stat_ping_delay() const;

  ATBUS_MACRO_API std::chrono::system_clock::time_point get_stat_last_pong() const;

  ATBUS_MACRO_API size_t get_stat_push_start_times() const;
  ATBUS_MACRO_API size_t get_stat_push_start_size() const;
  ATBUS_MACRO_API size_t get_stat_push_success_times() const;
  ATBUS_MACRO_API size_t get_stat_push_success_size() const;
  ATBUS_MACRO_API size_t get_stat_push_failed_times() const;
  ATBUS_MACRO_API size_t get_stat_push_failed_size() const;
  ATBUS_MACRO_API size_t get_stat_pull_times() const;
  ATBUS_MACRO_API size_t get_stat_pull_size() const;

  ATBUS_MACRO_API std::chrono::system_clock::time_point get_stat_created_time();

  ATBUS_MACRO_API const node *get_owner() const;

 private:
  bus_id_t id_;
  std::string hash_code_;
  std::bitset<static_cast<size_t>(flag_t::type::MAX)> flags_;
  std::string hostname_;
  int32_t pid_;

  // 这里不用智能指针是为了该值在上层对象（node）析构时仍然可用
  node *owner_;
  ::atfw::util::memory::weak_rc_ptr<endpoint> watcher_;

  std::list<channel::channel_address_t> listen_address_;
  std::unordered_set<std::string> supported_schemas_;
  connection::ptr_t ctrl_conn_;
  std::list<connection::ptr_t> data_conn_;

  // 统计数据
  struct stat_t {
    size_t fault_count;        // 错误容忍计数
    uint64_t unfinished_ping;  // 上一次未完成的ping的序号
    std::chrono::microseconds ping_delay;
    std::chrono::system_clock::time_point last_pong_time;  // 上一次接到PONG包时间
    std::chrono::system_clock::time_point created_time;
    stat_t();
  };
  stat_t stat_;
};
ATBUS_MACRO_NAMESPACE_END
