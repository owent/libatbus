/**
 * atbus_endpoint.h
 *
 *  Created on: 2015年11月20日
 *      Author: owent
 */

#pragma once

#ifndef LIBATBUS_ENDPOINT_H
#  define LIBATBUS_ENDPOINT_H

#  pragma once

#  include <list>
#  include <memory>
#  include <vector>

#  ifdef __cpp_impl_three_way_comparison
#    include <compare>
#  endif

#  ifdef _MSC_VER
#    include <WinSock2.h>
#  endif

#  include <design_pattern/nomovable.h>
#  include <design_pattern/noncopyable.h>

#  include "detail/libatbus_channel_export.h"
#  include "detail/libatbus_config.h"
#  include "detail/libatbus_error.h"

#  include "atbus_connection.h"

namespace atbus {
namespace detail {
template <typename TKey, typename TVal>
struct auto_select_map {
  using type = ATBUS_ADVANCE_TYPE_MAP(TKey, TVal);
};

template <typename TVal>
struct auto_select_set {
  using type = ATBUS_ADVANCE_TYPE_SET(TVal);
};
}  // namespace detail

class node;

struct ATBUS_MACRO_API endpoint_subnet_conf {
  ATBUS_MACRO_BUSID_TYPE id_prefix;  // subnet prefix
  uint32_t mask_bits;                // suffix bits

  endpoint_subnet_conf();
  endpoint_subnet_conf(ATBUS_MACRO_BUSID_TYPE prefix, uint32_t mask);
};

class ATBUS_MACRO_API endpoint_subnet_range {
 public:
  endpoint_subnet_range();
  endpoint_subnet_range(ATBUS_MACRO_BUSID_TYPE a, uint32_t b);

  bool operator==(const endpoint_subnet_range &other) const;
#  ifdef __cpp_impl_three_way_comparison
  std::strong_ordering operator<=>(const endpoint_subnet_range &other) const;
#  else

  bool operator<(const endpoint_subnet_range &other) const;
  bool operator<=(const endpoint_subnet_range &other) const;
  bool operator>(const endpoint_subnet_range &other) const;
  bool operator>=(const endpoint_subnet_range &other) const;
  bool operator!=(const endpoint_subnet_range &other) const;
#  endif

  inline ATBUS_MACRO_BUSID_TYPE get_id_prefix() const { return id_prefix_; }
  inline uint32_t get_mask_bits() const { return mask_bits_; }
  inline ATBUS_MACRO_BUSID_TYPE get_id_min() const { return min_id_; }
  inline ATBUS_MACRO_BUSID_TYPE get_id_max() const { return max_id_; }

  bool contain(const endpoint_subnet_range &other) const;

  bool contain(ATBUS_MACRO_BUSID_TYPE id) const;
  static bool contain(ATBUS_MACRO_BUSID_TYPE id_prefix, uint32_t mask_bits, ATBUS_MACRO_BUSID_TYPE id);
  static bool contain(const endpoint_subnet_conf &conf, ATBUS_MACRO_BUSID_TYPE id);

  static bool lower_bound_by_max_id(const endpoint_subnet_range &l, ATBUS_MACRO_BUSID_TYPE r);

 private:
  ATBUS_MACRO_BUSID_TYPE id_prefix_;  // subnet prefix
  uint32_t mask_bits_;                // suffix bits
  ATBUS_MACRO_BUSID_TYPE min_id_;
  ATBUS_MACRO_BUSID_TYPE max_id_;
};

class endpoint final : public util::design_pattern::noncopyable {
 public:
  using bus_id_t = ATBUS_MACRO_BUSID_TYPE;
  using ptr_t = std::shared_ptr<endpoint>;

  struct flag_t {
    enum type {
      RESETTING, /** 正在执行重置（防止递归死循环） **/
      CONNECTION_SORTED,
      DESTRUCTING,     /** 正在执行析构 **/
      HAS_LISTEN_PORC, /** 是否有proc类的listen地址 **/
      HAS_LISTEN_FD,   /** 是否有fd类的listen地址 **/

      MUTABLE_FLAGS,  /** 可动态变化的属性其实边界 **/
      HAS_PING_TIMER, /** 是否设置了ping定时器 **/
      MAX
    };
  };

  using get_connection_fn_t = connection *(endpoint::*)(endpoint *ep) const;

  UTIL_DESIGN_PATTERN_NOCOPYABLE(endpoint)
  UTIL_DESIGN_PATTERN_NOMOVABLE(endpoint)

 private:
  endpoint();

 public:
  /**
   * @brief 创建端点
   */
  static ATBUS_MACRO_API ptr_t create(node *owner, bus_id_t id, const std::vector<endpoint_subnet_conf> &subnets,
                                      int32_t pid, const std::string &hn);
  ATBUS_MACRO_API ~endpoint();

  ATBUS_MACRO_API void reset();

  ATBUS_MACRO_API bus_id_t get_id() const;
  ATBUS_MACRO_API const std::vector<endpoint_subnet_range> &get_subnets() const;

  ATBUS_MACRO_API int32_t get_pid() const;
  ATBUS_MACRO_API const std::string &get_hostname() const;
  ATBUS_MACRO_API const std::string &get_hash_code() const;
  ATBUS_MACRO_API void update_hash_code(const std::string &);

  ATBUS_MACRO_API bool is_child_node(bus_id_t id) const;

  static ATBUS_MACRO_API bus_id_t get_children_min_id(bus_id_t children_prefix, uint32_t mask);
  static ATBUS_MACRO_API bus_id_t get_children_max_id(bus_id_t children_prefix, uint32_t mask);
  static ATBUS_MACRO_API bool is_child_node(bus_id_t parent_id, bus_id_t parent_children_prefix, uint32_t parent_mask,
                                            bus_id_t checked_id);

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

  ATBUS_MACRO_API const std::list<std::string> &get_listen() const;

  ATBUS_MACRO_API void add_listen(const std::string &addr);

  ATBUS_MACRO_API void add_ping_timer();
  ATBUS_MACRO_API void clear_ping_timer();

 private:
  static bool sort_connection_cmp_fn(const connection::ptr_t &left, const connection::ptr_t &right);

 public:
  ATBUS_MACRO_API connection *get_ctrl_connection(endpoint *ep) const;

  ATBUS_MACRO_API connection *get_data_connection(endpoint *ep) const;
  ATBUS_MACRO_API connection *get_data_connection(endpoint *ep, bool enable_fallback_ctrl) const;

  /** 增加错误计数 **/
  ATBUS_MACRO_API size_t add_stat_fault();

  /** 清空错误计数 **/
  ATBUS_MACRO_API void clear_stat_fault();

  ATBUS_MACRO_API void set_stat_ping(uint64_t p);

  ATBUS_MACRO_API uint64_t get_stat_ping() const;

  ATBUS_MACRO_API void set_stat_ping_delay(time_t pd, time_t pong_tm);

  ATBUS_MACRO_API time_t get_stat_ping_delay() const;

  ATBUS_MACRO_API time_t get_stat_last_pong() const;

  ATBUS_MACRO_API size_t get_stat_push_start_times() const;
  ATBUS_MACRO_API size_t get_stat_push_start_size() const;
  ATBUS_MACRO_API size_t get_stat_push_success_times() const;
  ATBUS_MACRO_API size_t get_stat_push_success_size() const;
  ATBUS_MACRO_API size_t get_stat_push_failed_times() const;
  ATBUS_MACRO_API size_t get_stat_push_failed_size() const;
  ATBUS_MACRO_API size_t get_stat_pull_times() const;
  ATBUS_MACRO_API size_t get_stat_pull_size() const;

  ATBUS_MACRO_API time_t get_stat_created_time_sec();
  ATBUS_MACRO_API time_t get_stat_created_time_usec();

  ATBUS_MACRO_API const node *get_owner() const;

  static ATBUS_MACRO_API void merge_subnets(std::vector<endpoint_subnet_range> &subnets);

  static ATBUS_MACRO_API std::vector<endpoint_subnet_range>::const_iterator search_subnet_for_id(
      const std::vector<endpoint_subnet_range> &subnets, bus_id_t id);
  static ATBUS_MACRO_API bool contain(const std::vector<endpoint_subnet_range> &parent_subnets,
                                      const std::vector<endpoint_subnet_range> &child_subnets);
  static ATBUS_MACRO_API bool contain(const std::vector<endpoint_subnet_range> &parent_subnets,
                                      const std::vector<endpoint_subnet_conf> &child_subnets);
  static ATBUS_MACRO_API bool contain(const std::vector<endpoint_subnet_range> &parent_subnets, bus_id_t id);
  static ATBUS_MACRO_API bool contain(const std::vector<endpoint_subnet_conf> &parent_subnets, bus_id_t id);

 private:
  bus_id_t id_;
  std::string hash_code_;
  std::vector<endpoint_subnet_range> subnets_;
  std::bitset<flag_t::MAX> flags_;
  std::string hostname_;
  int32_t pid_;

  // 这里不用智能指针是为了该值在上层对象（node）析构时仍然可用
  node *owner_;
  timer_desc_ls<std::weak_ptr<endpoint> >::type::iterator ping_timer_;
  std::weak_ptr<endpoint> watcher_;

  std::list<std::string> listen_address_;
  connection::ptr_t ctrl_conn_;
  std::list<connection::ptr_t> data_conn_;

  // 统计数据
  struct stat_t {
    size_t fault_count;        // 错误容忍计数
    uint64_t unfinished_ping;  // 上一次未完成的ping的序号
    time_t ping_delay;
    time_t last_pong_time;  // 上一次接到PONG包时间
    time_t created_time_sec;
    time_t created_time_usec;
    stat_t();
  };
  stat_t stat_;
};
}  // namespace atbus

#endif /* LIBATBUS_ENDPOINT_H_ */
