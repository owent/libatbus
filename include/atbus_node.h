/**
 * atbus_node.h
 *
 *  Created on: 2015年10月29日
 *      Author: owent
 */

#pragma once

#include <design_pattern/nomovable.h>
#include <design_pattern/noncopyable.h>
#include <gsl/select-gsl.h>
#include <nostd/nullability.h>
#include <nostd/string_view.h>

#include <log/log_wrapper.h>

#include <bitset>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <functional>
#include <list>
#include <map>
#include <memory>
#include <set>
#include <unordered_map>
#include <vector>

#if defined(_WIN32) || defined(__WIN32__) || defined(WIN32)
#  include <WinSock2.h>
#endif

#include "lock/seq_alloc.h"

#include "detail/libatbus_channel_export.h"
#include "detail/libatbus_config.h"
#include "detail/libatbus_error.h"

#include "atbus_endpoint.h"
#include "atbus_topology.h"

ATBUS_MACRO_NAMESPACE_BEGIN

class node;
class node_access_controller {
 private:
  friend class endpoint;

  static bool add_ping_timer(node &n, const endpoint::ptr_t &ep);
  static void remove_ping_timer(node &n, const endpoint *ep);
};

class node final : public atfw::util::design_pattern::noncopyable {
 public:
  using ptr_t = ::atfw::util::memory::strong_rc_ptr<node>;
  using message_builder_ref_t = ::atframework::atbus::message &;

  struct conf_flag_t {
    enum type {
      EN_CONF_MAX = 0,
    };
  };

  /** 并没有非常复杂的状态切换，所以没有引入状态机 **/
  struct state_t {
    enum type { CREATED = 0, INITED, LOST_UPSTREAM, CONNECTING_UPSTREAM, RUNNING };
  };

  struct flag_t {
    enum type {
      EN_FT_RESETTING,         /** 正在重置 **/
      EN_FT_RESETTING_GC,      /** 正在重置且正准备GC或GC流程已完成 **/
      EN_FT_ACTIVED,           /** 已激活 **/
      EN_FT_UPSTREAM_REG_DONE, /** 已通过父节点注册 **/
      EN_FT_SHUTDOWN,          /** 已完成关闭前的资源回收 **/
      EN_FT_RECV_SELF_MSG,     /** 正在接收发给自己的信息 **/
      EN_FT_IN_CALLBACK,       /** 在回调函数中 **/
      EN_FT_IN_PROC,           /** 在Proc函数中 **/
      EN_FT_IN_POLL,           /** 在Poll函数中 **/
      EN_FT_IN_GC_ENDPOINTS,   /** 在清理endpoint过程中 **/
      EN_FT_IN_GC_CONNECTIONS, /** 在清理connection过程中 **/
      EN_FT_MAX,               /** flag max **/
    };
  };

  struct send_data_options_t {
    enum flag_type {
      EN_SDOPT_NONE = 0,
      EN_SDOPT_REQUIRE_RESPONSE = 0x01,  // 是否强制需要回包（默认情况下如果发送成功是没有回包通知的）
    };

    int32_t flags;  // @see flag_type upper
    uint64_t sequence;

    ATBUS_MACRO_API send_data_options_t();

    ATBUS_MACRO_API send_data_options_t(std::initializer_list<flag_type> flag_list) noexcept;

    ATBUS_MACRO_API send_data_options_t(gsl::span<flag_type> flag_list) noexcept;

    ATBUS_MACRO_API ~send_data_options_t();
    ATBUS_MACRO_API send_data_options_t(const send_data_options_t &other);
    ATBUS_MACRO_API send_data_options_t &operator=(const send_data_options_t &other);
    ATBUS_MACRO_API send_data_options_t(send_data_options_t &&other);
    ATBUS_MACRO_API send_data_options_t &operator=(send_data_options_t &&other);
  };

  struct conf_t {
    adapter::loop_t *ev_loop;
    std::bitset<conf_flag_t::EN_CONF_MAX> flags;                  /** 开关配置 **/
    std::string upstream_address;                                 /** 上游节点地址 **/
    std::unordered_map<std::string, std::string> topology_labels; /** 拓扑标签 **/
    int32_t loop_times; /** 消息循环次数限制，防止某些通道繁忙把其他通道堵死 **/
    int32_t ttl;        /** 消息转发跳转限制 **/
    int32_t protocol_version;
    int32_t protocol_minimal_version;

    // ===== 连接配置 =====
    int32_t backlog;
    std::chrono::microseconds first_idle_timeout; /** 第一个包允许的空闲时间 **/
    std::chrono::microseconds ping_interval;      /** ping包间隔 **/
    std::chrono::microseconds retry_interval;     /** 重试包间隔 **/
    size_t fault_tolerant;                        /** 容错次数，次 **/
    size_t access_token_max_number;               /** 最大access token数量，请不要设置的太大，验证次数最大可能是N^2 **/
    std::vector<std::vector<unsigned char>> access_tokens; /** access token列表 **/
    bool overwrite_listen_path;                            /** 是否覆盖已存在的listen path(unix/pipe socket) **/

    // ===== 加密算法配置 =====
    protocol::ATBUS_CRYPTO_KEY_EXCHANGE_TYPE crypto_key_exchange_type;
    std::chrono::microseconds crypto_key_refresh_interval;
    std::vector<protocol::ATBUS_CRYPTO_ALGORITHM_TYPE> crypto_allow_algorithms;

    // ===== 压缩算法配置 =====
    std::vector<protocol::ATBUS_COMPRESSION_ALGORITHM_TYPE> compression_allow_algorithms;

    // ===== 缓冲区配置 =====
    size_t message_size;        /** max message size **/
    size_t receive_buffer_size; /** 接收缓冲区，和数据包大小有关 **/
    size_t send_buffer_size;    /** 发送缓冲区限制 **/
    size_t send_buffer_number;  /** 发送缓冲区静态Buffer数量限制，0则为动态缓冲区 **/

    ATBUS_MACRO_API conf_t();
    ATBUS_MACRO_API conf_t(const conf_t &other);
    ATBUS_MACRO_API ~conf_t();
    ATBUS_MACRO_API conf_t &operator=(const conf_t &other);
  };

  struct start_conf_t {
    std::chrono::system_clock::time_point timer_timepoint;
  };

  using endpoint_collection_t = std::unordered_map<bus_id_t, endpoint::ptr_t>;

  struct event_handle_set_t {
    // 接收消息事件回调 => 参数列表: 发起节点，来源对端，来源连接，消息体，数据地址，数据长度
    using on_forward_request_fn_t = std::function<int(const node &, const endpoint *, const connection *,
                                                      const message &, gsl::span<const unsigned char>)>;
    // 发送消息失败事件或成功通知回调 => 参数列表: 发起节点，来源对端，来源连接，消息体
    // @note
    // 除非发送时标记atbus::protocol::FORWARD_DATA_FLAG_REQUIRE_RSP为true(即需要通知)，否则成功发送消息默认不回发通知
    using on_forward_response_fn_t =
        std::function<int(const node &, const endpoint *, const connection *, const message *m)>;
    // 新对端注册事件回调 => 参数列表: 发起节点，来源对端，来源连接，返回码
    using on_register_fn_t = std::function<int(const node &, const endpoint *, const connection *, ATBUS_ERROR_TYPE)>;
    // 节点关闭事件回调 => 参数列表: 发起节点，下线原因
    using on_node_down_fn_t = std::function<int(const node &, ATBUS_ERROR_TYPE)>;
    // 节点开始服务事件回调 => 参数列表: 发起节点，错误码，通常是 EN_ATBUS_ERR_SUCCESS
    using on_node_up_fn_t = std::function<int(const node &, ATBUS_ERROR_TYPE)>;
    // 失效连接事件回调 => 参数列表: 发起节点，来源连接，错误码，通常是 EN_ATBUS_ERR_NODE_TIMEOUT
    using on_invalid_connection_fn_t = std::function<int(const node &, const connection *, ATBUS_ERROR_TYPE)>;
    using on_new_connection_fn_t = std::function<int(const node &, const connection *)>;
    // 接收到命令消息事件回调 => 参数列表:
    //      发起节点，来源对端，来源连接，来源节点ID，命令参数列表，返回信息列表（跨节点的共享内存和内存通道的返回消息将被忽略）
    using on_custom_command_request_fn_t =
        std::function<int(const node &, const endpoint *, const connection *, bus_id_t,
                          gsl::span<gsl::span<const unsigned char>>, std::list<std::string> &)>;
    // 接收到命令回包事件回调 => 参数列表: 发起节点，来源对端，来源连接，来源节点ID，回包数据列表，对应请求包的sequence
    using on_custom_command_response_fn_t =
        std::function<int(const node &, const endpoint *, const connection *, bus_id_t,
                          gsl::span<gsl::span<const unsigned char>>, uint64_t)>;
    // 对端上线事件回调 => 参数列表: 发起节点，新增的对端，错误码，通常是 EN_ATBUS_ERR_SUCCESS
    using on_add_endpoint_fn_t = std::function<int(const node &, endpoint *, ATBUS_ERROR_TYPE)>;
    // 对端离线事件回调 => 参数列表: 发起节点，新增的对端，错误码，通常是 EN_ATBUS_ERR_SUCCESS
    using on_remove_endpoint_fn_t = std::function<int(const node &, endpoint *, ATBUS_ERROR_TYPE)>;
    // 对端ping/pong事件回调 => 参数列表: 发起节点，ping/pong的对端，消息体，ping_data
    using on_ping_pong_endpoint_fn_t = std::function<int(const node &, const endpoint *, const message &,
                                                         const ::atframework::atbus::protocol::ping_data &)>;

    // 拓扑关系-当前节点的上游拓扑变更回调 => 参数列表: 发起节点，几方拓扑节点，新上游节点，当前节点的拓扑数据
    using on_topology_update_upstream_fn_t = std::function<void(
        const node &, const topology_peer::ptr_t &, const topology_peer::ptr_t &, const topology_data::ptr_t &)>;

    on_forward_request_fn_t on_forward_request;
    on_forward_response_fn_t on_forward_response;
    on_register_fn_t on_register;
    on_node_down_fn_t on_node_down;
    on_node_up_fn_t on_node_up;
    on_invalid_connection_fn_t on_invalid_connection;
    on_new_connection_fn_t on_new_connection;
    on_custom_command_request_fn_t on_custom_command_request;
    on_custom_command_response_fn_t on_custom_command_response;
    on_add_endpoint_fn_t on_endpoint_added;
    on_remove_endpoint_fn_t on_endpoint_removed;
    on_ping_pong_endpoint_fn_t on_endpoint_ping;
    on_ping_pong_endpoint_fn_t on_endpoint_pong;
    on_topology_update_upstream_fn_t on_topology_update_upstream;
  };

  struct flag_guard_t {
    node *owner;
    flag_t::type flag;
    bool holder;
    ATBUS_MACRO_API flag_guard_t(const node *o, flag_t::type f);
    ATBUS_MACRO_API ~flag_guard_t();

    inline operator bool() { return holder; }
  };

 public:
  static ATBUS_MACRO_API void default_conf(conf_t *conf);
  static ATBUS_MACRO_API void default_conf(start_conf_t *conf);

  UTIL_DESIGN_PATTERN_NOCOPYABLE(node)
  UTIL_DESIGN_PATTERN_NOMOVABLE(node)

 private:
  node();

  struct io_stream_channel_del {
    void operator()(channel::io_stream_channel *p) const;
  };

 public:
  static ATBUS_MACRO_API ptr_t create();
  ATBUS_MACRO_API ~node();

  /**
   * @brief 数据初始化
   * @return 0或错误码
   */
  ATBUS_MACRO_API int init(bus_id_t id, const conf_t *conf);

  /**
   * @brief 启动连接流程
   * @return 0或错误码
   */
  ATBUS_MACRO_API void reload_crypto(protocol::ATBUS_CRYPTO_KEY_EXCHANGE_TYPE crypto_key_exchange_type,
                                     std::chrono::microseconds crypto_key_refresh_interval,
                                     gsl::span<const protocol::ATBUS_CRYPTO_ALGORITHM_TYPE> crypto_allow_algorithms);

  /**
   * @brief 启动连接流程
   * @return 0或错误码
   */
  ATBUS_MACRO_API void reload_compression(
      gsl::span<const protocol::ATBUS_COMPRESSION_ALGORITHM_TYPE> compression_allow_algorithms);

  /**
   * @brief 启动连接流程
   * @return 0或错误码
   */
  ATBUS_MACRO_API int start(const start_conf_t &start_conf);

  /**
   * @brief 启动连接流程
   * @return 0或错误码
   */
  ATBUS_MACRO_API int start();

  /**
   * @brief 数据重置（释放资源）
   * @return 0或错误码
   */
  ATBUS_MACRO_API int reset();

  /**
   * @brief 执行一帧
   * @param now 当前时间
   * @return 本帧处理的消息数
   */
  ATBUS_MACRO_API int proc(std::chrono::system_clock::time_point now);

  /**
   * @brief poll libuv
   * @note can not be call in any libuv's callback
   * @return the number of message dispatched
   */
  ATBUS_MACRO_API int poll();

  /**
   * @brief 监听数据接收地址
   * @param addr 监听地址
   * @param is_caddr 是否是控制节点
   * @return 0或错误码
   */
  ATBUS_MACRO_API int listen(gsl::string_view addr);

  /**
   * @brief 连接到目标地址
   * @param addr 连接目标地址
   * @return 0或错误码
   */
  ATBUS_MACRO_API int connect(gsl::string_view addr);

  /**
   * @brief 连接到目标地址
   * @param addr 连接目标地址
   * @param ep 连接目标的端点
   * @return 0或错误码
   */
  ATBUS_MACRO_API int connect(gsl::string_view addr, endpoint *ep);

  /**
   * @brief 断开到目标的连接
   * @param id 目标ID
   * @return 0或错误码
   */
  ATBUS_MACRO_API int disconnect(bus_id_t id);

  /**
   * @brief 获取加密密钥交换算法类型
   * @return 加密密钥交换算法类型
   */
  ATBUS_MACRO_API protocol::ATBUS_CRYPTO_KEY_EXCHANGE_TYPE get_crypto_key_exchange_type() const noexcept;

  /**
   * @brief 获取加密密钥交换共享数据上下文
   * @return 加密密钥交换共享数据上下文
   */
  ATBUS_MACRO_API const ::atfw::util::crypto::dh::shared_context::ptr_t &get_crypto_key_exchange_context()
      const noexcept;

  /**
   * @brief 发送数据
   * @param tid 发送目标ID
   * @param type 自定义类型，将作为message.head.type字段传递。可用于业务区分服务类型
   * @param data 要发送的数据块
   * @return 0或错误码
   * @note 接收端收到的数据很可能不是地址对齐的，所以这里不建议发送内存数据对象(struct/class)
   *       如果非要发送内存数据的话，接收端一定要memcpy，不能直接类型转换，除非手动设置了地址对齐规则
   */
  ATBUS_MACRO_API int send_data(bus_id_t tid, int type, gsl::span<const unsigned char> data);

  /**
   * @brief 发送数据
   * @param tid 发送目标ID
   * @param type 自定义类型，将作为message.head.type字段传递。可用于业务区分服务类型
   * @param data 要发送的数据块
   * @param options 发送选项,如果未设置sequence,会自动分配并传出
   * @return 0或错误码
   * @note 接收端收到的数据很可能不是地址对齐的，所以这里不建议发送内存数据对象(struct/class)
   *       如果非要发送内存数据的话，接收端一定要memcpy，不能直接类型转换，除非手动设置了地址对齐规则
   */
  ATBUS_MACRO_API int send_data(bus_id_t tid, int type, gsl::span<const unsigned char> data,
                                send_data_options_t &options);

  /**
   * @brief 发送自定义命令消息
   * @param tid 发送目标ID
   * @param args 自定义消息内容数组
   * @param options 发送选项,如果未设置sequence,会自动分配并传出
   * @return 0或错误码
   */
  ATBUS_MACRO_API int send_custom_command(bus_id_t tid, gsl::span<gsl::span<const unsigned char>> args);

  /**
   * @brief 发送自定义命令消息
   * @param tid 发送目标ID
   * @param args 自定义消息内容数组
   * @param options 发送选项,如果未设置sequence,会自动分配并传出
   * @return 0或错误码
   */
  ATBUS_MACRO_API int send_custom_command(bus_id_t tid, gsl::span<gsl::span<const unsigned char>> args,
                                          send_data_options_t &options);

  /**
   * @brief 获取远程发送目标信息
   * @param tid 发送目标ID，不能是自己的的BUS ID
   * @param fn 获取有效连接的接口，用以区分数据通道和控制通道
   * @param ep_out 如果发送成功，导出发送目标，否则导出NULL
   * @param conn_out 如果发送成功，导出发送连接，否则导出NULL
   * @return 0或错误码
   */
  ATBUS_MACRO_API ATBUS_ERROR_TYPE get_peer_channel(bus_id_t tid, endpoint::get_connection_fn_t fn, endpoint **ep_out,
                                                    connection **conn_out);

  /**
   * @brief 设置当前节点的上游端点拓扑关系
   * @param tid 上游端点ID
   */
  ATBUS_MACRO_API void set_topology_upstream(bus_id_t tid);

  /**
   * @brief 根据对端ID查找直链的端点
   * @param tid 目标端点ID
   * @return 直连的端点，不存在则返回NULL
   */
  ATBUS_MACRO_API endpoint *get_endpoint(bus_id_t tid) noexcept;

  /**
   * @brief 根据对端ID查找直链的端点
   * @param tid 目标端点ID
   * @return 直连的端点，不存在则返回NULL
   */
  ATBUS_MACRO_API const endpoint *get_endpoint(bus_id_t tid) const noexcept;

  /**
   * @brief 添加目标端点
   * @param ep 目标端点
   * @return 0或错误码
   */
  ATBUS_MACRO_API ATBUS_ERROR_TYPE add_endpoint(endpoint::ptr_t ep);

  /**
   * @brief 移除目标端点
   * @param tid 目标端点ID
   * @return 0或错误码
   */
  ATBUS_MACRO_API ATBUS_ERROR_TYPE remove_endpoint(bus_id_t tid);

  /**
   * @brief 是否有到对端的数据通道(可以向对端发送数据)
   * @note 如果只有控制通道没有数据通道返回false
   * @param tid 目标端点ID
   * @return 有则返回true
   */
  ATBUS_MACRO_API bool is_endpoint_available(bus_id_t tid) const;

  /**
   * @brief 检查access token集合的有效性
   * @param access_key access token集合和参数数据
   * @param plaintext 需要进行签名的明文数据
   * @param conn 关联的连接
   * @return 没有检查通过的access token则返回false
   */
  ATBUS_MACRO_API bool check_access_hash(const ::atframework::atbus::protocol::access_data &access_key,
                                         atfw::util::nostd::string_view plaintext, connection *conn) const;

  /**
   * @brief 获取节点的hash code
   */
  ATBUS_MACRO_API const std::string &get_hash_code() const;

 public:
  ATBUS_MACRO_API channel::io_stream_channel *get_iostream_channel();

  ATBUS_MACRO_API const endpoint *get_self_endpoint() const;

  ATBUS_MACRO_API const endpoint *get_upstream_endpoint() const;

  ATBUS_MACRO_API const endpoint_collection_t &get_immediate_endpoint_set() const;

  /**
   * @brief 获取关联的事件管理器,如果未设置则会初始化为默认时间管理器
   * @return 关联的事件管理器
   */
  ATBUS_MACRO_API adapter::loop_t *get_evloop();

 private:
  ATBUS_ERROR_TYPE remove_endpoint(bus_id_t tid, endpoint *expected);

  /**
   * @brief 发送数据消息
   * @param tid 发送目标ID
   * @param message_builder 消息构建器
   * @return 0或错误码
   */
  ATBUS_ERROR_TYPE send_data_message(bus_id_t tid, message_builder_ref_t mb);

  /**
   * @brief 发送数据消息
   * @param tid 发送目标ID
   * @param message_builder 消息构建器
   * @param ep_out 如果发送成功，导出发送目标
   * @param conn_out 如果发送成功，导出发送连接
   * @return 0或错误码
   */
  ATBUS_ERROR_TYPE send_data_message(bus_id_t tid, message_builder_ref_t mb, endpoint **ep_out, connection **conn_out);

  /**
   * @brief 发送控制消息
   * @param tid 发送目标ID
   * @param message_builder 消息构建器
   * @return 0或错误码
   */
  ATBUS_ERROR_TYPE send_ctrl_message(bus_id_t tid, message_builder_ref_t mb);

  /**
   * @brief 发送控制消息
   * @param tid 发送目标ID
   * @param message_builder 消息构建器
   * @param ep_out 如果发送成功，导出发送目标
   * @param conn_out 如果发送成功，导出发送连接
   * @return 0或错误码
   */
  ATBUS_ERROR_TYPE send_ctrl_message(bus_id_t tid, message_builder_ref_t mb, endpoint **ep_out, connection **conn_out);

  /**
   * @brief 发送消息
   * @param tid 发送目标ID
   * @param message_builder 消息构建器
   * @param fn 获取有效连接的接口，用以区分数据通道和控制通道
   * @param ep_out 如果发送成功，导出发送目标
   * @param conn_out 如果发送成功，导出发送连接
   * @return 0或错误码
   */
  ATBUS_ERROR_TYPE send_message(bus_id_t tid, message_builder_ref_t message_builder, endpoint::get_connection_fn_t fn,
                                endpoint **ep_out, connection **conn_out);

  channel::io_stream_conf *get_iostream_conf();

 public:
  ATBUS_MACRO_API bus_id_t get_id() const;
  ATBUS_MACRO_API const conf_t &get_conf() const;

  ATBUS_MACRO_API bool check_flag(flag_t::type f) const;
  ATBUS_MACRO_API state_t::type get_state() const;

  ATBUS_MACRO_API ptr_t get_watcher();

  ATBUS_MACRO_API const ::atfw::util::nostd::nonnull<topology_registry::ptr_t> &get_topology_registry() const noexcept;

  ATBUS_MACRO_API topology_relation_type get_topology_relation(bus_id_t id,
                                                               topology_peer::ptr_t *next_hop_peer) const noexcept;

  static ATBUS_MACRO_API int get_pid();
  static ATBUS_MACRO_API const std::string &get_hostname();
  /**
   * @brief 设置hostname，用于再查找路由路径时区分是否同物理机，不设置的话默认会自动检测本机地址生成一个
   * @param hn 本机物理机名称，全局共享。仅会影响这之后创建的node
   * @param force 是否强制设置，一般情况下已经有node使用过物理地址的情况下不允许设置
   * @return 成功返回true
   */
  static ATBUS_MACRO_API bool set_hostname(gsl::string_view hn, bool force = false);

  ATBUS_MACRO_API int32_t get_protocol_version() const;

  ATBUS_MACRO_API int32_t get_protocol_minimal_version() const;

  ATBUS_MACRO_API const std::list<channel::channel_address_t> &get_listen_list() const;

  ATBUS_MACRO_API bool add_proc_connection(connection::ptr_t conn);
  ATBUS_MACRO_API bool remove_proc_connection(const std::string &conn_key);

  ATBUS_MACRO_API bool add_connection_timer(connection::ptr_t conn);

  ATBUS_MACRO_API bool remove_connection_timer(const connection *conn);

  ATBUS_MACRO_API size_t get_connection_timer_size() const;

  ATBUS_MACRO_API std::chrono::system_clock::time_point get_timer_tick() const;

  ATBUS_MACRO_API void on_receive_message(connection *conn, message &&m, int status, ATBUS_ERROR_TYPE errcode);

  ATBUS_MACRO_API void on_receive_data(const endpoint *ep, connection *conn, const message &m,
                                       gsl::span<const unsigned char> data) const;

  ATBUS_MACRO_API void on_receive_forward_response(const endpoint *, const connection *, const message *m);

  ATBUS_MACRO_API ATBUS_ERROR_TYPE on_disconnect(const connection *);
  ATBUS_MACRO_API ATBUS_ERROR_TYPE on_new_connection(connection *);
  ATBUS_MACRO_API ATBUS_ERROR_TYPE on_shutdown(ATBUS_ERROR_TYPE errcode);
  ATBUS_MACRO_API ATBUS_ERROR_TYPE on_register(const endpoint *, const connection *, ATBUS_ERROR_TYPE);
  ATBUS_MACRO_API ATBUS_ERROR_TYPE on_actived();
  ATBUS_MACRO_API ATBUS_ERROR_TYPE on_upstream_register_done();
  ATBUS_MACRO_API ATBUS_ERROR_TYPE on_custom_command_request(const endpoint *, const connection *, bus_id_t from,
                                                             gsl::span<gsl::span<const unsigned char>> args,
                                                             std::list<std::string> &rsp);
  ATBUS_MACRO_API ATBUS_ERROR_TYPE on_custom_command_response(const endpoint *, const connection *, bus_id_t from,
                                                              gsl::span<gsl::span<const unsigned char>> args,
                                                              uint64_t sequence);

  ATBUS_MACRO_API ATBUS_ERROR_TYPE on_ping(const endpoint *ep, const message &m,
                                           const ::atframework::atbus::protocol::ping_data &body);
  ATBUS_MACRO_API ATBUS_ERROR_TYPE on_pong(const endpoint *ep, const message &m,
                                           const ::atframework::atbus::protocol::ping_data &body);

  /**
   * @brief 关闭node
   * @param errcode 关闭原因错误码
   * @note 如果需要在关闭前执行资源回收，可以在on_node_down_fn_t回调中返回非0值来阻止node的reset操作，
   *       并在资源释放完成后再调用shutdown函数，在第二次on_node_down_fn_t回调中返回0值
   *
   * @note 或者也可以通过ref_object和unref_object来标记和解除数据引用，reset函数会执行事件loop知道所有引用的资源被移除
   */
  ATBUS_MACRO_API int shutdown(ATBUS_ERROR_TYPE errcode);

  /** do not use this directly **/
  ATBUS_MACRO_API int fatal_shutdown(const atfw::util::log::log_wrapper::caller_info_t &caller, const endpoint *,
                                     const connection *, int status, ATBUS_ERROR_TYPE errcode);

  /** dispatch all self messages **/
  ATBUS_MACRO_API int dispatch_all_self_messages();

  ATBUS_MACRO_API const detail::buffer_block *get_temp_static_buffer() const;
  ATBUS_MACRO_API detail::buffer_block *get_temp_static_buffer();

  ATBUS_MACRO_API int ping_endpoint(endpoint &ep);

  ATBUS_MACRO_API uint64_t allocate_message_sequence();

  ATBUS_MACRO_API void add_endpoint_gc_list(const endpoint::ptr_t &ep);

  ATBUS_MACRO_API void add_connection_gc_list(const connection::ptr_t &conn);

  ATBUS_MACRO_API void set_on_forward_request_handle(event_handle_set_t::on_forward_request_fn_t fn);
  ATBUS_MACRO_API const event_handle_set_t::on_forward_request_fn_t &get_on_forward_request_handle() const;

  ATBUS_MACRO_API void set_on_forward_response_handle(event_handle_set_t::on_forward_response_fn_t fn);
  ATBUS_MACRO_API const event_handle_set_t::on_forward_response_fn_t &get_on_forward_response_handle() const;

  ATBUS_MACRO_API void set_on_register_handle(event_handle_set_t::on_register_fn_t fn);
  ATBUS_MACRO_API const event_handle_set_t::on_register_fn_t &get_on_register_handle() const;

  ATBUS_MACRO_API void set_on_shutdown_handle(event_handle_set_t::on_node_down_fn_t fn);
  ATBUS_MACRO_API const event_handle_set_t::on_node_down_fn_t &get_on_shutdown_handle() const;

  ATBUS_MACRO_API void set_on_available_handle(event_handle_set_t::on_node_up_fn_t fn);
  ATBUS_MACRO_API const event_handle_set_t::on_node_up_fn_t &get_on_available_handle() const;

  ATBUS_MACRO_API void set_on_invalid_connection_handle(event_handle_set_t::on_invalid_connection_fn_t fn);
  ATBUS_MACRO_API const event_handle_set_t::on_invalid_connection_fn_t &get_on_invalid_connection_handle() const;

  ATBUS_MACRO_API void set_on_new_connection_handle(event_handle_set_t::on_new_connection_fn_t fn);
  ATBUS_MACRO_API const event_handle_set_t::on_new_connection_fn_t &get_on_new_connection_handle() const;

  ATBUS_MACRO_API void set_on_custom_command_request_handle(event_handle_set_t::on_custom_command_request_fn_t fn);
  ATBUS_MACRO_API const event_handle_set_t::on_custom_command_request_fn_t &get_on_custom_command_request_handle()
      const;

  ATBUS_MACRO_API void set_on_custom_command_response_handle(event_handle_set_t::on_custom_command_response_fn_t fn);
  ATBUS_MACRO_API const event_handle_set_t::on_custom_command_response_fn_t &get_on_custom_command_response_handle()
      const;

  ATBUS_MACRO_API void set_on_add_endpoint_handle(event_handle_set_t::on_add_endpoint_fn_t fn);
  ATBUS_MACRO_API const event_handle_set_t::on_add_endpoint_fn_t &get_on_add_endpoint_handle() const;

  ATBUS_MACRO_API void set_on_remove_endpoint_handle(event_handle_set_t::on_remove_endpoint_fn_t fn);
  ATBUS_MACRO_API const event_handle_set_t::on_remove_endpoint_fn_t &get_on_remove_endpoint_handle() const;

  ATBUS_MACRO_API void set_on_ping_endpoint_handle(event_handle_set_t::on_ping_pong_endpoint_fn_t fn);
  ATBUS_MACRO_API const event_handle_set_t::on_ping_pong_endpoint_fn_t &get_on_ping_endpoint_handle() const;

  ATBUS_MACRO_API void set_on_pong_endpoint_handle(event_handle_set_t::on_ping_pong_endpoint_fn_t fn);
  ATBUS_MACRO_API const event_handle_set_t::on_ping_pong_endpoint_fn_t &get_on_pong_endpoint_handle() const;

  ATBUS_MACRO_API void set_on_topology_update_upstream_handle(event_handle_set_t::on_topology_update_upstream_fn_t fn);
  ATBUS_MACRO_API const event_handle_set_t::on_topology_update_upstream_fn_t &get_on_topology_update_upstream_handle()
      const;

  ATFW_UTIL_FORCEINLINE const atfw::util::log::log_wrapper::ptr_t &get_logger() const noexcept { return logger_; }

  ATBUS_MACRO_API void set_logger(atfw::util::log::log_wrapper::ptr_t logger) noexcept;

  ATFW_UTIL_FORCEINLINE bool is_debug_message_verbose_enabled() const noexcept {
    return logger_enable_debug_message_verbose_;
  }

  ATFW_UTIL_FORCEINLINE void enable_debug_message_verbose() noexcept { logger_enable_debug_message_verbose_ = true; }

  ATFW_UTIL_FORCEINLINE void disable_debug_message_verbose() noexcept { logger_enable_debug_message_verbose_ = false; }

  // inner API, please don't use it if you don't known what will happen
  ATBUS_MACRO_API void ref_object(void *);
  // inner API, please don't use it if you don't known what will happen
  ATBUS_MACRO_API void unref_object(void *);

  static ATBUS_MACRO_API protocol::ATBUS_CRYPTO_ALGORITHM_TYPE parse_crypto_algorithm_name(
      gsl::string_view name) noexcept;

  static ATBUS_MACRO_API protocol::ATBUS_COMPRESSION_ALGORITHM_TYPE parse_compression_algorithm_name(
      gsl::string_view name) noexcept;

 private:
  static endpoint *find_route(endpoint_collection_t &coll, bus_id_t id);

  bool insert_child(endpoint_collection_t &coll, endpoint::ptr_t ep, bool ignore_event = false);

  bool remove_child(endpoint_collection_t &coll, bus_id_t id, endpoint *expected = nullptr, bool ignore_event = false);

  bool remove_collection(endpoint_collection_t &coll);

  /**
   * @brief 增加错误计数，如果超出容忍值则移除
   * @return 是否被移除
   */
  bool add_endpoint_fault(endpoint &ep);

  /**
   * @brief 增加错误计数，如果超出容忍值则断开连接
   * @return 是否被移除
   */
  bool add_connection_fault(connection &conn);

  /**
   * @brief 添加到ping timer列表
   */
  bool add_ping_timer(const endpoint::ptr_t &ep);

  /**
   * @brief 从ping timer列表中移除
   */
  void remove_ping_timer(const endpoint *ep);

  friend class node_access_controller;
  friend struct node_msg_test_access;

  void init_hash_code();

 public:
  ATBUS_MACRO_API void stat_add_dispatch_times();

 private:
  // ============ 基础信息 ============
  // ID
  endpoint::ptr_t self_;
  state_t::type state_;
  std::bitset<flag_t::EN_FT_MAX> flags_;
  topology_registry::ptr_t topology_registry_;

  // 配置
  conf_t conf_;
  topology_data::ptr_t topology_;
  std::string hash_code_;
  ::atfw::util::memory::weak_rc_ptr<node> watcher_;  // just like std::shared_from_this<T>
  atfw::util::lock::seq_alloc_u64 message_sequence_allocator_;

  // 加密设置
  protocol::ATBUS_CRYPTO_KEY_EXCHANGE_TYPE crypto_key_exchange_type_;
  ::atfw::util::crypto::dh::shared_context::ptr_t crypto_key_exchange_context_;

  // 引用的资源标记（释放时要保证这些资源引用被移除）
  std::set<void *> ref_objs_;

  // ============ IO事件数据 ============
  // 事件分发器
  adapter::loop_t *ev_loop_;
  std::unique_ptr<channel::io_stream_channel, io_stream_channel_del> iostream_channel_;
  std::unique_ptr<channel::io_stream_conf> iostream_conf_;
  event_handle_set_t event_message_;
  using self_data_messages_t = std::list<message>;
  using self_command_messages_t = std::list<message>;
  self_data_messages_t self_data_messages_;
  self_command_messages_t self_command_messages_;

  // ============ 定时器 ============
  struct evt_timer_t {
    std::chrono::system_clock::time_point tick;

    std::chrono::system_clock::time_point upstream_op_timepoint;  // 上游节点操作时间（断线重连或Ping）
    timer_desc_ls<const endpoint *, ::atfw::util::memory::weak_rc_ptr<endpoint>>::type ping_list;  // 定时ping
    timer_desc_ls<std::string, connection::ptr_t>::type connecting_list;  // 未完成连接（正在网络连接或握手）
    std::list<endpoint::ptr_t> pending_endpoint_gc_list;                  // 待检测GC的endpoint列表
    std::list<connection::ptr_t> pending_connection_gc_list;              // 待检测GC的connection列表
  };
  evt_timer_t event_timer_;

  // 轮训接收通道集
  detail::buffer_block *static_buffer_;
  std::unordered_map<std::string, connection::ptr_t> proc_connections_;

  // 基于事件的通道信息
  // 基于事件的通道超时收集

  // ============ 节点逻辑关系数据 ============
  // 上游节点
  struct upstream_info_t {
    endpoint::ptr_t node_;
  };
  upstream_info_t node_upstream_;  // 上游节点（默认路由，自动重连）

  // 路由节点
  endpoint_collection_t node_route_;

  // 统计信息
  struct stat_info_t {
    size_t dispatch_times;

    stat_info_t();
  };
  stat_info_t stat_;
  random_engine_t random_engine_;

  atfw::util::log::log_wrapper::ptr_t logger_;
  bool logger_enable_debug_message_verbose_;

 public:
  friend struct message_handler;
};

namespace details {
ATFW_UTIL_FORCEINLINE uint64_t __log_get_node_id(const node &n) noexcept { return n.get_id(); }
ATFW_UTIL_FORCEINLINE uint64_t __log_get_endpoint_id(const endpoint *ep) noexcept {
  if (ep == nullptr) {
    return 0;
  }

  return ep->get_id();
}
ATFW_UTIL_FORCEINLINE const void *__log_get_connection_fmt_ptr(const connection *c) noexcept {
  return reinterpret_cast<const void *>(c);
}
ATFW_UTIL_FORCEINLINE std::string __log_get_message_debug_head(const message *m) noexcept {
  if (m == nullptr) {
    return {};
  }

  return m->get_head_debug_string();
}

ATFW_UTIL_FORCEINLINE std::string __log_get_message_debug_body(const message *m) noexcept {
  if (m == nullptr) {
    return {};
  }

  return m->get_body_debug_string();
}

ATFW_UTIL_FORCEINLINE bool __log_has_message_data(const message *m) noexcept {
  if (m == nullptr) {
    return false;
  }

  return m->get_head() != nullptr || m->get_body() != nullptr;
}
}  // namespace details
ATBUS_MACRO_NAMESPACE_END

#define ATBUS_FUNC_NODE_FATAL_SHUTDOWN(n, ep, conn, status, errorcode)                                              \
  (n).fatal_shutdown(WDTLOGFILENF(atfw::util::log::log_wrapper::level_t::LOG_LW_ERROR, {}), (ep), (conn), (status), \
                     (errorcode))

#ifdef _MSC_VER
#  define ATBUS_FUNC_NODE_ERROR(n, ep, conn, status, errorcode, fmt, ...)                                              \
    if ((n).get_logger()) {                                                                                            \
      FWINSTLOGERROR(*(n).get_logger(), "node={:#x}, endpoint={:#x}, connection={}, status: {}, error_code: {}: " fmt, \
                     ::atframework::atbus::details::__log_get_node_id(n),                                              \
                     ::atframework::atbus::details::__log_get_endpoint_id(ep),                                         \
                     ::atframework::atbus::details::__log_get_connection_fmt_ptr(conn), (status), (errorcode),         \
                     __VA_ARGS__)                                                                                      \
    }

#  define ATBUS_FUNC_NODE_INFO(n, ep, conn, fmt, ...)                                               \
    if ((n).get_logger()) {                                                                         \
      FWINSTLOGINFO(*(n).get_logger(), "node={:#x}, endpoint={:#x}, connection={}: " fmt,           \
                    ::atframework::atbus::details::__log_get_node_id(n),                            \
                    ::atframework::atbus::details::__log_get_endpoint_id(ep),                       \
                    ::atframework::atbus::details::__log_get_connection_fmt_ptr(conn), __VA_ARGS__) \
    }

#  define ATBUS_FUNC_NODE_DEBUG(n, ep, conn, m, fmt, ...)                                                       \
    if ((n).get_logger()) {                                                                                     \
      FWINSTLOGDEBUG(*(n).get_logger(), "node={:#x}, endpoint={:#x}, connection={}: " fmt,                      \
                     ::atframework::atbus::details::__log_get_node_id((n)),                                     \
                     ::atframework::atbus::details::__log_get_endpoint_id((ep)),                                \
                     ::atframework::atbus::details::__log_get_connection_fmt_ptr(conn), __VA_ARGS__)            \
      if ((n).is_debug_message_verbose_enabled() && ::atframework::atbus::details::__log_has_message_data(m)) { \
        FWINSTLOGDEBUG(*(n).get_logger(), "\tmessage head: {}\n\tmessage body: {}",                             \
                       ::atframework::atbus::details::__log_get_message_debug_head(m),                          \
                       ::atframework::atbus::details::__log_get_message_debug_body(m))                          \
      }                                                                                                         \
    }
#else

#  define ATBUS_FUNC_NODE_ERROR(n, ep, conn, status, errorcode, fmt, args...)                                          \
    if ((n).get_logger()) {                                                                                            \
      FWINSTLOGERROR(*(n).get_logger(), "node={:#x}, endpoint={:#x}, connection={}, status: {}, error_code: {}: " fmt, \
                     ::atframework::atbus::details::__log_get_node_id(n),                                              \
                     ::atframework::atbus::details::__log_get_endpoint_id(ep),                                         \
                     ::atframework::atbus::details::__log_get_connection_fmt_ptr(conn), (status), (errorcode), ##args) \
    }

#  define ATBUS_FUNC_NODE_INFO(n, ep, conn, fmt, args...)                                      \
    if ((n).get_logger()) {                                                                    \
      FWINSTLOGINFO(*(n).get_logger(), "node={:#x}, endpoint={:#x}, connection={}: " fmt,      \
                    ::atframework::atbus::details::__log_get_node_id(n),                       \
                    ::atframework::atbus::details::__log_get_endpoint_id(ep),                  \
                    ::atframework::atbus::details::__log_get_connection_fmt_ptr(conn), ##args) \
    }

#  define ATBUS_FUNC_NODE_DEBUG(n, ep, conn, m, fmt, args...)                                                   \
    if ((n).get_logger()) {                                                                                     \
      FWINSTLOGDEBUG(*(n).get_logger(), "node={:#x}, endpoint={:#x}, connection={}: " fmt,                      \
                     ::atframework::atbus::details::__log_get_node_id((n)),                                     \
                     ::atframework::atbus::details::__log_get_endpoint_id((ep)),                                \
                     ::atframework::atbus::details::__log_get_connection_fmt_ptr(conn), ##args)                 \
      if ((n).is_debug_message_verbose_enabled() && ::atframework::atbus::details::__log_has_message_data(m)) { \
        FWINSTLOGDEBUG(*(n).get_logger(), "\tmessage head: {}\n\tmessage body: {}",                             \
                       ::atframework::atbus::details::__log_get_message_debug_head(m),                          \
                       ::atframework::atbus::details::__log_get_message_debug_body(m))                          \
      }                                                                                                         \
    }
#endif
