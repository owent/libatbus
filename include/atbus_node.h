/**
 * atbus_node.h
 *
 *  Created on: 2015年10月29日
 *      Author: owent
 */

#ifndef LIBATBUS_NODE_H
#define LIBATBUS_NODE_H

#pragma once

#include <bitset>
#include <cstddef>
#include <ctime>
#include <list>
#include <map>
#include <set>
#include <stdint.h>
#include <vector>

#if defined(_WIN32) || defined(__WIN32__) || defined(WIN32)
#include <WinSock2.h>
#endif

#include <design_pattern/noncopyable.h>
#include <design_pattern/nomovable.h>

#include "lock/seq_alloc.h"
#include "random/random_generator.h"
#include "std/functional.h"
#include "std/smart_ptr.h"


#include "detail/libatbus_channel_export.h"
#include "detail/libatbus_config.h"
#include "detail/libatbus_error.h"

#include "atbus_endpoint.h"

namespace atbus {

    class node UTIL_CONFIG_FINAL : public util::design_pattern::noncopyable {
    public:
        typedef std::shared_ptr<node> ptr_t;
        typedef ::atbus::protocol::msg &msg_builder_ref_t;

        typedef ATBUS_MACRO_BUSID_TYPE bus_id_t;
        struct conf_flag_t {
            enum type {
                EN_CONF_MAX = 0,
            };
        };

        /** 并没有非常复杂的状态切换，所以没有引入状态机 **/
        struct state_t {
            enum type { CREATED = 0, INITED, LOST_PARENT, CONNECTING_PARENT, RUNNING };
        };

        struct flag_t {
            enum type {
                EN_FT_RESETTING,          /** 正在重置 **/
                EN_FT_RESETTING_GC,       /** 正在重置且正准备GC或GC流程已完成 **/
                EN_FT_ACTIVED,            /** 已激活 **/
                EN_FT_PARENT_REG_DONE,    /** 已通过父节点注册 **/
                EN_FT_SHUTDOWN,           /** 已完成关闭前的资源回收 **/
                EN_FT_RECV_SELF_MSG,      /** 正在接收发给自己的信息 **/
                EN_FT_IN_CALLBACK,        /** 在回调函数中 **/
                EN_FT_IN_PROC,            /** 在Proc函数中 **/
                EN_FT_IN_POLL,            /** 在Poll函数中 **/
                EN_FT_IN_GC_ENDPOINTS,    /** 在清理endpoint过程中 **/
                EN_FT_IN_GC_CONNECTIONS,  /** 在清理connection过程中 **/
                EN_FT_MAX,                /** flag max **/
            };
        };

        struct conf_t {
            adapter::loop_t *ev_loop;
            std::vector<endpoint_subnet_conf> subnets;   /** 子网范围 **/
            std::bitset<conf_flag_t::EN_CONF_MAX> flags; /** 开关配置 **/
            std::string parent_address;                  /** 父节点地址 **/
            int loop_times;                              /** 消息循环次数限制，防止某些通道繁忙把其他通道堵死 **/
            int ttl;                                     /** 消息转发跳转限制 **/
            int32_t protocol_version;
            int32_t protocol_minimal_version;

            // ===== 连接配置 =====
            int backlog;
            time_t first_idle_timeout;      /** 第一个包允许的空闲时间，秒 **/
            time_t ping_interval;           /** ping包间隔，秒 **/
            time_t retry_interval;          /** 重试包间隔，秒 **/
            size_t fault_tolerant;          /** 容错次数，次 **/
            size_t access_token_max_number; /** 最大access token数量，请不要设置的太大，验证次数最大可能是N^2 **/
            std::vector<std::vector<unsigned char> > access_tokens; /** access token列表 **/

            // ===== 缓冲区配置 =====
            size_t msg_size;           /** max message size **/
            size_t recv_buffer_size;   /** 接收缓冲区，和数据包大小有关 **/
            size_t send_buffer_size;   /** 发送缓冲区限制 **/
            size_t send_buffer_number; /** 发送缓冲区静态Buffer数量限制，0则为动态缓冲区 **/

            ATBUS_MACRO_API conf_t();
            ATBUS_MACRO_API conf_t(const conf_t& other);
            ATBUS_MACRO_API ~conf_t();
            ATBUS_MACRO_API conf_t& operator=(const conf_t& other);
        };

        typedef std::map<endpoint_subnet_range, endpoint::ptr_t> endpoint_collection_t;

        struct evt_msg_t {
            // 接收消息事件回调 => 参数列表: 发起节点，来源对端，来源连接，消息体，数据地址，数据长度
            typedef std::function<int(const node &, const endpoint *, const connection *, const ::atbus::protocol::msg &, const void *,
                                      size_t)>
                on_recv_msg_fn_t;
            // 发送消息失败事件或成功通知回调 => 参数列表: 发起节点，来源对端，来源连接，消息体
            // @note 除非发送时标记atbus::protocol::FORWARD_DATA_FLAG_REQUIRE_RSP为true(即需要通知)，否则成功发送消息默认不回发通知 
            typedef std::function<int(const node &, const endpoint *, const connection *, const ::atbus::protocol::msg *m)>
                on_forward_response_fn_t;
            // 错误回调 => 参数列表: 发起节点，来源对端，来源连接，状态码（通常来自libuv），错误码
            typedef std::function<int(const node &, const endpoint *, const connection *, int, int)> on_error_fn_t;
            // 新对端注册事件回调 => 参数列表: 发起节点，来源对端，来源连接，返回码（通常来自libuv）
            typedef std::function<int(const node &, const endpoint *, const connection *, int)> on_reg_fn_t;
            // 节点关闭事件回调 => 参数列表: 发起节点，下线原因
            typedef std::function<int(const node &, int)> on_node_down_fn_t;
            // 节点开始服务事件回调 => 参数列表: 发起节点，错误码，通常是 EN_ATBUS_ERR_SUCCESS
            typedef std::function<int(const node &, int)> on_node_up_fn_t;
            // 失效连接事件回调 => 参数列表: 发起节点，来源连接，错误码，通常是 EN_ATBUS_ERR_NODE_TIMEOUT
            typedef std::function<int(const node &, const connection *, int)> on_invalid_connection_fn_t;
            typedef std::function<int(const node &, const connection *)> on_new_connection_fn_t;
            // 接收到命令消息事件回调 => 参数列表:
            //      发起节点，来源对端，来源连接，来源节点ID，命令参数列表，返回信息列表（跨节点的共享内存和内存通道的返回消息将被忽略）
            typedef std::function<int(const node &, const endpoint *, const connection *, bus_id_t,
                                      const std::vector<std::pair<const void *, size_t> > &, std::list<std::string> &)>
                on_custom_cmd_fn_t;
            // 接收到命令回包事件回调 => 参数列表: 发起节点，来源对端，来源连接，来源节点ID，回包数据列表，对应请求包的sequence
            typedef std::function<int(const node &, const endpoint *, const connection *, bus_id_t,
                                      const std::vector<std::pair<const void *, size_t> > &, uint64_t)>
                on_custom_rsp_fn_t;

            // 对端上线事件回调 => 参数列表: 发起节点，新增的对端，错误码，通常是 EN_ATBUS_ERR_SUCCESS
            typedef std::function<int(const node &, endpoint *, int)> on_add_endpoint_fn_t;
            // 对端离线事件回调 => 参数列表: 发起节点，新增的对端，错误码，通常是 EN_ATBUS_ERR_SUCCESS
            typedef std::function<int(const node &, endpoint *, int)> on_remove_endpoint_fn_t;

            on_recv_msg_fn_t on_recv_msg;
            on_forward_response_fn_t on_forward_response;
            on_error_fn_t on_error;
            on_reg_fn_t on_reg;
            on_node_down_fn_t on_node_down;
            on_node_up_fn_t on_node_up;
            on_invalid_connection_fn_t on_invalid_connection;
            on_new_connection_fn_t on_new_connection;
            on_custom_cmd_fn_t on_custom_cmd;
            on_custom_rsp_fn_t on_custom_rsp;
            on_add_endpoint_fn_t on_endpoint_added;
            on_remove_endpoint_fn_t on_endpoint_removed;
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
        ATBUS_MACRO_API int start();

        /**
         * @brief 数据重置（释放资源）
         * @return 0或错误码
         */
        ATBUS_MACRO_API int reset();

        /**
         * @brief 执行一帧
         * @param sec 当前时间-秒
         * @param sec 当前时间-微秒
         * @return 本帧处理的消息数
         */
        ATBUS_MACRO_API int proc(time_t sec, time_t usec);

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
        ATBUS_MACRO_API int listen(const char *addr);

        /**
         * @brief 连接到目标地址
         * @param addr 连接目标地址
         * @return 0或错误码
         */
        ATBUS_MACRO_API int connect(const char *addr);

        /**
         * @brief 连接到目标地址
         * @param addr 连接目标地址
         * @param ep 连接目标的端点
         * @return 0或错误码
         */
        ATBUS_MACRO_API int connect(const char *addr, endpoint *ep);

        /**
         * @brief 断开到目标的连接
         * @param id 目标ID
         * @return 0或错误码
         */
        ATBUS_MACRO_API int disconnect(bus_id_t id);


        /**
         * @brief 发送数据
         * @param tid 发送目标ID
         * @param type 自定义类型，将作为msg.head.type字段传递。可用于业务区分服务类型
         * @param buffer 数据块地址
         * @param s 数据块长度
         * @param require_rsp 是否强制需要回包（默认情况下如果发送成功是没有回包通知的）
         * @return 0或错误码
         * @note 接收端收到的数据很可能不是地址对齐的，所以这里不建议发送内存数据
         *       如果非要发送内存数据的话，一定要memcpy，不能直接类型转换，除非手动设置了地址对齐规则
         */
        ATBUS_MACRO_API int send_data(bus_id_t tid, int type, const void *buffer, size_t s, bool require_rsp = false);

        /**
         * @brief 发送自定义命令消息
         * @param tid 发送目标ID
         * @param arr_buf 自定义消息内容数组
         * @param arr_size 自定义消息内容长度
         * @param arr_count 自定义消息数组个数
         * @param seq 返回本次自定义消息的发送序号
         * @return 0或错误码
         */
        ATBUS_MACRO_API int send_custom_cmd(bus_id_t tid, const void *arr_buf[], size_t arr_size[], size_t arr_count, uint64_t *seq = NULL);

        /**
         * @brief 获取远程发送目标信息
         * @param tid 发送目标ID，不能是自己的的BUS ID
         * @param fn 获取有效连接的接口，用以区分数据通道和控制通道
         * @param ep_out 如果发送成功，导出发送目标，否则导出NULL
         * @param conn_out 如果发送成功，导出发送连接，否则导出NULL
         * @return 0或错误码
         */
        ATBUS_MACRO_API int get_remote_channel(bus_id_t tid, endpoint::get_connection_fn_t fn, endpoint **ep_out, connection **conn_out);

        /**
         * @brief 根据对端ID查找直链的端点
         * @param tid 目标端点ID
         * @return 直连的端点，不存在则返回NULL
         */
        ATBUS_MACRO_API endpoint *get_endpoint(bus_id_t tid);
        ATBUS_MACRO_API const endpoint *get_endpoint(bus_id_t tid) const;

        /**
         * @brief 添加目标端点
         * @param ep 目标端点
         * @return 0或错误码
         */
        ATBUS_MACRO_API int add_endpoint(endpoint::ptr_t ep);

        /**
         * @brief 移除目标端点
         * @param tid 目标端点ID
         * @return 0或错误码
         */
        ATBUS_MACRO_API int remove_endpoint(bus_id_t tid);

        /**
         * @brief 是否有到对端的数据通道(可以向对端发送数据)
         * @note 如果只有控制通道没有数据通道返回false
         * @param tid 目标端点ID
         * @return 有则返回true
         */
        ATBUS_MACRO_API bool is_endpoint_available(bus_id_t tid) const;

        /**
         * @brief 生成用于access token验证的hash值
         * @param idx 第几个accesstoken
         * @param salt 生成的随机盐
         * @param hashval1 生成的hash值1
         * @param hashval2 生成的hash值2
         * @return idx无效返回false
         */
        ATBUS_MACRO_API bool generate_access_hash(size_t idx, uint32_t &salt, uint64_t &hashval1, uint64_t &hashval2);

        /**
         * @brief 检查access token的有效性
         * @param salt 盐
         * @param hashval1 hash值1
         * @param hashval2 hash值2
         * @return 没有检查通过的access token则返回false
         */
        ATBUS_MACRO_API bool check_access_hash(const uint32_t salt, const uint64_t hashval1, const uint64_t hashval2) const;

    public:
        ATBUS_MACRO_API channel::io_stream_channel *get_iostream_channel();

        ATBUS_MACRO_API const endpoint *get_self_endpoint() const;

        ATBUS_MACRO_API const endpoint *get_parent_endpoint() const;

        ATBUS_MACRO_API const endpoint_collection_t &get_routes() const;

        /**
         * @brief 获取关联的事件管理器,如果未设置则会初始化为默认时间管理器
         * @return 关联的事件管理器
         */
        ATBUS_MACRO_API adapter::loop_t *get_evloop();

    private:
        int remove_endpoint(bus_id_t tid, endpoint* expected);
        
        /**
         * @brief 发送数据消息
         * @param tid 发送目标ID
         * @param msg_builder 消息构建器
         * @return 0或错误码
         */
        int send_data_msg(bus_id_t tid, msg_builder_ref_t mb);

        /**
         * @brief 发送数据消息
         * @param tid 发送目标ID
         * @param msg_builder 消息构建器
         * @param ep_out 如果发送成功，导出发送目标
         * @param conn_out 如果发送成功，导出发送连接
         * @return 0或错误码
         */
        int send_data_msg(bus_id_t tid, msg_builder_ref_t mb, endpoint **ep_out, connection **conn_out);

        /**
         * @brief 发送控制消息
         * @param tid 发送目标ID
         * @param msg_builder 消息构建器
         * @return 0或错误码
         */
        int send_ctrl_msg(bus_id_t tid, msg_builder_ref_t mb);

        /**
         * @brief 发送控制消息
         * @param tid 发送目标ID
         * @param msg_builder 消息构建器
         * @param ep_out 如果发送成功，导出发送目标
         * @param conn_out 如果发送成功，导出发送连接
         * @return 0或错误码
         */
        int send_ctrl_msg(bus_id_t tid, msg_builder_ref_t mb, endpoint **ep_out, connection **conn_out);

        /**
         * @brief 发送消息
         * @param tid 发送目标ID
         * @param msg_builder 消息构建器
         * @param fn 获取有效连接的接口，用以区分数据通道和控制通道
         * @param ep_out 如果发送成功，导出发送目标
         * @param conn_out 如果发送成功，导出发送连接
         * @return 0或错误码
         */
        int send_msg(bus_id_t tid, msg_builder_ref_t msg_builder, endpoint::get_connection_fn_t fn, endpoint **ep_out,
                     connection **conn_out);

        channel::io_stream_conf *get_iostream_conf();

    public:
        ATBUS_MACRO_API bus_id_t get_id() const;
        ATBUS_MACRO_API const conf_t &get_conf() const;

        ATBUS_MACRO_API bool check_flag(flag_t::type f) const;
        ATBUS_MACRO_API state_t::type get_state() const;

        ATBUS_MACRO_API ptr_t get_watcher();

        ATBUS_MACRO_API bool is_child_node(bus_id_t id) const;
        ATBUS_MACRO_API bool is_parent_node(bus_id_t id) const;

        static ATBUS_MACRO_API int get_pid();
        static ATBUS_MACRO_API const std::string &get_hostname();
        /**
         * @brief 设置hostname，用于再查找路由路径时区分是否同物理机，不设置的话默认会自动检测本机地址生成一个
         * @param hn 本机物理机名称，全局共享。仅会影响这之后创建的node
         * @param force 是否强制设置，一般情况下已经有node使用过物理地址的情况下不允许设置
         * @return 成功返回true
         */
        static ATBUS_MACRO_API bool set_hostname(const std::string &hn, bool force = false);

        ATBUS_MACRO_API int32_t get_protocol_version() const;

        ATBUS_MACRO_API int32_t get_protocol_minimal_version() const;

        ATBUS_MACRO_API const std::list<std::string> &get_listen_list() const;

        ATBUS_MACRO_API bool add_proc_connection(connection::ptr_t conn);
        ATBUS_MACRO_API bool remove_proc_connection(const std::string &conn_key);

        ATBUS_MACRO_API bool add_connection_timer(connection::ptr_t conn, timer_desc_ls<connection::ptr_t>::type::iterator& out);

        ATBUS_MACRO_API bool remove_connection_timer(timer_desc_ls<connection::ptr_t>::type::iterator& out);

        ATBUS_MACRO_API size_t get_connection_timer_size() const;

        ATBUS_MACRO_API time_t get_timer_sec() const;

        ATBUS_MACRO_API time_t get_timer_usec() const;

        ATBUS_MACRO_API void on_recv(connection *conn, ::atbus::protocol::msg ATBUS_MACRO_RVALUE_REFERENCES m, int status, int errcode);

        ATBUS_MACRO_API void on_recv_data(const endpoint *ep, connection *conn, const ::atbus::protocol::msg &m, const void *buffer, size_t s) const;

        ATBUS_MACRO_API void on_recv_forward_response(const endpoint *, const connection *, const ::atbus::protocol::msg *m);

        ATBUS_MACRO_API int on_error(const char *file_path, size_t line, const endpoint *, const connection *, int, int);
        ATBUS_MACRO_API int on_disconnect(const connection *);
        ATBUS_MACRO_API int on_new_connection(connection *);
        ATBUS_MACRO_API int on_shutdown(int reason);
        ATBUS_MACRO_API int on_reg(const endpoint *, const connection *, int);
        ATBUS_MACRO_API int on_actived();
        ATBUS_MACRO_API int on_parent_reg_done();
        ATBUS_MACRO_API int on_custom_cmd(const endpoint *, const connection *, bus_id_t from,
                          const std::vector<std::pair<const void *, size_t> > &cmd_args, std::list<std::string> &rsp);
        ATBUS_MACRO_API int on_custom_rsp(const endpoint *, const connection *, bus_id_t from,
                          const std::vector<std::pair<const void *, size_t> > &cmd_args, uint64_t seq);

        /**
         * @brief 关闭node
         * @param reason 关闭原因ID
         * @note 如果需要在关闭前执行资源回收，可以在on_node_down_fn_t回调中返回非0值来阻止node的reset操作，
         *       并在资源释放完成后再调用shutdown函数，在第二次on_node_down_fn_t回调中返回0值
         *
         * @note 或者也可以通过ref_object和unref_object来标记和解除数据引用，reset函数会执行事件loop知道所有引用的资源被移除
         */
        ATBUS_MACRO_API int shutdown(int reason);


        /** do not use this directly **/
        ATBUS_MACRO_API int fatal_shutdown(const char *file_path, size_t line, const endpoint *, const connection *, int status, int errcode);

        /** dispatch all self messages **/
        ATBUS_MACRO_API int dispatch_all_self_msgs();

        ATBUS_MACRO_API const detail::buffer_block *get_temp_static_buffer() const;
        ATBUS_MACRO_API detail::buffer_block *get_temp_static_buffer();

        ATBUS_MACRO_API int ping_endpoint(endpoint &ep);

#if 0 // disabled
        ATBUS_MACRO_API int push_node_sync();

        ATBUS_MACRO_API int pull_node_sync();
#endif

        ATBUS_MACRO_API uint64_t alloc_msg_seq();

        ATBUS_MACRO_API void add_endpoint_gc_list(const endpoint::ptr_t &ep);

        ATBUS_MACRO_API void add_connection_gc_list(const connection::ptr_t &conn);

        ATBUS_MACRO_API void set_on_recv_handle(evt_msg_t::on_recv_msg_fn_t fn);
        ATBUS_MACRO_API const evt_msg_t::on_recv_msg_fn_t &get_on_recv_handle() const;

        ATBUS_MACRO_API void set_on_receive_handle(evt_msg_t::on_recv_msg_fn_t fn);
        ATBUS_MACRO_API const evt_msg_t::on_recv_msg_fn_t &get_on_receive_handle() const;

        ATBUS_MACRO_API void set_on_forward_response_handle(evt_msg_t::on_forward_response_fn_t fn);
        ATBUS_MACRO_API const evt_msg_t::on_forward_response_fn_t &get_on_forward_response_handle() const;

        ATBUS_MACRO_API void set_on_error_handle(evt_msg_t::on_error_fn_t fn);
        ATBUS_MACRO_API const evt_msg_t::on_error_fn_t &get_on_error_handle() const;

        ATBUS_MACRO_API void set_on_register_handle(evt_msg_t::on_reg_fn_t fn);
        ATBUS_MACRO_API const evt_msg_t::on_reg_fn_t &get_on_register_handle() const;

        ATBUS_MACRO_API void set_on_shutdown_handle(evt_msg_t::on_node_down_fn_t fn);
        ATBUS_MACRO_API const evt_msg_t::on_node_down_fn_t &get_on_shutdown_handle() const;

        ATBUS_MACRO_API void set_on_available_handle(evt_msg_t::on_node_up_fn_t fn);
        ATBUS_MACRO_API const evt_msg_t::on_node_up_fn_t &get_on_available_handle() const;

        ATBUS_MACRO_API void set_on_invalid_connection_handle(evt_msg_t::on_invalid_connection_fn_t fn);
        ATBUS_MACRO_API const evt_msg_t::on_invalid_connection_fn_t &get_on_invalid_connection_handle() const;

        ATBUS_MACRO_API void set_on_new_connection_handle(evt_msg_t::on_new_connection_fn_t fn);
        ATBUS_MACRO_API const evt_msg_t::on_new_connection_fn_t &get_on_new_connection_handle() const;

        ATBUS_MACRO_API void set_on_custom_cmd_handle(evt_msg_t::on_custom_cmd_fn_t fn);
        ATBUS_MACRO_API const evt_msg_t::on_custom_cmd_fn_t &get_on_custom_cmd_handle() const;

        ATBUS_MACRO_API void set_on_custom_rsp_handle(evt_msg_t::on_custom_rsp_fn_t fn);
        ATBUS_MACRO_API const evt_msg_t::on_custom_rsp_fn_t &get_on_custom_rsp_handle() const;

        ATBUS_MACRO_API void set_on_add_endpoint_handle(evt_msg_t::on_add_endpoint_fn_t fn);
        ATBUS_MACRO_API const evt_msg_t::on_add_endpoint_fn_t &get_on_add_endpoint_handle() const;

        ATBUS_MACRO_API void set_on_remove_endpoint_handle(evt_msg_t::on_remove_endpoint_fn_t fn);
        ATBUS_MACRO_API const evt_msg_t::on_remove_endpoint_fn_t &get_on_remove_endpoint_handle() const;

        // inner API, please don't use it if you don't known what will happen
        ATBUS_MACRO_API void ref_object(void *);
        // inner API, please don't use it if you don't known what will happen
        ATBUS_MACRO_API void unref_object(void *);

        static ATBUS_MACRO_API bool check_conflict(endpoint_collection_t &coll, const endpoint_subnet_range& conf);
        static ATBUS_MACRO_API bool check_conflict(endpoint_collection_t &coll, const std::vector<endpoint_subnet_range>& confs);
    private:
        static endpoint *find_route(endpoint_collection_t &coll, bus_id_t id);

        bool insert_child(endpoint_collection_t &coll, endpoint::ptr_t ep);

        bool remove_child(endpoint_collection_t &coll, bus_id_t id, endpoint* expected = NULL);

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
         * @brief 添加到ping列表
         */
        void add_ping_timer(endpoint::ptr_t &ep);

    public:
        ATBUS_MACRO_API void stat_add_dispatch_times();

    private:
        // ============ 基础信息 ============
        // ID
        endpoint::ptr_t self_;
        state_t::type state_;
        std::bitset<flag_t::EN_FT_MAX> flags_;

        // 配置
        conf_t conf_;
        std::weak_ptr<node> watcher_; // just like std::shared_from_this<T>
        util::lock::seq_alloc_u64 msg_seq_alloc_;

        // 引用的资源标记（释放时要保证这些资源引用被移除）
        std::set<void *> ref_objs_;

        // ============ IO事件数据 ============
        // 事件分发器
        adapter::loop_t *ev_loop_;
        std::unique_ptr<channel::io_stream_channel, io_stream_channel_del> iostream_channel_;
        std::unique_ptr<channel::io_stream_conf> iostream_conf_;
        evt_msg_t event_msg_;
        typedef std::list<std::vector<unsigned char> > self_data_msgs_t;
        typedef std::list<std::vector<unsigned char> > self_cmd_msgs_t;
        self_data_msgs_t self_data_msgs_;
        self_cmd_msgs_t self_cmd_msgs_;

        // ============ 定时器 ============
        typedef struct {
            time_t sec;
            time_t usec;

            time_t node_sync_push;                                   // 节点变更推送
            time_t parent_opr_time_point;                            // 父节点操作时间（断线重连或Ping）
            timer_desc_ls<std::weak_ptr<endpoint> >::type ping_list; // 定时ping
            timer_desc_ls<connection::ptr_t>::type connecting_list;  // 未完成连接（正在网络连接或握手）
            std::list<endpoint::ptr_t> pending_endpoint_gc_list;     // 待检测GC的endpoint列表
            std::list<connection::ptr_t> pending_connection_gc_list; // 待检测GC的connection列表
        } evt_timer_t;
        evt_timer_t event_timer_;

        // 轮训接收通道集
        detail::buffer_block *static_buffer_;
        detail::auto_select_map<std::string, connection::ptr_t>::type proc_connections_;

        // 基于事件的通道信息
        // 基于事件的通道超时收集

        // ============ 节点逻辑关系数据 ============
        // 父节点
        struct parent_info_t {
            endpoint::ptr_t node_;
        };
        parent_info_t node_parent_; // 父节点（默认路由，自动重连）

        // 路由节点
        endpoint_collection_t node_routes_;

        // 统计信息
        struct stat_info_t {
            size_t dispatch_times;

            stat_info_t();
        };
        stat_info_t stat_;
        ::util::random::xoshiro256_starstar random_engine_;

        // 调试辅助函数
    public:
        void (*on_debug)(const char *file_path, size_t line, const node &, const endpoint *, const connection *,
                         const ::atbus::protocol::msg *, const char *fmt, ...);
        friend struct msg_handler;
    };
} // namespace atbus


#define ATBUS_FUNC_NODE_ERROR(n, ep, conn, status, errorcode) (n).on_error(__FILE__, __LINE__, (ep), (conn), (status), (errorcode))
#define ATBUS_FUNC_NODE_FATAL_SHUTDOWN(n, ep, conn, status, errorcode) \
    (n).fatal_shutdown(__FILE__, __LINE__, (ep), (conn), (status), (errorcode))

#ifdef _MSC_VER
#define ATBUS_FUNC_NODE_DEBUG(n, ep, conn, m, fmt, ...)                             \
    if ((n).on_debug) {                                                             \
        (n).on_debug(__FILE__, __LINE__, (n), (ep), (conn), (m), fmt, __VA_ARGS__); \
    }
#else
#define ATBUS_FUNC_NODE_DEBUG(n, ep, conn, m, fmt, args...)                    \
    if ((n).on_debug) {                                                        \
        (n).on_debug(__FILE__, __LINE__, (n), (ep), (conn), (m), fmt, ##args); \
    }
#endif


#endif /* LIBATBUS_NODE_H_ */
