/**
 * atbus_endpoint.h
 *
 *  Created on: 2015年11月20日
 *      Author: owent
 */

#pragma once

#ifndef LIBATBUS_ENDPOINT_H
#define LIBATBUS_ENDPOINT_H

#pragma once

#include <list>

#ifdef _MSC_VER
#include <WinSock2.h>
#endif

#include "std/smart_ptr.h"

#include "design_pattern/noncopyable.h"

#include "detail/libatbus_channel_export.h"
#include "detail/libatbus_config.h"
#include "detail/libatbus_error.h"

#include "atbus_connection.h"

namespace atbus {
    namespace detail {
        template <typename TKey, typename TVal>
        struct auto_select_map {
            typedef ATBUS_ADVANCE_TYPE_MAP(TKey, TVal) type;
        };

        template <typename TVal>
        struct auto_select_set {
            typedef ATBUS_ADVANCE_TYPE_SET(TVal) type;
        };
    } // namespace detail

    class node;

    class endpoint UTIL_CONFIG_FINAL : public util::design_pattern::noncopyable {
    public:
        typedef ATBUS_MACRO_BUSID_TYPE bus_id_t;
        typedef std::shared_ptr<endpoint> ptr_t;

        typedef struct {
            enum type {
                RESETTING, /** 正在执行重置（防止递归死循环） **/
                CONNECTION_SORTED,
                DESTRUCTING,     /** 正在执行析构 **/
                HAS_LISTEN_PORC, /** 是否有proc类的listen地址 **/
                HAS_LISTEN_FD,   /** 是否有fd类的listen地址 **/

                MUTABLE_FLAGS,
                MAX
            };
        } flag_t;

        typedef connection *(endpoint::*get_connection_fn_t)(endpoint *ep) const;

    private:
        endpoint();

    public:
        /**
         * @brief 创建端点
         */
        static ptr_t create(node *owner, bus_id_t id, uint32_t children_mask, int32_t pid, const std::string &hn);
        ~endpoint();

        void reset();

        inline bus_id_t get_id() const { return id_; }
        inline bus_id_t get_children_prefix() const { return get_id(); }
        inline uint32_t get_children_mask() const { return children_mask_; }

        inline int32_t get_pid() const { return pid_; };
        inline const std::string &get_hostname() const { return hostname_; };


        bool is_child_node(bus_id_t id) const;
        bool is_brother_node(bus_id_t id, uint32_t parent_mask) const;
        static bool is_parent_node(bus_id_t id, bus_id_t parent_id, uint32_t parent_mask);
        static bus_id_t get_children_min_id(bus_id_t children_prefix, uint32_t mask);
        static bus_id_t get_children_max_id(bus_id_t children_prefix, uint32_t mask);
        static bool is_child_node(bus_id_t parent_id, bus_id_t parent_children_prefix, uint32_t parent_mask, bus_id_t checked_id);

        bool add_connection(connection *conn, bool force_data);

        bool remove_connection(connection *conn);

        /**
         * @brief 是否处于可用状态
         * @note 可用状态是指同时存在正在运行的命令通道和数据通道
         */
        bool is_available() const;

        /**
         * @brief 获取flag
         * @param f flag的key
         * @return 返回f的值，如果f无效，返回false
         */
        bool get_flag(flag_t::type f) const;

        /**
         * @brief 设置可变flag的值
         * @param f flag的key，这个值必须大于等于flat_t::MUTABLE_FLAGS
         * @param v 值
         * @return 0或错误码
         * @see flat_t
         */
        int set_flag(flag_t::type f, bool v);

        /**
         * @brief 获取所有flag
         * @return 整数表示的flags
         * @see flat_t
         */
        uint32_t get_flags() const;

        /**
         * @breif 获取自身的资源holder
         */
        ptr_t watch() const;

        inline const std::list<std::string> &get_listen() const { return listen_address_; }
        void add_listen(const std::string &addr);

    private:
        static bool sort_connection_cmp_fn(const connection::ptr_t &left, const connection::ptr_t &right);

    public:
        connection *get_ctrl_connection(endpoint *ep) const;

        connection *get_data_connection(endpoint *ep) const;
        connection *get_data_connection(endpoint *ep, bool enable_fallback_ctrl) const;

        /** 增加错误计数 **/
        size_t add_stat_fault();

        /** 清空错误计数 **/
        void clear_stat_fault();

        void set_stat_ping(uint32_t p);

        uint32_t get_stat_ping() const;

        void set_stat_ping_delay(time_t pd, time_t pong_tm);

        time_t get_stat_ping_delay() const;

        time_t get_stat_last_pong() const;

        size_t get_stat_push_start_times() const;
        size_t get_stat_push_start_size() const;
        size_t get_stat_push_success_times() const;
        size_t get_stat_push_success_size() const;
        size_t get_stat_push_failed_times() const;
        size_t get_stat_push_failed_size() const;
        size_t get_stat_pull_times() const;
        size_t get_stat_pull_size() const;

        inline const node *get_owner() const { return owner_; }

    private:
        bus_id_t id_;
        uint32_t children_mask_;
        std::bitset<flag_t::MAX> flags_;
        std::string hostname_;
        int32_t pid_;

        // 这里不用智能指针是为了该值在上层对象（node）析构时仍然可用
        node *owner_;
        std::weak_ptr<endpoint> watcher_;

        std::list<std::string> listen_address_;
        connection::ptr_t ctrl_conn_;
        std::list<connection::ptr_t> data_conn_;

        // 统计数据
        struct stat_t {
            size_t fault_count;       // 错误容忍计数
            uint32_t unfinished_ping; // 上一次未完成的ping的序号
            time_t ping_delay;
            time_t last_pong_time; // 上一次接到PONG包时间
            stat_t();
        };
        stat_t stat_;
    };
} // namespace atbus

#endif /* LIBATBUS_ENDPOINT_H_ */
