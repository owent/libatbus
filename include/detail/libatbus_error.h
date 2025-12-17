#ifndef LIBATBUS_DETAIL_LIBATBUS_ERROR_H
#define LIBATBUS_DETAIL_LIBATBUS_ERROR_H

#pragma once

#include <string/string_format.h>

#include <string>

#include "detail/libatbus_config.h"

enum ATBUS_ERROR_TYPE {
  EN_ATBUS_ERR_SUCCESS = 0,

  EN_ATBUS_ERR_PARAMS = -1,
  EN_ATBUS_ERR_INNER = -2,
  EN_ATBUS_ERR_NO_DATA = -3,                  // 无数据
  EN_ATBUS_ERR_BUFF_LIMIT = -4,               // 缓冲区不足
  EN_ATBUS_ERR_MALLOC = -5,                   // 分配失败
  EN_ATBUS_ERR_SCHEME = -6,                   // 协议错误
  EN_ATBUS_ERR_BAD_DATA = -7,                 // 数据校验不通过
  EN_ATBUS_ERR_INVALID_SIZE = -8,             // 数据大小异常
  EN_ATBUS_ERR_NOT_INITED = -9,               // 未初始化
  EN_ATBUS_ERR_ALREADY_INITED = -10,          // 已填充初始数据
  EN_ATBUS_ERR_ACCESS_DENY = -11,             // 不允许的操作
  EN_ATBUS_ERR_UNPACK = -12,                  // 解包失败
  EN_ATBUS_ERR_PACK = -13,                    // 打包失败
  EN_ATBUS_ERR_UNSUPPORTED_VERSION = -14,     // 版本不受支持
  EN_ATBUS_ERR_CLOSING = -15,                 // 正在关闭或已关闭
  EN_ATBUS_ERR_ALGORITHM_NOT_SUPPORT = -16,   // 算法不受支持
  EN_ATBUS_ERR_MESSAGE_NOT_FINISH_YET = -17,  // 消息尚未调用finish

  EN_ATBUS_ERR_ATNODE_NOT_FOUND = -65,         // 查找不到目标节点
  EN_ATBUS_ERR_ATNODE_INVALID_ID = -66,        // 不可用的ID
  EN_ATBUS_ERR_ATNODE_NO_CONNECTION = -67,     // 无可用连接
  EN_ATBUS_ERR_ATNODE_FAULT_TOLERANT = -68,    // 超出容错值
  EN_ATBUS_ERR_ATNODE_INVALID_MSG = -69,       // 错误的消息
  EN_ATBUS_ERR_ATNODE_BUS_ID_NOT_MATCH = -70,  // Bus ID不匹配
  EN_ATBUS_ERR_ATNODE_TTL = -71,               // ttl限制
  EN_ATBUS_ERR_ATNODE_MASK_CONFLICT = -72,     // 域范围错误或冲突
  EN_ATBUS_ERR_ATNODE_ID_CONFLICT = -73,       // ID冲突
  EN_ATBUS_ERR_ATNODE_SRC_DST_IS_SAME = -75,   // 发送源和发送目标不能相同

  EN_ATBUS_ERR_CHANNEL_SIZE_TOO_SMALL = -101,
  EN_ATBUS_ERR_CHANNEL_BUFFER_INVALID = -102,        // 缓冲区错误（已被其他模块使用或检测冲突）
  EN_ATBUS_ERR_CHANNEL_ADDR_INVALID = -103,          // 地址错误
  EN_ATBUS_ERR_CHANNEL_CLOSING = -104,               // 正在关闭
  EN_ATBUS_ERR_CHANNEL_NOT_SUPPORT = -105,           // 不支持的通道
  EN_ATBUS_ERR_CHANNEL_UNSUPPORTED_VERSION = -106,   // 通道版本不受支持
  EN_ATBUS_ERR_CHANNEL_ALIGN_SIZE_MISMATCH = -107,   // 对齐参数不一致
  EN_ATBUS_ERR_CHANNEL_ARCH_SIZE_T_MISMATCH = -108,  // 架构size_t不匹配

  EN_ATBUS_ERR_NODE_BAD_BLOCK_NODE_NUM = -202,   // 发现写坏的数据块 - 节点数量错误
  EN_ATBUS_ERR_NODE_BAD_BLOCK_BUFF_SIZE = -203,  // 发现写坏的数据块 - 节点数量错误
  EN_ATBUS_ERR_NODE_BAD_BLOCK_WSEQ_ID = -204,    // 发现写坏的数据块 - 写操作序列错误
  EN_ATBUS_ERR_NODE_BAD_BLOCK_CSEQ_ID = -205,    // 发现写坏的数据块 - 检查操作序列错误

  EN_ATBUS_ERR_NODE_TIMEOUT = -211,  // 操作超时

  EN_ATBUS_ERR_SHM_GET_FAILED = -301,    // 连接共享内存出错，具体错误原因可以查看errno或类似的位置
  EN_ATBUS_ERR_SHM_NOT_FOUND = -302,     // 共享内存未找到
  EN_ATBUS_ERR_SHM_CLOSE_FAILED = -303,  // 移除共享内存出错，具体错误原因可以查看errno或类似的位置
  EN_ATBUS_ERR_SHM_PATH_INVALID = -304,  // 共享内存地址错误
  EN_ATBUS_ERR_SHM_MAP_FAILED = -305,    // 共享内存地址映射错误

  EN_ATBUS_ERR_SOCK_BIND_FAILED = -401,     // 绑定地址或端口失败
  EN_ATBUS_ERR_SOCK_LISTEN_FAILED = -402,   // 监听失败
  EN_ATBUS_ERR_SOCK_CONNECT_FAILED = -403,  // 连接失败

  EN_ATBUS_ERR_PIPE_BIND_FAILED = -501,       // 绑定地址或端口失败
  EN_ATBUS_ERR_PIPE_LISTEN_FAILED = -502,     // 监听失败
  EN_ATBUS_ERR_PIPE_CONNECT_FAILED = -503,    // 连接失败
  EN_ATBUS_ERR_PIPE_ADDR_TOO_LONG = -504,     // 地址路径过长，绝对路径长度要小于 sizeof(sockaddr_un.sun_path) - 1
  EN_ATBUS_ERR_PIPE_REMOVE_FAILED = -505,     // 删除老socket失败
  EN_ATBUS_ERR_PIPE_PATH_EXISTS = -506,       // 该地址已被占用
  EN_ATBUS_ERR_PIPE_LOCK_PATH_FAILED = -507,  // 锁地址失败

  EN_ATBUS_ERR_DNS_GETADDR_FAILED = -601,    // DNS解析失败
  EN_ATBUS_ERR_CONNECTION_NOT_FOUND = -602,  // 找不到连接
  EN_ATBUS_ERR_WRITE_FAILED = -603,          // 底层API写失败
  EN_ATBUS_ERR_READ_FAILED = -604,           // 底层API读失败
  EN_ATBUS_ERR_EV_RUN = -605,                // 底层API事件循环失败
  EN_ATBUS_ERR_NO_LISTEN = -606,             // 尚未监听（绑定）
  EN_ATBUS_ERR_NOT_READY = -607,             // 未准备好（没有握手完成）

  EN_ATBUS_ERR_MIN = -999,
};

template <class CharT>
struct libatbus_strerror_helper;

ATBUS_MACRO_API const std::basic_string<char> &libatbus_strerror(ATBUS_ERROR_TYPE errcode) noexcept;
template <>
struct libatbus_strerror_helper<char> {
  ATFW_UTIL_FORCEINLINE static const std::basic_string<char> &get(ATBUS_ERROR_TYPE errcode) noexcept {
    return libatbus_strerror(errcode);
  }
};

ATBUS_MACRO_API const std::basic_string<wchar_t> &libatbus_wstrerror(ATBUS_ERROR_TYPE errcode) noexcept;
template <>
struct libatbus_strerror_helper<wchar_t> {
  ATFW_UTIL_FORCEINLINE static const std::basic_string<wchar_t> &get(ATBUS_ERROR_TYPE errcode) noexcept {
    return libatbus_wstrerror(errcode);
  }
};

#ifdef __cpp_unicode_characters
ATBUS_MACRO_API const std::basic_string<char16_t> &libatbus_u16strerror(ATBUS_ERROR_TYPE errcode) noexcept;
template <>
struct libatbus_strerror_helper<char16_t> {
  ATFW_UTIL_FORCEINLINE static const std::basic_string<char16_t> &get(ATBUS_ERROR_TYPE errcode) noexcept {
    return libatbus_u16strerror(errcode);
  }
};
ATBUS_MACRO_API const std::basic_string<char32_t> &libatbus_u32strerror(ATBUS_ERROR_TYPE errcode) noexcept;
template <>
struct libatbus_strerror_helper<char32_t> {
  ATFW_UTIL_FORCEINLINE static const std::basic_string<char32_t> &get(ATBUS_ERROR_TYPE errcode) noexcept {
    return libatbus_u32strerror(errcode);
  }
};
#endif
#ifdef __cpp_char8_t
ATBUS_MACRO_API const std::basic_string<char8_t> &libatbus_u8strerror(ATBUS_ERROR_TYPE errcode) noexcept;
template <>
struct libatbus_strerror_helper<char8_t> {
  ATFW_UTIL_FORCEINLINE static const std::basic_string<char8_t> &get(ATBUS_ERROR_TYPE errcode) noexcept {
    return libatbus_u8strerror(errcode);
  }
};
#endif

ATFRAMEWORK_UTILS_STRING_FWAPI_NAMESPACE_BEGIN
template <class CharT>
struct ATFW_UTIL_SYMBOL_VISIBLE formatter<::ATBUS_ERROR_TYPE, CharT>
    : formatter<ATFRAMEWORK_UTILS_STRING_FWAPI_NAMESPACE_ID::basic_string_view<CharT>, CharT> {
  template <class FormatContext>
  auto format(ATBUS_ERROR_TYPE const &val, FormatContext &ctx) const -> decltype(ctx.out()) {
    return formatter<ATFRAMEWORK_UTILS_STRING_FWAPI_NAMESPACE_ID::basic_string_view<CharT>, CharT>::format(
        ATFRAMEWORK_UTILS_STRING_FWAPI_NAMESPACE_ID::basic_string_view<CharT>{
            libatbus_strerror_helper<CharT>::get(val)},
        ctx);
  }
};
ATFRAMEWORK_UTILS_STRING_FWAPI_NAMESPACE_END

#endif
