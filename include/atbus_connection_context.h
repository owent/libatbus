// Copyright 2026 atframework

#pragma once

#include <design_pattern/nomovable.h>
#include <design_pattern/noncopyable.h>
#include <gsl/select-gsl.h>
#include <memory/rc_ptr.h>

#include <design_pattern/result_type.h>

#include <algorithm/crypto_cipher.h>
#include <algorithm/crypto_dh.h>
#include <random/random_generator.h>

#include <vector>

#include "detail/buffer.h"
#include "detail/libatbus_config.h"
#include "detail/libatbus_error.h"
#include "libatbus_protocol.h"  // NOLINT: build/include_subdir

ATBUS_MACRO_NAMESPACE_BEGIN

using random_engine_t = atfw::util::random::xoshiro256_starstar;

class ATFW_UTIL_SYMBOL_VISIBLE connection_context final {
  UTIL_DESIGN_PATTERN_NOCOPYABLE(connection_context)
  UTIL_DESIGN_PATTERN_NOMOVABLE(connection_context)

 public:
  using ptr_t = atfw::util::memory::strong_rc_ptr<connection_context>;
  using buffer_result_t = ::atfw::util::design_pattern::result_type<static_buffer_block, ATBUS_ERROR_TYPE>;

 private:
  struct ctor_guard_type {};

 public:
  ATBUS_MACRO_API connection_context(ctor_guard_type &,
                                     protocol::ATBUS_CRYPTO_KEY_EXCHANGE_TYPE crypto_key_exchange_algorithm,
                                     ::atfw::util::crypto::dh::shared_context::ptr_t shared_dh_context);
  ATBUS_MACRO_API ~connection_context();

  static ATBUS_MACRO_API ptr_t create(protocol::ATBUS_CRYPTO_KEY_EXCHANGE_TYPE crypto_key_exchange_algorithm,
                                      ::atfw::util::crypto::dh::shared_context::ptr_t shared_dh_context);

  ATBUS_MACRO_API buffer_result_t pack_message(message &m, int32_t protocol_version, random_engine_t &random_engine,
                                               size_t max_body_size) noexcept;

  ATBUS_MACRO_API ATBUS_ERROR_TYPE unpack_message(message &m, gsl::span<const unsigned char> input,
                                                  size_t max_body_size) noexcept;

  ATBUS_MACRO_API std::chrono::system_clock::time_point get_handshake_start_time() const noexcept;
  ATBUS_MACRO_API protocol::ATBUS_CRYPTO_KEY_EXCHANGE_TYPE get_crypto_key_exchange_algorithm() const noexcept;
  ATBUS_MACRO_API protocol::ATBUS_CRYPTO_KDF_TYPE get_crypto_select_kdf_type() const noexcept;
  ATBUS_MACRO_API protocol::ATBUS_CRYPTO_ALGORITHM_TYPE get_crypto_select_algorithm() const noexcept;
  ATBUS_MACRO_API protocol::ATBUS_COMPRESSION_ALGORITHM_TYPE get_compression_select_algorithm() const noexcept;

  /**
   * @brief 生成加密握手密钥对
   * @param peer_sequence_id 对端握手序列号,如果是Client模式，这里传0表示自己生产
   * @return int 0或错误码
   */
  ATBUS_MACRO_API ATBUS_ERROR_TYPE handshake_generate_self_key(uint64_t peer_sequence_id);

  /**
   * @brief 读取对端公钥并计算共享密钥
   * @param peer_pub_key 对端公钥数据结构
   * @param supported_crypto_algorithms 支持的加密算法列表
   * @return int 0或错误码
   */
  ATBUS_MACRO_API ATBUS_ERROR_TYPE
  handshake_read_peer_key(const protocol::crypto_handshake_data &peer_pub_key,
                          gsl::span<const protocol::ATBUS_CRYPTO_ALGORITHM_TYPE> supported_crypto_algorithms);

  /**
   * @brief 写入自己的公钥到握手数据结构
   * @param self_pub_key 输出的公钥数据结构
   * @param supported_crypto_algorithms 支持的加密算法列表
   * @return int 0或错误码
   */
  ATBUS_MACRO_API ATBUS_ERROR_TYPE
  handshake_write_self_public_key(protocol::crypto_handshake_data &self_pub_key,
                                  gsl::span<const protocol::ATBUS_CRYPTO_ALGORITHM_TYPE> supported_crypto_algorithms);

  static ATBUS_MACRO_API size_t internal_padding_temporary_buffer_block(size_t origin_size) noexcept;

  ATBUS_MACRO_API ATBUS_ERROR_TYPE
  update_compression_algorithm(gsl::span<const protocol::ATBUS_COMPRESSION_ALGORITHM_TYPE> algorithm) noexcept;

  static ATBUS_MACRO_API bool is_compression_algorithm_supported(
      protocol::ATBUS_COMPRESSION_ALGORITHM_TYPE algorithm) noexcept;

  /**
   * @brief 直接设置加密密钥（用于测试，跳过密钥交换）
   * @param algorithm 加密算法类型
   * @param key 密钥数据
   * @param key_size 密钥大小（字节）
   * @param iv 初始化向量数据
   * @param iv_size 初始化向量大小（字节）
   * @return int 0或错误码
   */
  ATBUS_MACRO_API ATBUS_ERROR_TYPE setup_crypto_with_key(protocol::ATBUS_CRYPTO_ALGORITHM_TYPE algorithm,
                                                         const unsigned char *key, size_t key_size,
                                                         const unsigned char *iv, size_t iv_size);

 private:
  ATBUS_MACRO_API buffer_result_t pack_message_origin(message &m) noexcept;

  ATBUS_MACRO_API buffer_result_t pack_message_with(message &m,
                                                    protocol::ATBUS_COMPRESSION_ALGORITHM_TYPE compression_algorithm,
                                                    protocol::ATBUS_CRYPTO_ALGORITHM_TYPE crypto_algorithm,
                                                    random_engine_t &random_engine) noexcept;

 private:
  protocol::ATBUS_CRYPTO_KEY_EXCHANGE_TYPE crypto_key_exchange_algorithm_;
  protocol::ATBUS_CRYPTO_KDF_TYPE crypto_select_kdf_type_;
  protocol::ATBUS_CRYPTO_ALGORITHM_TYPE crypto_select_algorithm_;
  protocol::ATBUS_COMPRESSION_ALGORITHM_TYPE compression_select_algorithm_;
  std::vector<protocol::ATBUS_COMPRESSION_ALGORITHM_TYPE> supported_compression_algorithms_;
  uint64_t handshake_sequence_id_;
  std::chrono::system_clock::time_point handshake_start_time_;
  std::vector<unsigned char> handshake_self_public_key_;
  ::atfw::util::crypto::dh::shared_context::ptr_t handshake_ctx_;
  ::atfw::util::memory::strong_rc_ptr<::atfw::util::crypto::dh> handshake_dh_;
  ::atfw::util::memory::strong_rc_ptr<::atfw::util::crypto::cipher> send_cipher_;
  ::atfw::util::memory::strong_rc_ptr<::atfw::util::crypto::cipher> receive_cipher_;
};
ATBUS_MACRO_NAMESPACE_END
