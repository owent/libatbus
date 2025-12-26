// Copyright 2025 atframework

#include "atbus_connection_context.h"

#include <algorithm/bit.h>
#include <algorithm/crypto_hmac.h>
#include <time/time_utility.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <unordered_set>
#include <vector>

#include "detail/buffer.h"
#include "detail/libatbus_error.h"
#include "libatbus_protocol.h"

ATBUS_MACRO_NAMESPACE_BEGIN

namespace {

static bool _allow_crypto(protocol::message_body::MessageTypeCase message_type) {
  // ping/pong and register messages have no crypto and compression and without padding
  switch (message_type) {
    case protocol::message_body::kNodeRegisterReq:
    case protocol::message_body::kNodeRegisterRsp:
    case protocol::message_body::kNodePingReq:
    case protocol::message_body::kNodePongRsp:
      return false;
    default:
      return true;
  }
}

static bool _allow_compress(protocol::message_body::MessageTypeCase /*message_type*/, size_t body_size) {
  // TODO: 需要进一步测试确定实际案例中的阈值
  // 如果body本身太小，压缩的头部反而会导致整体膨胀，那就不如不压缩
  if (body_size <= 512) {
    return false;
  }

  return true;
}

static std::unordered_set<protocol::ATBUS_COMPRESSION_ALGORITHM_TYPE> _build_all_supported_compression_algorithms() {
  std::unordered_set<protocol::ATBUS_COMPRESSION_ALGORITHM_TYPE> ret;
  // TODO: 接入压缩算法
  return ret;
}

static const std::unordered_set<protocol::ATBUS_COMPRESSION_ALGORITHM_TYPE> &
_get_all_supported_compression_algorithms() {
  static const std::unordered_set<protocol::ATBUS_COMPRESSION_ALGORITHM_TYPE> ret =
      _build_all_supported_compression_algorithms();
  return ret;
}

static std::unordered_set<protocol::ATBUS_CRYPTO_KDF_TYPE> _build_all_supported_kdf_types() {
  std::unordered_set<protocol::ATBUS_CRYPTO_KDF_TYPE> ret;
  ret.insert(protocol::ATBUS_CRYPTO_KDF_HKDF_SHA256);
  return ret;
}

static const std::unordered_set<protocol::ATBUS_CRYPTO_KDF_TYPE> &_get_all_supported_kdf_types() {
  static const std::unordered_set<protocol::ATBUS_CRYPTO_KDF_TYPE> ret = _build_all_supported_kdf_types();
  return ret;
}

static uint64_t _build_handshake_sequence_init_id() {
  uint64_t us = static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch())
          .count());
  us -= 1735689600ULL * 1000000;  // 2025-01-01 00:00:00 UTC in microseconds

  return us;
}

static ::atfw::util::memory::strong_rc_ptr<::atfw::util::crypto::cipher> _create_crypto_cipher(
    protocol::ATBUS_CRYPTO_ALGORITHM_TYPE type, bool is_encrypt) {
  ::atfw::util::crypto::cipher::mode_t::type mode = is_encrypt ? ::atfw::util::crypto::cipher::mode_t::EN_CMODE_ENCRYPT
                                                               : ::atfw::util::crypto::cipher::mode_t::EN_CMODE_DECRYPT;
  switch (type) {
    case protocol::ATBUS_CRYPTO_ALGORITHM_XXTEA: {
      auto cipher_ptr = ::atfw::util::memory::make_strong_rc<::atfw::util::crypto::cipher>();
      if (cipher_ptr->init("xxtea", mode) != ::atfw::util::crypto::cipher::error_code_t::OK) {
        return nullptr;
      }
      return cipher_ptr;
    }
    case protocol::ATBUS_CRYPTO_ALGORITHM_AES_128_CBC: {
      auto cipher_ptr = ::atfw::util::memory::make_strong_rc<::atfw::util::crypto::cipher>();
      if (cipher_ptr->init("aes-128-cbc", mode) != ::atfw::util::crypto::cipher::error_code_t::OK) {
        return nullptr;
      }
      return cipher_ptr;
    }
    case protocol::ATBUS_CRYPTO_ALGORITHM_AES_128_GCM: {
      auto cipher_ptr = ::atfw::util::memory::make_strong_rc<::atfw::util::crypto::cipher>();
      if (cipher_ptr->init("aes-128-gcm", mode) != ::atfw::util::crypto::cipher::error_code_t::OK) {
        return nullptr;
      }
      return cipher_ptr;
    }
    case protocol::ATBUS_CRYPTO_ALGORITHM_AES_192_CBC: {
      auto cipher_ptr = ::atfw::util::memory::make_strong_rc<::atfw::util::crypto::cipher>();
      if (cipher_ptr->init("aes-192-cbc", mode) != ::atfw::util::crypto::cipher::error_code_t::OK) {
        return nullptr;
      }
      return cipher_ptr;
    }
    case protocol::ATBUS_CRYPTO_ALGORITHM_AES_192_GCM: {
      auto cipher_ptr = ::atfw::util::memory::make_strong_rc<::atfw::util::crypto::cipher>();
      if (cipher_ptr->init("aes-192-gcm", mode) != ::atfw::util::crypto::cipher::error_code_t::OK) {
        return nullptr;
      }
      return cipher_ptr;
    }
    case protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_CBC: {
      auto cipher_ptr = ::atfw::util::memory::make_strong_rc<::atfw::util::crypto::cipher>();
      if (cipher_ptr->init("aes-256-cbc", mode) != ::atfw::util::crypto::cipher::error_code_t::OK) {
        return nullptr;
      }
      return cipher_ptr;
    }
    case protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_GCM: {
      auto cipher_ptr = ::atfw::util::memory::make_strong_rc<::atfw::util::crypto::cipher>();
      auto init_ret = cipher_ptr->init("aes-256-gcm", mode);
      if (init_ret != ::atfw::util::crypto::cipher::error_code_t::OK) {
        return nullptr;
      }
      return cipher_ptr;
    }
    case protocol::ATBUS_CRYPTO_ALGORITHM_CHACHA20: {
      auto cipher_ptr = ::atfw::util::memory::make_strong_rc<::atfw::util::crypto::cipher>();
      if (cipher_ptr->init("chacha20", mode) != ::atfw::util::crypto::cipher::error_code_t::OK) {
        return nullptr;
      }
      return cipher_ptr;
    }
    case protocol::ATBUS_CRYPTO_ALGORITHM_CHACHA20_POLY1305_IETF: {
      auto cipher_ptr = ::atfw::util::memory::make_strong_rc<::atfw::util::crypto::cipher>();
      if (cipher_ptr->init("chacha20-poly1305-ietf", mode) != ::atfw::util::crypto::cipher::error_code_t::OK) {
        return nullptr;
      }
      return cipher_ptr;
    }
    case protocol::ATBUS_CRYPTO_ALGORITHM_XCHACHA20_POLY1305_IETF: {
      auto cipher_ptr = ::atfw::util::memory::make_strong_rc<::atfw::util::crypto::cipher>();
      if (cipher_ptr->init("xchacha20-poly1305-ietf", mode) != ::atfw::util::crypto::cipher::error_code_t::OK) {
        return nullptr;
      }
      return cipher_ptr;
    }
    default:
      return nullptr;
  }
}

static int _generate_key_iv(protocol::ATBUS_CRYPTO_KDF_TYPE /*type*/, std::vector<unsigned char> &shared_secret,
                            size_t key_iv_size, std::vector<unsigned char> &key_iv) {
  // FIXME: 目前只支持ATBUS_CRYPTO_KDF_HKDF_SHA256
  key_iv.resize(key_iv_size);

  if (::atfw::util::crypto::hkdf::derive(atfw::util::crypto::digest_type_t::kSha256, nullptr, 0, shared_secret.data(),
                                         shared_secret.size(), nullptr, 0, key_iv.data(), key_iv.size()) != 0) {
    key_iv.clear();
    return EN_ATBUS_ERR_CRYPTO_HANDSHAKE_KDF_ERROR;
  }
  return 0;
}

static uint64_t _generate_handshake_sequence_id() {
  static std::atomic<uint64_t> seq_id(_build_handshake_sequence_init_id());
  return ++seq_id;
}

static size_t _padding_temporary_buffer_block(size_t size) noexcept {
  // Align size to reduce memory fragmentation and improve malloc efficiency
  // This follows mimalloc/jemalloc/tcmalloc size class patterns with ~12.5% max internal fragmentation
  //
  // Size class strategy (similar to mimalloc):
  // - Tiny (0-64 bytes): align to 8 bytes (word size)
  // - Small (65-512 bytes): align to 16 bytes
  // - Medium (513-8KB): use exponential size classes with 12.5% spacing
  // - Large (>8KB): align to page size (4KB) for OS-level efficiency

  constexpr size_t kWordSize = sizeof(void *);  // 8 bytes on 64-bit
  constexpr size_t kMinAllocSize = kWordSize;   // Minimum allocation
  constexpr size_t kSmallPageSize = 4096;       // OS page size for large allocs

  if (size == 0) {
    return kMinAllocSize;
  }

  // Tiny allocations (<=64 bytes): align to word size (8 bytes)
  // mimalloc uses exact sizes for wsize 1-8
  if (size <= 64) {
    return (size + kWordSize - 1) & ~(kWordSize - 1);
  }

  // Small allocations (65-512 bytes): align to 16 bytes(for SIMD)
  if (size <= 512) {
    return (size + 15) & ~static_cast<size_t>(15);
  }

  // Medium allocations (513 bytes - 8KB): use mimalloc-style 12.5% spacing
  // bin = (b << 2) + top_2_bits, where b is the position of highest bit
  // This gives size classes like: 512, 576, 640, 704, 768, 832, 896, 960, 1024, ...
  if (size <= 8192) {
    // Convert to word size for calculation
    size_t wsize = (size + kWordSize - 1) / kWordSize;

    // Use compiler intrinsic to find highest bit position - O(1) on modern CPUs
    // bit_width returns the number of bits needed to represent wsize
    size_t b = static_cast<size_t>(::atfw::util::bit::bit_width(wsize - 1));

    // Calculate bin using top 2 bits after the highest bit
    // This gives ~12.5% size class spacing
    size_t bin;
    if (b < 3) {
      bin = wsize;  // Exact sizes for small wsize
    } else {
      bin = (b << 2) + (((wsize - 1) >> (b - 2)) & 0x03);
    }

    // Convert bin back to size: reconstruct size from bin
    // bin = (b << 2) + extra, where extra is 0-3
    size_t bin_b = bin >> 2;
    size_t bin_extra = bin & 0x03;
    size_t result_wsize;
    if (bin_b < 3) {
      result_wsize = bin;
    } else {
      // Reconstruct: wsize = (1 << (b-1)) + (extra+1) * (1 << (b-3))
      // This gives the upper bound of the size class
      result_wsize = (static_cast<size_t>(1) << (bin_b - 1)) + ((bin_extra + 1) << (bin_b - 3));
    }

    return result_wsize * kWordSize;
  }

  // Large allocations (>8KB): align to page size (4KB)
  // mimalloc aligns large objects to OS page boundaries
  return (size + kSmallPageSize - 1) & ~(kSmallPageSize - 1);
}

static static_buffer_block _allocate_temporary_buffer_block(size_t origin_size) {
  // size padding
  size_t real_size = _padding_temporary_buffer_block(origin_size);

  // TODO(owent): 线程安全的对象池(分block size)
  return {std::make_unique<unsigned char[]>(real_size), real_size, origin_size};
}

}  // namespace

ATBUS_MACRO_API connection_context::connection_context(
    ctor_guard_type &, protocol::ATBUS_CRYPTO_KEY_EXCHANGE_TYPE crypto_key_exchange_algorithm,
    ::atfw::util::crypto::dh::shared_context::ptr_t shared_dh_context)
    : crypto_key_exchange_algorithm_(crypto_key_exchange_algorithm),
      crypto_select_kdf_type_(protocol::ATBUS_CRYPTO_KDF_HKDF_SHA256),
      crypto_select_algorithm_(protocol::ATBUS_CRYPTO_ALGORITHM_NONE),
      compression_select_algorithm_(protocol::ATBUS_COMPRESSION_ALGORITHM_NONE),
      handshake_sequence_id_(0),
      handshake_start_time_(std::chrono::system_clock::from_time_t(0)) {
  if (!shared_dh_context || shared_dh_context->get_method() != ::atfw::util::crypto::dh::method_t::EN_CDT_ECDH) {
    crypto_key_exchange_algorithm_ = protocol::ATBUS_CRYPTO_KEY_EXCHANGE_NONE;
  }

  if (crypto_key_exchange_algorithm_ == protocol::ATBUS_CRYPTO_KEY_EXCHANGE_NONE) {
    return;
  }

  handshake_ctx_ = shared_dh_context;
}

ATBUS_MACRO_API connection_context::~connection_context() {}

ATBUS_MACRO_API connection_context::ptr_t connection_context::create(
    protocol::ATBUS_CRYPTO_KEY_EXCHANGE_TYPE crypto_algorithm,
    ::atfw::util::crypto::dh::shared_context::ptr_t shared_dh_context) {
  ctor_guard_type guard;
  return ::atfw::util::memory::make_strong_rc<connection_context>(guard, crypto_algorithm,
                                                                  std::move(shared_dh_context));
}

ATBUS_MACRO_API connection_context::buffer_result_t connection_context::pack_message(message &m,
                                                                                     int32_t protocol_version,
                                                                                     random_engine_t &random_engine,
                                                                                     size_t max_body_size) noexcept {
  size_t body_size = 0;
  protocol::ATBUS_COMPRESSION_ALGORITHM_TYPE compression_algorithm = protocol::ATBUS_COMPRESSION_ALGORITHM_NONE;
  protocol::ATBUS_CRYPTO_ALGORITHM_TYPE crypto_algorithm = protocol::ATBUS_CRYPTO_ALGORITHM_NONE;
  auto body = m.get_body();
  if (body != nullptr) {
    body_size = static_cast<size_t>(body->ByteSizeLong());

    if (_allow_crypto(body->message_type_case()) && send_cipher_) {
      crypto_algorithm = crypto_select_algorithm_;
    }
    if (_allow_compress(body->message_type_case(), body_size)) {
      compression_algorithm = compression_select_algorithm_;
    }
  }

  if (body_size > max_body_size) {
    if (body_size > max_body_size + ATBUS_MACRO_MAX_FRAME_HEADER) {
      return buffer_result_t::make_error(EN_ATBUS_ERR_INVALID_SIZE);
    }

    size_t check_user_body_size = body_size;
    switch (body->message_type_case()) {
      case protocol::message_body::kDataTransformReq:
        check_user_body_size = body->data_transform_req().content().size();
        break;
      case protocol::message_body::kDataTransformRsp:
        check_user_body_size = body->data_transform_rsp().content().size();
        break;
      case protocol::message_body::kCustomCommandReq:
        check_user_body_size = 0;
        for (auto &cmd : body->custom_command_req().commands()) {
          check_user_body_size += cmd.arg().size();
        }
        break;
      case protocol::message_body::kCustomCommandRsp:
        check_user_body_size = 0;
        for (auto &cmd : body->custom_command_rsp().commands()) {
          check_user_body_size += cmd.arg().size();
        }
        break;
      default:
        break;
    }

    if (check_user_body_size > max_body_size) {
      return buffer_result_t::make_error(EN_ATBUS_ERR_INVALID_SIZE);
    }
  }

  auto &head = m.mutable_head();
  head.set_version(protocol_version);
  head.set_body_size(static_cast<uint64_t>(body_size));

  // 如果无压缩，无加密。直接计算出目标buffer大小，避免多余的内存分配和数据拷贝
  if (compression_algorithm == protocol::ATBUS_COMPRESSION_ALGORITHM_NONE &&
      crypto_algorithm == protocol::ATBUS_CRYPTO_ALGORITHM_NONE) {
    return pack_message_origin(m);
  } else {
    return pack_message_with(m, compression_algorithm, crypto_algorithm, random_engine);
  }
}

// Message帧层: vint(header长度) + header + body + padding
ATBUS_MACRO_API int connection_context::unpack_message(message &m, gsl::span<const unsigned char> input,
                                                       size_t max_body_size) noexcept {
  if (input.size() > max_body_size + ATBUS_MACRO_MAX_FRAME_HEADER) {
    return EN_ATBUS_ERR_INVALID_SIZE;
  }

  // decode
  uint64_t head_size = 0;
  size_t head_vint_size = ::atframework::atbus::detail::fn::read_vint(
      head_size, reinterpret_cast<const void *>(input.data()), input.size());
  if (head_vint_size == 0) {
    return EN_ATBUS_ERR_INVALID_SIZE;
  }

  if (static_cast<size_t>(head_size) + head_vint_size > input.size()) {
    return EN_ATBUS_ERR_INVALID_SIZE;
  }

  auto &head = m.mutable_head();
  if (!head.ParseFromArray(reinterpret_cast<const uint8_t *>(input.data() + head_vint_size),
                           static_cast<int>(head_size))) {
    return EN_ATBUS_ERR_UNPACK;
  }

  if (head.body_size() <= 0) {
    return EN_ATBUS_ERR_SUCCESS;
  }

  if (max_body_size > 0 && head.body_size() > max_body_size + ATBUS_MACRO_MAX_FRAME_HEADER) {
    return EN_ATBUS_ERR_INVALID_SIZE;
  }

  // Step - 1: 解密阶段
  gsl::span<const unsigned char> next_block = input.subspan(head_vint_size + head_size);
  auto &crypt_info = head.crypto();
  static_buffer_block decrypt_data_block;
  if (crypt_info.algorithm() != protocol::ATBUS_CRYPTO_ALGORITHM_NONE) {
    if (crypt_info.algorithm() != crypto_select_algorithm_ || !receive_cipher_) {
      return EN_ATBUS_ERR_CRYPTO_ALGORITHM_NOT_MATCH;
    }

    if (!crypt_info.iv().empty()) {
      receive_cipher_->set_iv(reinterpret_cast<const unsigned char *>(crypt_info.iv().data()), crypt_info.iv().size());
    }

    if (receive_cipher_->is_aead()) {
      size_t expect_at_least_size = static_cast<size_t>(next_block.size() + receive_cipher_->get_block_size());
      decrypt_data_block = _allocate_temporary_buffer_block(expect_at_least_size);
      size_t olen = decrypt_data_block.size();
      if (receive_cipher_->decrypt_aead(next_block.data(), next_block.size(), decrypt_data_block.data(), &olen,
                                        reinterpret_cast<const unsigned char *>(crypt_info.aad().data()),
                                        crypt_info.aad().size()) < 0) {
        return EN_ATBUS_ERR_CRYPTO_DECRYPT;
      }
      next_block = gsl::span<const unsigned char>{decrypt_data_block.data(), olen};
    } else {
      size_t expect_at_least_size = static_cast<size_t>(next_block.size() + receive_cipher_->get_block_size());
      decrypt_data_block = _allocate_temporary_buffer_block(expect_at_least_size);
      size_t olen = decrypt_data_block.size();
      if (receive_cipher_->decrypt(next_block.data(), next_block.size(), decrypt_data_block.data(), &olen) < 0) {
        return EN_ATBUS_ERR_CRYPTO_DECRYPT;
      }
      next_block = gsl::span<const unsigned char>{decrypt_data_block.data(), olen};
    }
  }

  // Step - 2: 解压阶段
  auto &compression_info = head.compression();
  if (compression_info.type() != protocol::ATBUS_COMPRESSION_ALGORITHM_NONE) {
    // TODO: 压缩算法接入,解压前忽略掉padding部分
    // if (compression_info.original_size() > next_block.size()) {
    //   return buffer_result_t::make_error(EN_ATBUS_ERR_INVALID_SIZE);
    // }
    // if (compression_info.original_size() < next_block.size()) {
    //   next_block = next_block.subspan(0, compression_info.original_size());
    // }
    return EN_ATBUS_ERR_COMPRESSION_ALGORITHM_NOT_SUPPORT;
  }

  size_t body_size = static_cast<size_t>(head.body_size());
  if (body_size > next_block.size()) {
    return EN_ATBUS_ERR_INVALID_SIZE;
  }

  if (!m.mutable_body().ParseFromArray(reinterpret_cast<const void *>(next_block.data()),
                                       static_cast<int>(body_size))) {
    return EN_ATBUS_ERR_UNPACK;
  }

  return EN_ATBUS_ERR_SUCCESS;
}

ATBUS_MACRO_API std::chrono::system_clock::time_point connection_context::get_handshake_start_time() const noexcept {
  return handshake_start_time_;
}

ATBUS_MACRO_API protocol::ATBUS_CRYPTO_KEY_EXCHANGE_TYPE connection_context::get_crypto_key_exchange_algorithm()
    const noexcept {
  return crypto_key_exchange_algorithm_;
}

ATBUS_MACRO_API protocol::ATBUS_CRYPTO_KDF_TYPE connection_context::get_crypto_select_kdf_type() const noexcept {
  return crypto_select_kdf_type_;
}

ATBUS_MACRO_API protocol::ATBUS_CRYPTO_ALGORITHM_TYPE connection_context::get_crypto_select_algorithm() const noexcept {
  return crypto_select_algorithm_;
}

ATBUS_MACRO_API protocol::ATBUS_COMPRESSION_ALGORITHM_TYPE connection_context::get_compression_select_algorithm()
    const noexcept {
  return compression_select_algorithm_;
}

ATBUS_MACRO_API int connection_context::handshake_generate_self_key(uint64_t peer_sequence_id) {
  if (crypto_key_exchange_algorithm_ == protocol::ATBUS_CRYPTO_KEY_EXCHANGE_NONE || !handshake_ctx_) {
    return EN_ATBUS_ERR_SUCCESS;
  }

  if (peer_sequence_id != 0) {
    handshake_sequence_id_ = peer_sequence_id;
  } else {
    handshake_sequence_id_ = _generate_handshake_sequence_id();
  }

  ::atfw::util::time::time_utility::update();
  handshake_start_time_ = ::atfw::util::time::time_utility::sys_now();

  handshake_self_public_key_.clear();
  std::vector<unsigned char> handshake_self_private_key;
  handshake_dh_ = atfw::util::memory::make_strong_rc<::atfw::util::crypto::dh>();
  handshake_dh_->init(handshake_ctx_);

  if (handshake_dh_->make_params(handshake_self_private_key) != 0) {
    return EN_ATBUS_ERR_CRYPTO_HANDSHAKE_MAKE_KEY_PAIR;
  }

  if (handshake_dh_->make_public(handshake_self_public_key_) != 0) {
    return EN_ATBUS_ERR_CRYPTO_HANDSHAKE_MAKE_KEY_PAIR;
  }

  return EN_ATBUS_ERR_SUCCESS;
}

ATBUS_MACRO_API int connection_context::handshake_read_peer_key(
    const protocol::crypto_handshake_data &peer_pub_key,
    gsl::span<const protocol::ATBUS_CRYPTO_ALGORITHM_TYPE> supported_crypto_algorithms) {
  if (crypto_key_exchange_algorithm_ == protocol::ATBUS_CRYPTO_KEY_EXCHANGE_NONE || !handshake_dh_) {
    return EN_ATBUS_ERR_SUCCESS;
  }

  if (handshake_sequence_id_ != peer_pub_key.sequence()) {
    return EN_ATBUS_ERR_CRYPTO_HANDSHAKE_SEQUENCE_EXPIRED;
  }

  int ret = EN_ATBUS_ERR_SUCCESS;
  do {
    if (supported_crypto_algorithms.empty() && peer_pub_key.algorithms_size() == 0) {
      break;
    }

    if (crypto_key_exchange_algorithm_ != peer_pub_key.type()) {
      ret = EN_ATBUS_ERR_CRYPTO_ALGORITHM_NOT_MATCH;
      break;
    }

    crypto_select_kdf_type_ = protocol::ATBUS_CRYPTO_KDF_HKDF_SHA256;
    for (auto &peer_kdf_type : peer_pub_key.kdf_type()) {
      if (_get_all_supported_kdf_types().count(static_cast<protocol::ATBUS_CRYPTO_KDF_TYPE>(peer_kdf_type)) > 0) {
        crypto_select_kdf_type_ = static_cast<protocol::ATBUS_CRYPTO_KDF_TYPE>(peer_kdf_type);
        break;
      }
    }

    crypto_select_algorithm_ = protocol::ATBUS_CRYPTO_ALGORITHM_NONE;
    std::unordered_set<protocol::ATBUS_CRYPTO_ALGORITHM_TYPE> supported_set;
    supported_set.reserve(supported_crypto_algorithms.size());
    supported_set.insert(supported_crypto_algorithms.begin(), supported_crypto_algorithms.end());
    for (auto &peer_alg : peer_pub_key.algorithms()) {
      if (supported_set.end() != supported_set.find(static_cast<protocol::ATBUS_CRYPTO_ALGORITHM_TYPE>(peer_alg))) {
        crypto_select_algorithm_ = static_cast<protocol::ATBUS_CRYPTO_ALGORITHM_TYPE>(peer_alg);
        break;
      }
    }

    if (handshake_dh_->read_public(reinterpret_cast<const unsigned char *>(peer_pub_key.public_key().data()),
                                   peer_pub_key.public_key().size()) != 0) {
      ret = EN_ATBUS_ERR_CRYPTO_HANDSHAKE_NO_AVAILABLE_ALGORITHM;
      break;
    }

    if (crypto_select_algorithm_ == protocol::ATBUS_CRYPTO_ALGORITHM_NONE) {
      ret = EN_ATBUS_ERR_CRYPTO_HANDSHAKE_NO_AVAILABLE_ALGORITHM;
      break;
    }

    std::vector<unsigned char> shared_secret;
    if (handshake_dh_->calc_secret(shared_secret) != 0) {
      ret = EN_ATBUS_ERR_CRYPTO_HANDSHAKE_MAKE_SECRET;
      break;
    }

    // TODO: 初始化加密和解密cipher
    send_cipher_ = _create_crypto_cipher(crypto_select_algorithm_, true);
    receive_cipher_ = _create_crypto_cipher(crypto_select_algorithm_, false);
    if (!send_cipher_ || !receive_cipher_) {
      ret = EN_ATBUS_ERR_CRYPTO_HANDSHAKE_NO_AVAILABLE_ALGORITHM;
      break;
    }
    // 如果对方传来了iv size，以协商对方的为准
    // 否则本地创建cipher后以cipher的默认值为准
    uint32_t iv_size = peer_pub_key.iv_size();
    if (iv_size == 0) {
      iv_size = send_cipher_->get_iv_size();
    }
    uint32_t key_bits = send_cipher_->get_key_bits();
    uint32_t key_size = key_bits / 8;
    std::vector<unsigned char> key_iv;
    ret = _generate_key_iv(crypto_select_kdf_type_, shared_secret, iv_size + key_size, key_iv);
    if (ret != 0) {
      break;
    }
    if (send_cipher_->set_key(key_iv.data(), key_bits) != 0) {
      ret = EN_ATBUS_ERR_CRYPTO_ENCRYPT;
      break;
    }
    if (send_cipher_->set_iv(key_iv.data() + key_size, iv_size) != 0) {
      ret = EN_ATBUS_ERR_CRYPTO_INVALID_IV;
      break;
    }
    if (receive_cipher_->set_key(key_iv.data(), key_bits) != 0) {
      ret = EN_ATBUS_ERR_CRYPTO_ENCRYPT;
      break;
    }
    if (receive_cipher_->set_iv(key_iv.data() + key_size, iv_size) != 0) {
      ret = EN_ATBUS_ERR_CRYPTO_INVALID_IV;
      break;
    }
  } while (false);

  handshake_dh_.reset();

  return ret;
}

ATBUS_MACRO_API int connection_context::handshake_write_self_public_key(
    protocol::crypto_handshake_data &self_pub_key,
    gsl::span<const protocol::ATBUS_CRYPTO_ALGORITHM_TYPE> supported_crypto_algorithms) {
  self_pub_key.set_sequence(handshake_sequence_id_);
  self_pub_key.set_type(crypto_key_exchange_algorithm_);

  // 如果已经协商完毕，只需要下发选中的KDF类型
  if (send_cipher_ || receive_cipher_) {
    self_pub_key.mutable_kdf_type()->Reserve(1);
    self_pub_key.add_kdf_type(static_cast<protocol::ATBUS_CRYPTO_KDF_TYPE>(crypto_select_kdf_type_));
  } else {
    self_pub_key.mutable_kdf_type()->Reserve(static_cast<int>(_get_all_supported_kdf_types().size()));
    for (const auto &kdf_type : _get_all_supported_kdf_types()) {
      self_pub_key.add_kdf_type(kdf_type);
    }
  }

  self_pub_key.mutable_algorithms()->Reserve(static_cast<int>(supported_crypto_algorithms.size()));
  for (const auto &alg : supported_crypto_algorithms) {
    self_pub_key.add_algorithms(alg);
  }

  self_pub_key.set_public_key(std::string(reinterpret_cast<const char *>(handshake_self_public_key_.data()),
                                          handshake_self_public_key_.size()));

  if (send_cipher_) {
    self_pub_key.set_iv_size(send_cipher_->get_iv_size());
  } else if (receive_cipher_) {
    self_pub_key.set_iv_size(receive_cipher_->get_iv_size());
  }

  if (send_cipher_ && send_cipher_->is_aead()) {
    self_pub_key.set_tag_size(send_cipher_->get_tag_size());
  }
  return EN_ATBUS_ERR_SUCCESS;
}

ATBUS_MACRO_API size_t connection_context::internal_padding_temporary_buffer_block(size_t origin_size) noexcept {
  return _padding_temporary_buffer_block(origin_size);
}

ATBUS_MACRO_API int connection_context::update_compression_algorithm(
    gsl::span<const protocol::ATBUS_COMPRESSION_ALGORITHM_TYPE> algorithm) noexcept {
  supported_compression_algorithms_.clear();
  supported_compression_algorithms_.reserve(algorithm.size());
  supported_compression_algorithms_.assign(algorithm.begin(), algorithm.end());

  // 按优先级排序
  std::sort(supported_compression_algorithms_.begin(), supported_compression_algorithms_.end());

  // 选取第一个支持的压缩算法作为当前使用算法
  compression_select_algorithm_ = protocol::ATBUS_COMPRESSION_ALGORITHM_NONE;
  for (const auto &alg : supported_compression_algorithms_) {
    if (_get_all_supported_compression_algorithms().count(alg) > 0) {
      compression_select_algorithm_ = alg;
      break;
    }
  }

  return EN_ATBUS_ERR_SUCCESS;
}

ATBUS_MACRO_API bool connection_context::is_compression_algorithm_supported(
    protocol::ATBUS_COMPRESSION_ALGORITHM_TYPE algorithm) noexcept {
  return _get_all_supported_compression_algorithms().count(algorithm) > 0;
}

// Message帧层: vint(header长度) + header + body
ATBUS_MACRO_API connection_context::buffer_result_t connection_context::pack_message_origin(message &m) noexcept {
  auto &head = m.mutable_head();
  size_t body_size = static_cast<size_t>(head.body_size());

  size_t head_size = head.ByteSizeLong();

  unsigned char head_len_buffer[16];
  size_t head_vint_size = ::atframework::atbus::detail::fn::write_vint(
      static_cast<uint64_t>(head_size), reinterpret_cast<void *>(head_len_buffer), sizeof(head_len_buffer));

  size_t total_size = head_vint_size + head_size + body_size;

  static_buffer_block buffer = _allocate_temporary_buffer_block(total_size);
  memcpy(buffer.data(), head_len_buffer, head_vint_size);
  head.SerializeWithCachedSizesToArray(reinterpret_cast<uint8_t *>(buffer.data() + head_vint_size));
  auto body = m.get_body();
  if (body != nullptr && body_size > 0) {
    body->SerializeWithCachedSizesToArray(reinterpret_cast<uint8_t *>(buffer.data() + head_vint_size + head_size));
  }

  return buffer_result_t::make_success(std::move(buffer));
}

// Message帧层: vint(header长度) + header + body + padding
ATBUS_MACRO_API connection_context::buffer_result_t connection_context::pack_message_with(
    message &m, protocol::ATBUS_COMPRESSION_ALGORITHM_TYPE compression_algorithm,
    protocol::ATBUS_CRYPTO_ALGORITHM_TYPE crypto_algorithm, random_engine_t &random_engine) noexcept {
  auto &head = m.mutable_head();
  size_t body_size = static_cast<size_t>(head.body_size());
  size_t block_size = 0;
  if (send_cipher_) {
    block_size = send_cipher_->get_block_size();
  }
  static_buffer_block origin_buffer = _allocate_temporary_buffer_block(body_size + block_size);

  if (crypto_algorithm != protocol::ATBUS_CRYPTO_ALGORITHM_NONE &&
      (!send_cipher_ || crypto_algorithm != crypto_select_algorithm_)) {
    return buffer_result_t::make_error(EN_ATBUS_ERR_CRYPTO_ALGORITHM_NOT_MATCH);
  }

  auto body = m.get_body();
  if (body != nullptr && body_size > 0) {
    body->SerializeWithCachedSizesToArray(reinterpret_cast<uint8_t *>(origin_buffer.data()));
  }

  size_t head_size;
  unsigned char head_len_buffer[16];
  size_t head_vint_size;
  static_buffer_block final_buffer;

  // Step - 1: body压缩
  if (compression_algorithm != protocol::ATBUS_COMPRESSION_ALGORITHM_NONE) {
    // TODO: 压缩算法接入
    // TODO: 如果仅压缩，不加密，可以直接压缩到 final_buffer, 少一次copy
    return buffer_result_t::make_error(EN_ATBUS_ERR_COMPRESSION_ALGORITHM_NOT_SUPPORT);
  }

  // 对齐到加密算法的block size，有些套件需要我们手动对齐
  gsl::span<unsigned char> body_data_span;
  if (block_size > 1 && send_cipher_ && !send_cipher_->is_aead()) {
    // 对于非AEAD加密算法（如CBC），需要对齐到block size
    size_t padded_size = ((body_size + block_size - 1) / block_size) * block_size;
    // 填充字节使用 PKCS#7 padding
    if (padded_size > body_size) {
      unsigned char padding_value = static_cast<unsigned char>(padded_size - body_size);
      memset(origin_buffer.data() + body_size, padding_value, padded_size - body_size);
    }
    body_data_span = gsl::span<unsigned char>{origin_buffer.data(), padded_size};
  } else {
    body_data_span = gsl::span<unsigned char>{origin_buffer.data(), body_size};
  }

  // Step - 2: body加密
  auto crypto_info = head.mutable_crypto();
  if (crypto_info == nullptr) {
    return buffer_result_t::make_error(EN_ATBUS_ERR_MALLOC);
  }

  crypto_info->set_algorithm(crypto_algorithm);
  gsl::span<const unsigned char> iv = send_cipher_->get_iv();
  // 必须先写入，因为执行加密后iv会变更
  if (!iv.empty()) {
    crypto_info->set_iv(std::string(reinterpret_cast<const char *>(iv.data()), iv.size()));
  }
  if (send_cipher_->is_aead()) {
    crypto_info->set_aad(
        ::atfw::util::string::format("{:#x}.{:#x}-{:#x}", ::atfw::util::time::time_utility::get_sys_now(),
                                     ::atfw::util::time::time_utility::get_now_usec(), random_engine.random()));
    size_t body_at_least_size = body_data_span.size() + crypto_info->aad().size() + send_cipher_->get_block_size() +
                                send_cipher_->get_tag_size();
    // 这时候header数据已经固定，可以计算长度了
    head_size = head.ByteSizeLong();
    head_vint_size = ::atframework::atbus::detail::fn::write_vint(
        static_cast<uint64_t>(head_size), reinterpret_cast<void *>(head_len_buffer), sizeof(head_len_buffer));

    size_t total_size = head_vint_size + head_size + body_at_least_size;
    final_buffer = _allocate_temporary_buffer_block(total_size);

    memcpy(final_buffer.data(), head_len_buffer, head_vint_size);
    head.SerializeWithCachedSizesToArray(reinterpret_cast<uint8_t *>(final_buffer.data() + head_vint_size));

    int encrypt_result = send_cipher_->encrypt_aead(
        body_data_span.data(), body_data_span.size(), final_buffer.data() + head_vint_size + head_size,
        &body_at_least_size, reinterpret_cast<const unsigned char *>(crypto_info->aad().data()),
        crypto_info->aad().size());
    if (encrypt_result < 0) {
      return buffer_result_t::make_error(EN_ATBUS_ERR_CRYPTO_ENCRYPT);
    }
    final_buffer.set_used(head_vint_size + head_size + body_at_least_size);
  } else {
    size_t body_at_least_size = body_data_span.size() + send_cipher_->get_block_size();
    // 这时候header数据已经固定，可以计算长度了
    head_size = head.ByteSizeLong();
    head_vint_size = ::atframework::atbus::detail::fn::write_vint(
        static_cast<uint64_t>(head_size), reinterpret_cast<void *>(head_len_buffer), sizeof(head_len_buffer));

    size_t total_size = head_vint_size + head_size + body_at_least_size;
    final_buffer = _allocate_temporary_buffer_block(total_size);

    memcpy(final_buffer.data(), head_len_buffer, head_vint_size);
    head.SerializeWithCachedSizesToArray(reinterpret_cast<uint8_t *>(final_buffer.data() + head_vint_size));

    if (send_cipher_->encrypt(body_data_span.data(), body_data_span.size(),
                              final_buffer.data() + head_vint_size + head_size, &body_at_least_size) < 0) {
      return buffer_result_t::make_error(EN_ATBUS_ERR_CRYPTO_ENCRYPT);
    }
    final_buffer.set_used(head_vint_size + head_size + body_at_least_size);
  }

  return buffer_result_t::make_success(std::move(final_buffer));
}

ATBUS_MACRO_NAMESPACE_END
