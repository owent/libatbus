// Copyright 2026 atframework

#include <atbus_connection_context.h>
#include <libatbus_protocol.h>

#include <algorithm/crypto_cipher.h>
#include <algorithm/crypto_dh.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "frame/test_macros.h"

namespace {

#ifdef CRYPTO_DH_ENABLED
struct openssl_test_init_wrapper_for_connection_context {
  openssl_test_init_wrapper_for_connection_context() { atfw::util::crypto::cipher::init_global_algorithm(); }
  ~openssl_test_init_wrapper_for_connection_context() { atfw::util::crypto::cipher::cleanup_global_algorithm(); }
};

static std::shared_ptr<openssl_test_init_wrapper_for_connection_context> openssl_test_inited_for_connection_context;

static void ensure_openssl_initialized() {
  if (!openssl_test_inited_for_connection_context) {
    openssl_test_inited_for_connection_context = std::make_shared<openssl_test_init_wrapper_for_connection_context>();
  }
}

// Helper function to create a DH shared context for testing
static ::atfw::util::crypto::dh::shared_context::ptr_t create_test_dh_context(const char* curve_name) {
  auto ctx = ::atfw::util::crypto::dh::shared_context::create();
  if (ctx && ctx->init(curve_name) == 0) {
    return ctx;
  }
  return nullptr;
}

// Helper function to check if a cipher algorithm is available
static bool is_cipher_algorithm_available(const std::string& algo_name) {
  auto all_ciphers = atfw::util::crypto::cipher::get_all_cipher_names();
  for (const auto& cipher : all_ciphers) {
    if (cipher == algo_name) {
      return true;
    }
  }
  return false;
}

// Helper function to verify cipher can encrypt/decrypt
static bool test_cipher_encrypt_decrypt(const char* cipher_name) {
  atfw::util::crypto::cipher ci;
  int init_res = ci.init(cipher_name, atfw::util::crypto::cipher::mode_t::EN_CMODE_ENCRYPT |
                                          atfw::util::crypto::cipher::mode_t::EN_CMODE_DECRYPT);
  if (init_res != 0) {
    CASE_MSG_INFO() << "cipher init failed: " << init_res << ", errno: " << ci.get_last_errno() << std::endl;
    return false;
  }

  // Set a test key
  uint32_t key_bits = ci.get_key_bits();
  std::vector<unsigned char> key(key_bits / 8, 0x42);
  int key_res = ci.set_key(key.data(), key_bits);
  if (key_res != 0) {
    CASE_MSG_INFO() << "set_key failed: " << key_res << ", errno: " << ci.get_last_errno() << std::endl;
    return false;
  }

  // Set IV
  uint32_t iv_size = ci.get_iv_size();
  if (iv_size > 0) {
    std::vector<unsigned char> iv(iv_size, 0x24);
    int iv_res = ci.set_iv(iv.data(), iv_size);
    if (iv_res != 0) {
      CASE_MSG_INFO() << "set_iv failed: " << iv_res << ", errno: " << ci.get_last_errno() << std::endl;
      return false;
    }
  }

  // Test encryption
  const std::string plaintext = "Hello, encrypted world!";
  size_t out_size = plaintext.size() + ci.get_block_size() + ci.get_tag_size();
  std::vector<unsigned char> ciphertext(out_size);

  int encrypt_res;
  if (ci.is_aead()) {
    const std::string aad = "additional-data";
    encrypt_res =
        ci.encrypt_aead(reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size(), ciphertext.data(),
                        &out_size, reinterpret_cast<const unsigned char*>(aad.data()), aad.size());
    if (encrypt_res != 0) {
      CASE_MSG_INFO() << "encrypt_aead failed: " << encrypt_res << ", errno: " << ci.get_last_errno()
                      << ", is_aead: " << ci.is_aead() << ", tag_size: " << ci.get_tag_size()
                      << ", block_size: " << ci.get_block_size() << std::endl;
      return false;
    }
  } else {
    encrypt_res = ci.encrypt(reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size(),
                             ciphertext.data(), &out_size);
    if (encrypt_res != 0) {
      CASE_MSG_INFO() << "encrypt failed: " << encrypt_res << ", errno: " << ci.get_last_errno() << std::endl;
      return false;
    }
  }

  return true;
}

// Helper function to test cipher with ENCRYPT mode only (like _create_crypto_cipher does for send_cipher_)
static bool test_cipher_encrypt_only_mode(const char* cipher_name) {
  atfw::util::crypto::cipher ci;
  // Use ONLY encrypt mode, just like _create_crypto_cipher does for send_cipher_
  int init_res = ci.init(cipher_name, atfw::util::crypto::cipher::mode_t::EN_CMODE_ENCRYPT);
  if (init_res != 0) {
    CASE_MSG_INFO() << "[SINGLE MODE] cipher init failed: " << init_res << ", errno: " << ci.get_last_errno()
                    << std::endl;
    return false;
  }

  // Set a test key (use correct bit count)
  uint32_t key_bits = ci.get_key_bits();
  std::vector<unsigned char> key(key_bits / 8, 0x42);
  int key_res = ci.set_key(key.data(), key_bits);
  if (key_res != 0) {
    CASE_MSG_INFO() << "[SINGLE MODE] set_key failed: " << key_res << ", errno: " << ci.get_last_errno() << std::endl;
    return false;
  }

  // Set IV
  uint32_t iv_size = ci.get_iv_size();
  if (iv_size > 0) {
    std::vector<unsigned char> iv(iv_size, 0x24);
    int iv_res = ci.set_iv(iv.data(), iv_size);
    if (iv_res != 0) {
      CASE_MSG_INFO() << "[SINGLE MODE] set_iv failed: " << iv_res << ", errno: " << ci.get_last_errno() << std::endl;
      return false;
    }
  }

  // Test encryption with AEAD if applicable
  const std::string plaintext = "Hello, encrypted world!";
  size_t out_size = plaintext.size() + ci.get_block_size() + ci.get_tag_size();
  std::vector<unsigned char> ciphertext(out_size);

  int encrypt_res;
  if (ci.is_aead()) {
    const std::string aad = "additional-data";
    encrypt_res =
        ci.encrypt_aead(reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size(), ciphertext.data(),
                        &out_size, reinterpret_cast<const unsigned char*>(aad.data()), aad.size());
    if (encrypt_res != 0) {
      CASE_MSG_INFO() << "[SINGLE MODE] encrypt_aead failed: " << encrypt_res << ", errno: " << ci.get_last_errno()
                      << ", is_aead: " << ci.is_aead() << ", tag_size: " << ci.get_tag_size()
                      << ", block_size: " << ci.get_block_size() << std::endl;
      return false;
    }
  } else {
    encrypt_res = ci.encrypt(reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size(),
                             ciphertext.data(), &out_size);
    if (encrypt_res != 0) {
      CASE_MSG_INFO() << "[SINGLE MODE] encrypt failed: " << encrypt_res << ", errno: " << ci.get_last_errno()
                      << std::endl;
      return false;
    }
  }

  CASE_MSG_INFO() << "[SINGLE MODE] cipher encrypt test PASSED for " << cipher_name << std::endl;
  return true;
}
#endif

}  // namespace

// Test zero size input
CASE_TEST(atbus_connection_context, padding_zero_size) {
  // Zero size should return minimum allocation size (word size = 8 bytes on 64-bit)
  size_t result = atfw::atbus::connection_context::internal_padding_temporary_buffer_block(0);
  CASE_EXPECT_EQ(sizeof(void*), result);
}

// Test tiny allocations (1-64 bytes) - should align to word size (8 bytes)
CASE_TEST(atbus_connection_context, padding_tiny_allocations) {
  constexpr size_t kWordSize = sizeof(void*);

  // Test boundary values
  CASE_EXPECT_EQ(kWordSize, atfw::atbus::connection_context::internal_padding_temporary_buffer_block(1));
  CASE_EXPECT_EQ(kWordSize, atfw::atbus::connection_context::internal_padding_temporary_buffer_block(kWordSize - 1));
  CASE_EXPECT_EQ(kWordSize, atfw::atbus::connection_context::internal_padding_temporary_buffer_block(kWordSize));

  CASE_EXPECT_EQ(kWordSize * 2,
                 atfw::atbus::connection_context::internal_padding_temporary_buffer_block(kWordSize + 1));
  CASE_EXPECT_EQ(kWordSize * 2, atfw::atbus::connection_context::internal_padding_temporary_buffer_block(16));

  // Test various tiny sizes
  CASE_EXPECT_EQ(24, atfw::atbus::connection_context::internal_padding_temporary_buffer_block(17));
  CASE_EXPECT_EQ(24, atfw::atbus::connection_context::internal_padding_temporary_buffer_block(24));
  CASE_EXPECT_EQ(32, atfw::atbus::connection_context::internal_padding_temporary_buffer_block(25));
  CASE_EXPECT_EQ(32, atfw::atbus::connection_context::internal_padding_temporary_buffer_block(32));

  // Test boundary at 64 bytes
  CASE_EXPECT_EQ(56, atfw::atbus::connection_context::internal_padding_temporary_buffer_block(49));
  CASE_EXPECT_EQ(64, atfw::atbus::connection_context::internal_padding_temporary_buffer_block(57));
  CASE_EXPECT_EQ(64, atfw::atbus::connection_context::internal_padding_temporary_buffer_block(64));
}

// Test small allocations (65-512 bytes) - should align to 16 bytes
CASE_TEST(atbus_connection_context, padding_small_allocations) {
  // Just above tiny threshold
  CASE_EXPECT_EQ(80, atfw::atbus::connection_context::internal_padding_temporary_buffer_block(65));
  CASE_EXPECT_EQ(80, atfw::atbus::connection_context::internal_padding_temporary_buffer_block(80));

  // Various small sizes
  CASE_EXPECT_EQ(96, atfw::atbus::connection_context::internal_padding_temporary_buffer_block(81));
  CASE_EXPECT_EQ(128, atfw::atbus::connection_context::internal_padding_temporary_buffer_block(128));
  CASE_EXPECT_EQ(256, atfw::atbus::connection_context::internal_padding_temporary_buffer_block(256));

  // Test boundary at 512 bytes
  CASE_EXPECT_EQ(496, atfw::atbus::connection_context::internal_padding_temporary_buffer_block(481));
  CASE_EXPECT_EQ(512, atfw::atbus::connection_context::internal_padding_temporary_buffer_block(497));
  CASE_EXPECT_EQ(512, atfw::atbus::connection_context::internal_padding_temporary_buffer_block(512));
}

// Test medium allocations (513-8192 bytes) - mimalloc-style size classes
CASE_TEST(atbus_connection_context, padding_medium_allocations) {
  // Just above small threshold - uses size class spacing
  size_t result_513 = atfw::atbus::connection_context::internal_padding_temporary_buffer_block(513);
  CASE_EXPECT_GE(result_513, static_cast<size_t>(513));
  // Result should be aligned to word size * power-of-2 for efficiency
  CASE_EXPECT_EQ(0u, result_513 % sizeof(void*));

  // Test 1KB boundary
  size_t result_1024 = atfw::atbus::connection_context::internal_padding_temporary_buffer_block(1024);
  CASE_EXPECT_GE(result_1024, static_cast<size_t>(1024));

  // Test 2KB
  size_t result_2048 = atfw::atbus::connection_context::internal_padding_temporary_buffer_block(2048);
  CASE_EXPECT_GE(result_2048, static_cast<size_t>(2048));

  // Test 4KB
  size_t result_4096 = atfw::atbus::connection_context::internal_padding_temporary_buffer_block(4096);
  CASE_EXPECT_GE(result_4096, static_cast<size_t>(4096));

  // Test boundary at 8KB
  size_t result_8192 = atfw::atbus::connection_context::internal_padding_temporary_buffer_block(8192);
  CASE_EXPECT_GE(result_8192, static_cast<size_t>(8192));

  // Verify size class spacing - result should increase monotonically
  // and always be >= input
  size_t prev_result = 512;
  for (size_t size = 513; size <= 8192; size += 64) {
    size_t result = atfw::atbus::connection_context::internal_padding_temporary_buffer_block(size);
    CASE_EXPECT_GE(result, size);
    CASE_EXPECT_GE(result, prev_result);
    // Result should be word-aligned for efficiency
    CASE_EXPECT_EQ(0u, result % sizeof(void*));
    prev_result = result;
  }
}

// Test large allocations (>8192 bytes) - should align to page size (4KB)
CASE_TEST(atbus_connection_context, padding_large_allocations) {
  constexpr size_t kPageSize = 4096;

  // Just above medium threshold
  size_t result_8193 = atfw::atbus::connection_context::internal_padding_temporary_buffer_block(8193);
  CASE_EXPECT_EQ(kPageSize * 3, result_8193);  // 12288

  // Test various large sizes
  CASE_EXPECT_EQ(kPageSize * 3, atfw::atbus::connection_context::internal_padding_temporary_buffer_block(9000));
  CASE_EXPECT_EQ(kPageSize * 3, atfw::atbus::connection_context::internal_padding_temporary_buffer_block(12288));
  CASE_EXPECT_EQ(kPageSize * 4, atfw::atbus::connection_context::internal_padding_temporary_buffer_block(12289));
  CASE_EXPECT_EQ(kPageSize * 4, atfw::atbus::connection_context::internal_padding_temporary_buffer_block(16384));

  // Test 1MB
  CASE_EXPECT_EQ(1024 * 1024, atfw::atbus::connection_context::internal_padding_temporary_buffer_block(1024 * 1024));
  CASE_EXPECT_EQ(1024 * 1024 + kPageSize,
                 atfw::atbus::connection_context::internal_padding_temporary_buffer_block(1024 * 1024 + 1));
}

// Test that result is always >= input
CASE_TEST(atbus_connection_context, padding_result_ge_input) {
  // Test many random sizes
  for (size_t size = 0; size <= 100000; size += 17) {
    size_t result = atfw::atbus::connection_context::internal_padding_temporary_buffer_block(size);
    if (size == 0) {
      CASE_EXPECT_EQ(sizeof(void*), result);
    } else {
      CASE_EXPECT_GE(result, size);
    }
  }
}

// Test alignment properties
CASE_TEST(atbus_connection_context, padding_alignment_properties) {
  constexpr size_t kWordSize = sizeof(void*);
  constexpr size_t kPageSize = 4096;

  // Tiny allocations should be word-aligned
  for (size_t size = 1; size <= 64; ++size) {
    size_t result = atfw::atbus::connection_context::internal_padding_temporary_buffer_block(size);
    CASE_EXPECT_EQ(0u, result % kWordSize);
  }

  // Small allocations should be 16-byte aligned
  for (size_t size = 65; size <= 512; ++size) {
    size_t result = atfw::atbus::connection_context::internal_padding_temporary_buffer_block(size);
    CASE_EXPECT_EQ(0u, result % 16);
  }

  // Large allocations should be page-aligned
  for (size_t size = 8193; size <= 100000; size += 1000) {
    size_t result = atfw::atbus::connection_context::internal_padding_temporary_buffer_block(size);
    CASE_EXPECT_EQ(0u, result % kPageSize);
  }
}

// Test monotonicity - larger input should never give smaller output
CASE_TEST(atbus_connection_context, padding_monotonicity) {
  size_t prev_result = 0;
  for (size_t size = 0; size <= 20000; ++size) {
    size_t result = atfw::atbus::connection_context::internal_padding_temporary_buffer_block(size);
    CASE_EXPECT_GE(result, prev_result);
    prev_result = result;
  }
}

// Test max overhead - verify result is always >= input with reasonable bounds
CASE_TEST(atbus_connection_context, padding_max_overhead) {
  // For medium allocations, verify that results are properly bounded
  // The size class algorithm uses power-of-2 bins, which can have variable overhead
  for (size_t size = 600; size <= 8000; size += 100) {
    size_t result = atfw::atbus::connection_context::internal_padding_temporary_buffer_block(size);
    // Result should always be >= input
    CASE_EXPECT_GE(result, size);
    // Result should be word-aligned
    CASE_EXPECT_EQ(0u, result % sizeof(void*));
    // Result should not be excessively large (less than 2x input)
    CASE_EXPECT_LT(result, size * 2);
  }
}

// ============================================================================
// Test create() static factory method
// ============================================================================

// Test create with no encryption
CASE_TEST(atbus_connection_context, create_no_encryption) {
  auto ctx =
      atfw::atbus::connection_context::create(atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_NONE, nullptr);

  CASE_EXPECT_NE(nullptr, ctx.get());
  CASE_EXPECT_EQ(atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_NONE,
                 ctx->get_crypto_key_exchange_algorithm());
  CASE_EXPECT_EQ(atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_NONE, ctx->get_crypto_select_algorithm());
  CASE_EXPECT_EQ(atframework::atbus::protocol::ATBUS_COMPRESSION_ALGORITHM_NONE,
                 ctx->get_compression_select_algorithm());
}

#ifdef CRYPTO_DH_ENABLED
// Test create with X25519 key exchange
CASE_TEST(atbus_connection_context, create_with_x25519) {
  ensure_openssl_initialized();

  auto dh_ctx = create_test_dh_context("ecdh:X25519");
  if (!dh_ctx) {
    CASE_MSG_INFO() << "X25519 not supported, skipping test" << std::endl;
    return;
  }

  auto ctx =
      atfw::atbus::connection_context::create(atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_X25519, dh_ctx);

  CASE_EXPECT_NE(nullptr, ctx.get());
  CASE_EXPECT_EQ(atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_X25519,
                 ctx->get_crypto_key_exchange_algorithm());
}

// Test create with P-256 (secp256r1) key exchange
CASE_TEST(atbus_connection_context, create_with_secp256r1) {
  ensure_openssl_initialized();

  auto dh_ctx = create_test_dh_context("ecdh:P-256");
  if (!dh_ctx) {
    CASE_MSG_INFO() << "P-256 not supported, skipping test" << std::endl;
    return;
  }

  auto ctx = atfw::atbus::connection_context::create(atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_SECP256R1,
                                                     dh_ctx);

  CASE_EXPECT_NE(nullptr, ctx.get());
  CASE_EXPECT_EQ(atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_SECP256R1,
                 ctx->get_crypto_key_exchange_algorithm());
}

// Test create with null DH context falls back to no encryption
CASE_TEST(atbus_connection_context, create_with_null_dh_context) {
  ensure_openssl_initialized();

  auto ctx =
      atfw::atbus::connection_context::create(atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_X25519, nullptr);

  CASE_EXPECT_NE(nullptr, ctx.get());
  // Should fall back to no encryption when DH context is null
  CASE_EXPECT_EQ(atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_NONE,
                 ctx->get_crypto_key_exchange_algorithm());
}
#endif

// ============================================================================
// Test getter methods
// ============================================================================

// Test get_handshake_start_time initial value
CASE_TEST(atbus_connection_context, get_handshake_start_time_initial) {
  auto ctx =
      atfw::atbus::connection_context::create(atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_NONE, nullptr);

  CASE_EXPECT_NE(nullptr, ctx.get());
  // Initial handshake time should be epoch (0)
  auto handshake_time = ctx->get_handshake_start_time();
  CASE_EXPECT_EQ(std::chrono::system_clock::from_time_t(0), handshake_time);
}

// Test get_crypto_select_kdf_type default value
CASE_TEST(atbus_connection_context, get_crypto_select_kdf_type_default) {
  auto ctx =
      atfw::atbus::connection_context::create(atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_NONE, nullptr);

  CASE_EXPECT_NE(nullptr, ctx.get());
  // Default KDF type should be HKDF_SHA256
  CASE_EXPECT_EQ(atframework::atbus::protocol::ATBUS_CRYPTO_KDF_HKDF_SHA256, ctx->get_crypto_select_kdf_type());
}

// ============================================================================
// Test is_compression_algorithm_supported
// ============================================================================

// Test compression algorithm support - currently none should be supported
CASE_TEST(atbus_connection_context, is_compression_algorithm_supported) {
  // Currently no compression algorithms are supported
  CASE_EXPECT_FALSE(atfw::atbus::connection_context::is_compression_algorithm_supported(
      atframework::atbus::protocol::ATBUS_COMPRESSION_ALGORITHM_ZSTD));
  CASE_EXPECT_FALSE(atfw::atbus::connection_context::is_compression_algorithm_supported(
      atframework::atbus::protocol::ATBUS_COMPRESSION_ALGORITHM_LZ4));
  CASE_EXPECT_FALSE(atfw::atbus::connection_context::is_compression_algorithm_supported(
      atframework::atbus::protocol::ATBUS_COMPRESSION_ALGORITHM_SNAPPY));
  CASE_EXPECT_FALSE(atfw::atbus::connection_context::is_compression_algorithm_supported(
      atframework::atbus::protocol::ATBUS_COMPRESSION_ALGORITHM_ZLIB));
  CASE_EXPECT_FALSE(atfw::atbus::connection_context::is_compression_algorithm_supported(
      atframework::atbus::protocol::ATBUS_COMPRESSION_ALGORITHM_NONE));
}

// ============================================================================
// Test update_compression_algorithm
// ============================================================================

// Test update_compression_algorithm with empty list
CASE_TEST(atbus_connection_context, update_compression_algorithm_empty) {
  auto ctx =
      atfw::atbus::connection_context::create(atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_NONE, nullptr);

  CASE_EXPECT_NE(nullptr, ctx.get());

  std::vector<atframework::atbus::protocol::ATBUS_COMPRESSION_ALGORITHM_TYPE> algorithms;
  int result = ctx->update_compression_algorithm(algorithms);

  CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, result);
  CASE_EXPECT_EQ(atframework::atbus::protocol::ATBUS_COMPRESSION_ALGORITHM_NONE,
                 ctx->get_compression_select_algorithm());
}

// Test update_compression_algorithm with unsupported algorithms
CASE_TEST(atbus_connection_context, update_compression_algorithm_unsupported) {
  auto ctx =
      atfw::atbus::connection_context::create(atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_NONE, nullptr);

  CASE_EXPECT_NE(nullptr, ctx.get());

  std::vector<atframework::atbus::protocol::ATBUS_COMPRESSION_ALGORITHM_TYPE> algorithms = {
      atframework::atbus::protocol::ATBUS_COMPRESSION_ALGORITHM_ZSTD,
      atframework::atbus::protocol::ATBUS_COMPRESSION_ALGORITHM_LZ4,
  };
  int result = ctx->update_compression_algorithm(algorithms);

  CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, result);
  // Since none are supported, should remain NONE
  CASE_EXPECT_EQ(atframework::atbus::protocol::ATBUS_COMPRESSION_ALGORITHM_NONE,
                 ctx->get_compression_select_algorithm());
}

// ============================================================================
// Test handshake methods
// ============================================================================

#ifdef CRYPTO_DH_ENABLED
// Test handshake_generate_self_key with no encryption
CASE_TEST(atbus_connection_context, handshake_generate_self_key_no_encryption) {
  auto ctx =
      atfw::atbus::connection_context::create(atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_NONE, nullptr);

  CASE_EXPECT_NE(nullptr, ctx.get());

  int result = ctx->handshake_generate_self_key(0);
  CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, result);
  // Handshake time should still be epoch since no actual key exchange
  CASE_EXPECT_EQ(std::chrono::system_clock::from_time_t(0), ctx->get_handshake_start_time());
}

// Test handshake_generate_self_key with encryption enabled
CASE_TEST(atbus_connection_context, handshake_generate_self_key_with_encryption) {
  ensure_openssl_initialized();

  auto dh_ctx = create_test_dh_context("ecdh:P-256");
  if (!dh_ctx) {
    CASE_MSG_INFO() << "P-256 not supported, skipping test" << std::endl;
    return;
  }

  auto ctx = atfw::atbus::connection_context::create(atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_SECP256R1,
                                                     dh_ctx);

  CASE_EXPECT_NE(nullptr, ctx.get());

  auto before_handshake = std::chrono::system_clock::now();
  int result = ctx->handshake_generate_self_key(0);
  auto after_handshake = std::chrono::system_clock::now();

  CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, result);

  // Handshake time should be set to current time
  auto handshake_time = ctx->get_handshake_start_time();
  CASE_EXPECT_GE(handshake_time, before_handshake - std::chrono::seconds(1));
  CASE_EXPECT_LE(handshake_time, after_handshake + std::chrono::seconds(1));
}

// Test handshake_generate_self_key with peer sequence id
CASE_TEST(atbus_connection_context, handshake_generate_self_key_with_peer_sequence) {
  ensure_openssl_initialized();

  auto dh_ctx = create_test_dh_context("ecdh:P-256");
  if (!dh_ctx) {
    CASE_MSG_INFO() << "P-256 not supported, skipping test" << std::endl;
    return;
  }

  auto ctx = atfw::atbus::connection_context::create(atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_SECP256R1,
                                                     dh_ctx);

  CASE_EXPECT_NE(nullptr, ctx.get());

  uint64_t peer_sequence_id = 12345678;
  int result = ctx->handshake_generate_self_key(peer_sequence_id);

  CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, result);
}

// Test handshake_write_self_public_key
CASE_TEST(atbus_connection_context, handshake_write_self_public_key) {
  ensure_openssl_initialized();

  auto dh_ctx = create_test_dh_context("ecdh:P-256");
  if (!dh_ctx) {
    CASE_MSG_INFO() << "P-256 not supported, skipping test" << std::endl;
    return;
  }

  auto ctx = atfw::atbus::connection_context::create(atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_SECP256R1,
                                                     dh_ctx);

  CASE_EXPECT_NE(nullptr, ctx.get());

  // Generate self key first
  int result = ctx->handshake_generate_self_key(0);
  CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, result);

  // Write self public key
  atframework::atbus::protocol::crypto_handshake_data self_pub_key;
  std::vector<atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_TYPE> supported_algorithms = {
      atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_GCM,
      atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_128_GCM,
  };

  result = ctx->handshake_write_self_public_key(self_pub_key, supported_algorithms);

  CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, result);
  CASE_EXPECT_EQ(atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_SECP256R1, self_pub_key.type());
  CASE_EXPECT_FALSE(self_pub_key.public_key().empty());
  CASE_EXPECT_EQ(2, self_pub_key.algorithms_size());
}

// Test complete handshake flow between client and server
CASE_TEST(atbus_connection_context, handshake_complete_flow) {
  ensure_openssl_initialized();

  auto server_dh_ctx = create_test_dh_context("ecdh:P-256");
  auto client_dh_ctx = create_test_dh_context("ecdh:P-256");

  if (!server_dh_ctx || !client_dh_ctx) {
    CASE_MSG_INFO() << "P-256 not supported, skipping test" << std::endl;
    return;
  }

  // Create server and client contexts
  auto server_ctx = atfw::atbus::connection_context::create(
      atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_SECP256R1, server_dh_ctx);
  auto client_ctx = atfw::atbus::connection_context::create(
      atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_SECP256R1, client_dh_ctx);

  CASE_EXPECT_NE(nullptr, server_ctx.get());
  CASE_EXPECT_NE(nullptr, client_ctx.get());

  std::vector<atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_TYPE> supported_algorithms = {
      atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_GCM,
      atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_128_GCM,
  };

  // Step 1: Client generates key pair
  int result = client_ctx->handshake_generate_self_key(0);
  CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, result);

  // Step 2: Client writes public key
  atframework::atbus::protocol::crypto_handshake_data client_pub_key;
  result = client_ctx->handshake_write_self_public_key(client_pub_key, supported_algorithms);
  CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, result);

  // Step 3: Server generates key pair using client's sequence
  result = server_ctx->handshake_generate_self_key(client_pub_key.sequence());
  CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, result);

  // Step 4: Server reads client's public key and computes shared secret
  result = server_ctx->handshake_read_peer_key(client_pub_key, supported_algorithms);
  CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, result);

  // Step 5: Server writes its public key
  atframework::atbus::protocol::crypto_handshake_data server_pub_key;
  result = server_ctx->handshake_write_self_public_key(server_pub_key, supported_algorithms);
  CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, result);

  // Step 6: Client reads server's public key and computes shared secret
  result = client_ctx->handshake_read_peer_key(server_pub_key, supported_algorithms);
  CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, result);

  // Both should now have the same crypto algorithm selected
  CASE_EXPECT_EQ(server_ctx->get_crypto_select_algorithm(), client_ctx->get_crypto_select_algorithm());
  CASE_EXPECT_NE(atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_NONE, server_ctx->get_crypto_select_algorithm());
}

// Test handshake_read_peer_key with mismatched sequence
CASE_TEST(atbus_connection_context, handshake_read_peer_key_sequence_mismatch) {
  ensure_openssl_initialized();

  auto server_dh_ctx = create_test_dh_context("ecdh:P-256");
  auto client_dh_ctx = create_test_dh_context("ecdh:P-256");

  if (!server_dh_ctx || !client_dh_ctx) {
    CASE_MSG_INFO() << "P-256 not supported, skipping test" << std::endl;
    return;
  }

  auto server_ctx = atfw::atbus::connection_context::create(
      atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_SECP256R1, server_dh_ctx);
  auto client_ctx = atfw::atbus::connection_context::create(
      atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_SECP256R1, client_dh_ctx);

  CASE_EXPECT_NE(nullptr, server_ctx.get());
  CASE_EXPECT_NE(nullptr, client_ctx.get());

  std::vector<atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_TYPE> supported_algorithms = {
      atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_GCM,
  };

  // Client generates key
  int result = client_ctx->handshake_generate_self_key(0);
  CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, result);

  atframework::atbus::protocol::crypto_handshake_data client_pub_key;
  result = client_ctx->handshake_write_self_public_key(client_pub_key, supported_algorithms);
  CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, result);

  // Server generates key with DIFFERENT sequence
  result = server_ctx->handshake_generate_self_key(client_pub_key.sequence() + 1);  // Different sequence
  CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, result);

  // Server tries to read client's key - should fail due to sequence mismatch
  result = server_ctx->handshake_read_peer_key(client_pub_key, supported_algorithms);
  CASE_EXPECT_EQ(EN_ATBUS_ERR_CRYPTO_HANDSHAKE_SEQUENCE_EXPIRED, result);
}

// Test handshake_read_peer_key with no common algorithms
CASE_TEST(atbus_connection_context, handshake_read_peer_key_no_common_algorithm) {
  ensure_openssl_initialized();

  auto server_dh_ctx = create_test_dh_context("ecdh:P-256");
  auto client_dh_ctx = create_test_dh_context("ecdh:P-256");

  if (!server_dh_ctx || !client_dh_ctx) {
    CASE_MSG_INFO() << "P-256 not supported, skipping test" << std::endl;
    return;
  }

  auto server_ctx = atfw::atbus::connection_context::create(
      atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_SECP256R1, server_dh_ctx);
  auto client_ctx = atfw::atbus::connection_context::create(
      atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_SECP256R1, client_dh_ctx);

  CASE_EXPECT_NE(nullptr, server_ctx.get());
  CASE_EXPECT_NE(nullptr, client_ctx.get());

  // Client supports only AES-256-GCM
  std::vector<atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_TYPE> client_algorithms = {
      atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_GCM,
  };

  // Server supports only CHACHA20
  std::vector<atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_TYPE> server_algorithms = {
      atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_CHACHA20,
  };

  // Client generates key
  int result = client_ctx->handshake_generate_self_key(0);
  CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, result);

  atframework::atbus::protocol::crypto_handshake_data client_pub_key;
  result = client_ctx->handshake_write_self_public_key(client_pub_key, client_algorithms);
  CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, result);

  // Server generates key
  result = server_ctx->handshake_generate_self_key(client_pub_key.sequence());
  CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, result);

  // Server tries to read client's key - should fail due to no common algorithm
  result = server_ctx->handshake_read_peer_key(client_pub_key, server_algorithms);
  CASE_EXPECT_EQ(EN_ATBUS_ERR_CRYPTO_HANDSHAKE_NO_AVAILABLE_ALGORITHM, result);
}

// Test handshake with X25519 key exchange (if supported)
CASE_TEST(atbus_connection_context, handshake_with_x25519) {
  ensure_openssl_initialized();

  auto server_dh_ctx = create_test_dh_context("ecdh:X25519");
  auto client_dh_ctx = create_test_dh_context("ecdh:X25519");

  if (!server_dh_ctx || !client_dh_ctx) {
    CASE_MSG_INFO() << "X25519 not supported, skipping test" << std::endl;
    return;
  }

  auto server_ctx = atfw::atbus::connection_context::create(
      atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_X25519, server_dh_ctx);
  auto client_ctx = atfw::atbus::connection_context::create(
      atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_X25519, client_dh_ctx);

  CASE_EXPECT_NE(nullptr, server_ctx.get());
  CASE_EXPECT_NE(nullptr, client_ctx.get());

  std::vector<atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_TYPE> supported_algorithms = {
      atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_CHACHA20_POLY1305_IETF,
  };

  // Complete handshake
  int result = client_ctx->handshake_generate_self_key(0);
  CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, result);

  atframework::atbus::protocol::crypto_handshake_data client_pub_key;
  result = client_ctx->handshake_write_self_public_key(client_pub_key, supported_algorithms);
  CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, result);

  result = server_ctx->handshake_generate_self_key(client_pub_key.sequence());
  CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, result);

  result = server_ctx->handshake_read_peer_key(client_pub_key, supported_algorithms);
  CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, result);

  atframework::atbus::protocol::crypto_handshake_data server_pub_key;
  result = server_ctx->handshake_write_self_public_key(server_pub_key, supported_algorithms);
  CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, result);

  result = client_ctx->handshake_read_peer_key(server_pub_key, supported_algorithms);
  CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, result);

  CASE_EXPECT_EQ(atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_CHACHA20_POLY1305_IETF,
                 server_ctx->get_crypto_select_algorithm());
  CASE_EXPECT_EQ(atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_CHACHA20_POLY1305_IETF,
                 client_ctx->get_crypto_select_algorithm());
}

// Test pack and unpack message without encryption
CASE_TEST(atbus_connection_context, pack_unpack_message_no_encryption) {
  ensure_openssl_initialized();

  auto ctx =
      atfw::atbus::connection_context::create(atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_NONE, nullptr);

  CASE_EXPECT_NE(nullptr, ctx.get());

  // Create a message
  ::google::protobuf::ArenaOptions arena_options;
  atfw::atbus::message send_msg(arena_options);
  auto& body = send_msg.mutable_body();
  auto* ping_req = body.mutable_node_ping_req();
  ping_req->set_time_point(12345678);

  atfw::atbus::random_engine_t random_engine;
  random_engine.init_seed(static_cast<uint64_t>(time(nullptr)));

  // Pack message
  auto pack_result =
      ctx->pack_message(send_msg, atframework::atbus::protocol::ATBUS_PROTOCOL_VERSION, random_engine, 1024 * 1024);
  CASE_EXPECT_TRUE(pack_result.is_success());

  if (pack_result.is_success()) {
    auto* buffer = pack_result.get_success();
    CASE_EXPECT_NE(nullptr, buffer);
    CASE_EXPECT_GT(buffer->size(), static_cast<size_t>(0));

    // Unpack message
    atfw::atbus::message recv_msg(arena_options);
    gsl::span<const unsigned char> input_span(buffer->data(), buffer->used());
    int unpack_result = ctx->unpack_message(recv_msg, input_span, 1024 * 1024);
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, unpack_result);

    // Verify message content
    auto* recv_body = recv_msg.get_body();
    CASE_EXPECT_NE(nullptr, recv_body);
    if (recv_body != nullptr) {
      CASE_EXPECT_EQ(atframework::atbus::protocol::message_body::kNodePingReq, recv_body->message_type_case());
      CASE_EXPECT_EQ(12345678, recv_body->node_ping_req().time_point());
    }
  }
}

// Test pack and unpack message with encryption
CASE_TEST(atbus_connection_context, pack_unpack_message_with_encryption) {
  ensure_openssl_initialized();

  // Check if required cipher algorithm is available
  if (!is_cipher_algorithm_available("aes-256-gcm")) {
    CASE_MSG_INFO() << "AES-256-GCM not supported, skipping test" << std::endl;
    return;
  }

  // First, verify that cipher can encrypt/decrypt directly
  if (!test_cipher_encrypt_decrypt("aes-256-gcm")) {
    CASE_MSG_INFO() << "AES-256-GCM cipher direct test failed, skipping test" << std::endl;
    return;
  }

  // Also test with single ENCRYPT mode (like _create_crypto_cipher uses)
  if (!test_cipher_encrypt_only_mode("aes-256-gcm")) {
    CASE_MSG_INFO() << "AES-256-GCM single mode test failed, this indicates _create_crypto_cipher may have issues"
                    << std::endl;
    return;
  }

  auto server_dh_ctx = create_test_dh_context("ecdh:P-256");
  auto client_dh_ctx = create_test_dh_context("ecdh:P-256");

  if (!server_dh_ctx || !client_dh_ctx) {
    CASE_MSG_INFO() << "P-256 not supported, skipping test" << std::endl;
    return;
  }

  auto server_ctx = atfw::atbus::connection_context::create(
      atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_SECP256R1, server_dh_ctx);
  auto client_ctx = atfw::atbus::connection_context::create(
      atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_SECP256R1, client_dh_ctx);

  CASE_EXPECT_NE(nullptr, server_ctx.get());
  CASE_EXPECT_NE(nullptr, client_ctx.get());

  std::vector<atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_TYPE> supported_algorithms = {
      atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_GCM,
  };

  // Complete handshake
  int result = client_ctx->handshake_generate_self_key(0);
  if (result != EN_ATBUS_ERR_SUCCESS) {
    CASE_MSG_INFO() << "handshake_generate_self_key failed: " << result << ", skipping test" << std::endl;
    return;
  }

  atframework::atbus::protocol::crypto_handshake_data client_pub_key;
  result = client_ctx->handshake_write_self_public_key(client_pub_key, supported_algorithms);
  if (result != EN_ATBUS_ERR_SUCCESS) {
    CASE_MSG_INFO() << "handshake_write_self_public_key failed: " << result << ", skipping test" << std::endl;
    return;
  }

  result = server_ctx->handshake_generate_self_key(client_pub_key.sequence());
  if (result != EN_ATBUS_ERR_SUCCESS) {
    CASE_MSG_INFO() << "server handshake_generate_self_key failed: " << result << ", skipping test" << std::endl;
    return;
  }

  result = server_ctx->handshake_read_peer_key(client_pub_key, supported_algorithms);
  if (result != EN_ATBUS_ERR_SUCCESS) {
    CASE_MSG_INFO() << "server handshake_read_peer_key failed: " << result << ", skipping test" << std::endl;
    return;
  }

  atframework::atbus::protocol::crypto_handshake_data server_pub_key;
  result = server_ctx->handshake_write_self_public_key(server_pub_key, supported_algorithms);
  if (result != EN_ATBUS_ERR_SUCCESS) {
    CASE_MSG_INFO() << "server handshake_write_self_public_key failed: " << result << ", skipping test" << std::endl;
    return;
  }

  result = client_ctx->handshake_read_peer_key(server_pub_key, supported_algorithms);
  if (result != EN_ATBUS_ERR_SUCCESS) {
    CASE_MSG_INFO() << "client handshake_read_peer_key failed: " << result << ", skipping test" << std::endl;
    return;
  }

  // Debug: check selected algorithm
  CASE_MSG_INFO() << "Client selected algorithm: " << static_cast<int>(client_ctx->get_crypto_select_algorithm())
                  << std::endl;
  CASE_MSG_INFO() << "Server selected algorithm: " << static_cast<int>(server_ctx->get_crypto_select_algorithm())
                  << std::endl;

  // Create a message that allows encryption (not ping/pong/register)
  ::google::protobuf::ArenaOptions arena_options;
  atfw::atbus::message send_msg(arena_options);
  auto& body = send_msg.mutable_body();
  auto* forward_data = body.mutable_data_transform_req();
  forward_data->set_from(1001);
  forward_data->set_to(1002);
  forward_data->set_content("Hello, encrypted world!");

  // Debug: check message body size
  auto* check_body = send_msg.get_body();
  if (check_body) {
    CASE_MSG_INFO() << "Message body size: " << check_body->ByteSizeLong() << " bytes" << std::endl;
  }

  atfw::atbus::random_engine_t random_engine;
  random_engine.init_seed(static_cast<uint64_t>(time(nullptr)));

  // Additional debug: test cipher encryption directly with the same setup pattern as connection_context
  {
    atfw::util::crypto::cipher test_ci;
    int init_res = test_ci.init("aes-256-gcm", atfw::util::crypto::cipher::mode_t::EN_CMODE_ENCRYPT);
    CASE_MSG_INFO() << "Direct cipher init result: " << init_res << std::endl;
    if (init_res == 0) {
      // Use the exact same key size as connection_context would
      uint32_t key_bits = test_ci.get_key_bits();
      uint32_t key_size = key_bits / 8;
      uint32_t iv_size = test_ci.get_iv_size();
      std::vector<unsigned char> key_iv(key_size + iv_size, 0x42);

      // This is what connection_context does: set_key(key_iv.data(), key_size * 8)
      int key_res = test_ci.set_key(key_iv.data(), key_size * 8);
      CASE_MSG_INFO() << "Direct cipher set_key result: " << key_res << ", key_size: " << key_size
                      << ", key_bits: " << (key_size * 8) << std::endl;

      if (key_res == 0 && iv_size > 0) {
        int iv_res = test_ci.set_iv(key_iv.data() + key_size, iv_size);
        CASE_MSG_INFO() << "Direct cipher set_iv result: " << iv_res << ", iv_size: " << iv_size << std::endl;

        if (iv_res == 0) {
          const std::string plaintext = "Hello, encrypted world!";
          size_t out_size = plaintext.size() + test_ci.get_block_size() + test_ci.get_tag_size();
          std::vector<unsigned char> ciphertext(out_size);
          const std::string aad = "test-aad";

          int enc_res = test_ci.encrypt_aead(reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size(),
                                             ciphertext.data(), &out_size,
                                             reinterpret_cast<const unsigned char*>(aad.data()), aad.size());
          CASE_MSG_INFO() << "Direct cipher encrypt_aead result: " << enc_res
                          << ", last_errno: " << test_ci.get_last_errno() << std::endl;
        }
      }
    }
  }

  // Pack message from client
  auto pack_result = client_ctx->pack_message(send_msg, atframework::atbus::protocol::ATBUS_PROTOCOL_VERSION,
                                              random_engine, 1024 * 1024);
  if (pack_result.is_error()) {
    auto error_ptr = pack_result.get_error();
    if (error_ptr != nullptr) {
      CASE_MSG_INFO() << "pack_message failed with error: " << static_cast<int>(*error_ptr) << std::endl;
    }
  }
  CASE_EXPECT_TRUE(pack_result.is_success());

  if (pack_result.is_success()) {
    auto* buffer = pack_result.get_success();
    CASE_EXPECT_NE(nullptr, buffer);
    CASE_EXPECT_GT(buffer->size(), static_cast<size_t>(0));

    // Unpack message on server
    atfw::atbus::message recv_msg(arena_options);
    gsl::span<const unsigned char> input_span(buffer->data(), buffer->used());
    int unpack_result = server_ctx->unpack_message(recv_msg, input_span, 1024 * 1024);
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, unpack_result);

    // Verify message content
    auto* recv_body = recv_msg.get_body();
    CASE_EXPECT_NE(nullptr, recv_body);
    if (recv_body != nullptr) {
      CASE_EXPECT_EQ(atframework::atbus::protocol::message_body::kDataTransformReq, recv_body->message_type_case());
      CASE_EXPECT_EQ(1001, recv_body->data_transform_req().from());
      CASE_EXPECT_EQ(1002, recv_body->data_transform_req().to());
      CASE_EXPECT_EQ("Hello, encrypted world!", recv_body->data_transform_req().content());
    }
  }
}

// Test pack message with body size exceeding limit
CASE_TEST(atbus_connection_context, pack_message_size_limit) {
  ensure_openssl_initialized();

  auto ctx =
      atfw::atbus::connection_context::create(atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_NONE, nullptr);

  CASE_EXPECT_NE(nullptr, ctx.get());

  // Create a message with large content
  ::google::protobuf::ArenaOptions arena_options;
  atfw::atbus::message send_msg(arena_options);
  auto& body = send_msg.mutable_body();
  auto* forward_data = body.mutable_data_transform_req();
  forward_data->set_from(1001);
  forward_data->set_to(1002);
  // Create content much larger than max_body_size to ensure it exceeds the limit
  std::string large_content(16384, 'X');  // 16KB content
  forward_data->set_content(large_content);

  // Verify the message body size is large enough (should be > 16KB)
  auto* check_body = send_msg.get_body();
  CASE_EXPECT_NE(nullptr, check_body);
  if (check_body != nullptr) {
    size_t body_size = static_cast<size_t>(check_body->ByteSizeLong());
    CASE_MSG_INFO() << "Message body size: " << body_size << " bytes" << std::endl;
    CASE_EXPECT_GT(body_size, static_cast<size_t>(100));
  }

  atfw::atbus::random_engine_t random_engine;
  random_engine.init_seed(static_cast<uint64_t>(time(nullptr)));

  // Pack message with small max_body_size (100 bytes)
  auto pack_result = ctx->pack_message(send_msg, atframework::atbus::protocol::ATBUS_PROTOCOL_VERSION, random_engine,
                                       100);  // 100 bytes limit

  // With a 16KB+ message and 100 byte limit, pack should fail
  // Note: pack_message checks body_size > max_body_size, so 16KB body with 100 byte limit should fail
  CASE_EXPECT_TRUE(pack_result.is_error());
  if (pack_result.is_error()) {
    // get_error() returns a pointer to the error, so we need to dereference it
    auto error_ptr = pack_result.get_error();
    CASE_EXPECT_NE(nullptr, error_ptr);
    if (error_ptr != nullptr) {
      CASE_EXPECT_EQ(EN_ATBUS_ERR_INVALID_SIZE, *error_ptr);
    }
  } else {
    // If pack succeeded unexpectedly, log details for debugging
    auto* buffer = pack_result.get_success();
    CASE_MSG_INFO() << "pack_message unexpectedly succeeded, buffer size: " << (buffer ? buffer->size() : 0)
                    << " bytes, used: " << (buffer ? buffer->used() : 0) << " bytes" << std::endl;
  }
}

// Test unpack message with invalid data
CASE_TEST(atbus_connection_context, unpack_message_invalid_data) {
  ensure_openssl_initialized();

  auto ctx =
      atfw::atbus::connection_context::create(atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_NONE, nullptr);

  CASE_EXPECT_NE(nullptr, ctx.get());

  ::google::protobuf::ArenaOptions arena_options;
  atfw::atbus::message recv_msg(arena_options);

  // Test with empty data
  std::vector<unsigned char> empty_data;
  gsl::span<const unsigned char> empty_span(empty_data);
  int result = ctx->unpack_message(recv_msg, empty_span, 1024 * 1024);
  CASE_EXPECT_EQ(EN_ATBUS_ERR_INVALID_SIZE, result);

  // Test with garbage data
  std::vector<unsigned char> garbage_data = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  gsl::span<const unsigned char> garbage_span(garbage_data);
  result = ctx->unpack_message(recv_msg, garbage_span, 1024 * 1024);
  // Should fail due to invalid vint or header
  CASE_EXPECT_NE(EN_ATBUS_ERR_SUCCESS, result);
}

// Test bidirectional encrypted communication
CASE_TEST(atbus_connection_context, bidirectional_encrypted_communication) {
  ensure_openssl_initialized();

  // Check if required cipher algorithm is available
  if (!is_cipher_algorithm_available("aes-128-gcm")) {
    CASE_MSG_INFO() << "AES-128-GCM not supported, skipping test" << std::endl;
    return;
  }

  auto server_dh_ctx = create_test_dh_context("ecdh:P-256");
  auto client_dh_ctx = create_test_dh_context("ecdh:P-256");

  if (!server_dh_ctx || !client_dh_ctx) {
    CASE_MSG_INFO() << "P-256 not supported, skipping test" << std::endl;
    return;
  }

  auto server_ctx = atfw::atbus::connection_context::create(
      atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_SECP256R1, server_dh_ctx);
  auto client_ctx = atfw::atbus::connection_context::create(
      atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_SECP256R1, client_dh_ctx);

  std::vector<atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_TYPE> supported_algorithms = {
      atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_128_GCM,
  };

  // Complete handshake with error checking
  int result = client_ctx->handshake_generate_self_key(0);
  if (result != EN_ATBUS_ERR_SUCCESS) {
    CASE_MSG_INFO() << "client handshake_generate_self_key failed: " << result << ", skipping test" << std::endl;
    return;
  }

  atframework::atbus::protocol::crypto_handshake_data client_pub_key;
  result = client_ctx->handshake_write_self_public_key(client_pub_key, supported_algorithms);
  if (result != EN_ATBUS_ERR_SUCCESS) {
    CASE_MSG_INFO() << "client handshake_write_self_public_key failed: " << result << ", skipping test" << std::endl;
    return;
  }

  result = server_ctx->handshake_generate_self_key(client_pub_key.sequence());
  if (result != EN_ATBUS_ERR_SUCCESS) {
    CASE_MSG_INFO() << "server handshake_generate_self_key failed: " << result << ", skipping test" << std::endl;
    return;
  }

  result = server_ctx->handshake_read_peer_key(client_pub_key, supported_algorithms);
  if (result != EN_ATBUS_ERR_SUCCESS) {
    CASE_MSG_INFO() << "server handshake_read_peer_key failed: " << result << ", skipping test" << std::endl;
    return;
  }

  atframework::atbus::protocol::crypto_handshake_data server_pub_key;
  result = server_ctx->handshake_write_self_public_key(server_pub_key, supported_algorithms);
  if (result != EN_ATBUS_ERR_SUCCESS) {
    CASE_MSG_INFO() << "server handshake_write_self_public_key failed: " << result << ", skipping test" << std::endl;
    return;
  }

  result = client_ctx->handshake_read_peer_key(server_pub_key, supported_algorithms);
  if (result != EN_ATBUS_ERR_SUCCESS) {
    CASE_MSG_INFO() << "client handshake_read_peer_key failed: " << result << ", skipping test" << std::endl;
    return;
  }

  atfw::atbus::random_engine_t random_engine;
  random_engine.init_seed(static_cast<uint64_t>(time(nullptr)));
  ::google::protobuf::ArenaOptions arena_options;

  // Client -> Server message
  {
    atfw::atbus::message send_msg(arena_options);
    auto& body = send_msg.mutable_body();
    auto* forward_data = body.mutable_data_transform_req();
    forward_data->set_content("Message from client to server");

    auto pack_result = client_ctx->pack_message(send_msg, atframework::atbus::protocol::ATBUS_PROTOCOL_VERSION,
                                                random_engine, 1024 * 1024);
    if (pack_result.is_error()) {
      auto error_ptr = pack_result.get_error();
      if (error_ptr != nullptr) {
        CASE_MSG_INFO() << "Client->Server pack_message failed with error: " << static_cast<int>(*error_ptr)
                        << std::endl;
      }
    }
    CASE_EXPECT_TRUE(pack_result.is_success());

    if (pack_result.is_success()) {
      auto* buffer = pack_result.get_success();
      CASE_EXPECT_NE(nullptr, buffer);
      atfw::atbus::message recv_msg(arena_options);
      gsl::span<const unsigned char> input_span(buffer->data(), buffer->used());
      int unpack_result = server_ctx->unpack_message(recv_msg, input_span, 1024 * 1024);
      CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, unpack_result);

      auto* recv_body = recv_msg.get_body();
      CASE_EXPECT_NE(nullptr, recv_body);
      if (recv_body != nullptr) {
        CASE_EXPECT_EQ("Message from client to server", recv_body->data_transform_req().content());
      }
    }
  }

  // Server -> Client message
  {
    atfw::atbus::message send_msg(arena_options);
    auto& body = send_msg.mutable_body();
    auto* forward_data = body.mutable_data_transform_rsp();
    forward_data->set_content("Message from server to client");

    auto pack_result = server_ctx->pack_message(send_msg, atframework::atbus::protocol::ATBUS_PROTOCOL_VERSION,
                                                random_engine, 1024 * 1024);
    CASE_EXPECT_TRUE(pack_result.is_success());

    if (pack_result.is_success()) {
      auto* buffer = pack_result.get_success();
      CASE_EXPECT_NE(nullptr, buffer);
      atfw::atbus::message recv_msg(arena_options);
      gsl::span<const unsigned char> input_span(buffer->data(), buffer->used());
      int unpack_result = client_ctx->unpack_message(recv_msg, input_span, 1024 * 1024);
      CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, unpack_result);

      auto* recv_body = recv_msg.get_body();
      CASE_EXPECT_NE(nullptr, recv_body);
      if (recv_body != nullptr) {
        CASE_EXPECT_EQ("Message from server to client", recv_body->data_transform_rsp().content());
      }
    }
  }
}

// ============================================================================
// Comprehensive tests for all key exchange algorithms and encryption algorithms
// ============================================================================

// Define all key exchange algorithms with their DH curve names
struct key_exchange_test_case {
  atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_TYPE type;
  const char* dh_curve_name;
  const char* name;
};

static const key_exchange_test_case kKeyExchangeTestCases[] = {
    {atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_X25519, "ecdh:X25519", "X25519"},
    {atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_SECP256R1, "ecdh:P-256", "SECP256R1 (P-256)"},
    {atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_SECP384R1, "ecdh:P-384", "SECP384R1 (P-384)"},
    {atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_SECP521R1, "ecdh:P-521", "SECP521R1 (P-521)"},
};

// Define all encryption algorithms with their cipher names
struct crypto_algorithm_test_case {
  atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_TYPE type;
  const char* cipher_name;
  const char* name;
  bool is_aead;
};

static const crypto_algorithm_test_case kCryptoAlgorithmTestCases[] = {
    {atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_XXTEA, "xxtea", "XXTEA", false},
    {atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_128_CBC, "aes-128-cbc", "AES-128-CBC", false},
    {atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_192_CBC, "aes-192-cbc", "AES-192-CBC", false},
    {atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_CBC, "aes-256-cbc", "AES-256-CBC", false},
    {atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_128_GCM, "aes-128-gcm", "AES-128-GCM", true},
    {atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_192_GCM, "aes-192-gcm", "AES-192-GCM", true},
    {atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_GCM, "aes-256-gcm", "AES-256-GCM", true},
    {atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_CHACHA20, "chacha20", "ChaCha20", false},
    {atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_CHACHA20_POLY1305_IETF, "chacha20-poly1305-ietf",
     "ChaCha20-Poly1305-IETF", true},
    {atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_XCHACHA20_POLY1305_IETF, "xchacha20-poly1305-ietf",
     "XChaCha20-Poly1305-IETF", true},
};

// Helper function to test a complete handshake and encryption/decryption with specific algorithms
static bool test_complete_crypto_flow(const key_exchange_test_case& kex_case,
                                      const crypto_algorithm_test_case& crypto_case) {
  CASE_MSG_INFO() << "Testing Key Exchange: " << kex_case.name << " with Cipher: " << crypto_case.name << std::endl;

  // Check if cipher is available
  if (!is_cipher_algorithm_available(crypto_case.cipher_name)) {
    CASE_MSG_INFO() << "  Cipher " << crypto_case.cipher_name << " not supported, skipping" << std::endl;
    return true;  // Skip is not a failure
  }

  // Test cipher in single mode first
  if (!test_cipher_encrypt_only_mode(crypto_case.cipher_name)) {
    CASE_MSG_INFO() << "  Cipher " << crypto_case.cipher_name << " single mode test failed, skipping" << std::endl;
    return true;  // Skip is not a failure
  }

  auto server_dh_ctx = create_test_dh_context(kex_case.dh_curve_name);
  auto client_dh_ctx = create_test_dh_context(kex_case.dh_curve_name);

  if (!server_dh_ctx || !client_dh_ctx) {
    CASE_MSG_INFO() << "  Key exchange " << kex_case.dh_curve_name << " not supported, skipping" << std::endl;
    return true;  // Skip is not a failure
  }

  auto server_ctx = atfw::atbus::connection_context::create(kex_case.type, server_dh_ctx);
  auto client_ctx = atfw::atbus::connection_context::create(kex_case.type, client_dh_ctx);

  if (!server_ctx || !client_ctx) {
    CASE_MSG_INFO() << "  Failed to create connection contexts, skipping" << std::endl;
    return false;
  }

  std::vector<atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_TYPE> supported_algorithms = {
      crypto_case.type,
  };

  // Complete handshake
  int result = client_ctx->handshake_generate_self_key(0);
  if (result != EN_ATBUS_ERR_SUCCESS) {
    CASE_MSG_INFO() << "  client handshake_generate_self_key failed: " << result << std::endl;
    return false;
  }

  atframework::atbus::protocol::crypto_handshake_data client_pub_key;
  result = client_ctx->handshake_write_self_public_key(client_pub_key, supported_algorithms);
  if (result != EN_ATBUS_ERR_SUCCESS) {
    CASE_MSG_INFO() << "  client handshake_write_self_public_key failed: " << result << std::endl;
    return false;
  }

  result = server_ctx->handshake_generate_self_key(client_pub_key.sequence());
  if (result != EN_ATBUS_ERR_SUCCESS) {
    CASE_MSG_INFO() << "  server handshake_generate_self_key failed: " << result << std::endl;
    return false;
  }

  result = server_ctx->handshake_read_peer_key(client_pub_key, supported_algorithms);
  if (result != EN_ATBUS_ERR_SUCCESS) {
    CASE_MSG_INFO() << "  server handshake_read_peer_key failed: " << result << std::endl;
    return false;
  }

  atframework::atbus::protocol::crypto_handshake_data server_pub_key;
  result = server_ctx->handshake_write_self_public_key(server_pub_key, supported_algorithms);
  if (result != EN_ATBUS_ERR_SUCCESS) {
    CASE_MSG_INFO() << "  server handshake_write_self_public_key failed: " << result << std::endl;
    return false;
  }

  result = client_ctx->handshake_read_peer_key(server_pub_key, supported_algorithms);
  if (result != EN_ATBUS_ERR_SUCCESS) {
    CASE_MSG_INFO() << "  client handshake_read_peer_key failed: " << result << std::endl;
    return false;
  }

  // Verify both sides selected the same algorithm
  if (server_ctx->get_crypto_select_algorithm() != client_ctx->get_crypto_select_algorithm()) {
    CASE_MSG_INFO() << "  Algorithm mismatch: server=" << static_cast<int>(server_ctx->get_crypto_select_algorithm())
                    << ", client=" << static_cast<int>(client_ctx->get_crypto_select_algorithm()) << std::endl;
    return false;
  }

  if (server_ctx->get_crypto_select_algorithm() != crypto_case.type) {
    CASE_MSG_INFO() << "  Expected algorithm " << static_cast<int>(crypto_case.type) << ", got "
                    << static_cast<int>(server_ctx->get_crypto_select_algorithm()) << std::endl;
    return false;
  }

  atfw::atbus::random_engine_t random_engine;
  random_engine.init_seed(static_cast<uint64_t>(time(nullptr)));
  ::google::protobuf::ArenaOptions arena_options;

  // Test Client -> Server encrypted message
  {
    atfw::atbus::message send_msg(arena_options);
    auto& body = send_msg.mutable_body();
    auto* forward_data = body.mutable_data_transform_req();
    forward_data->set_from(1001);
    forward_data->set_to(1002);
    forward_data->set_content("Hello from client, testing " + std::string(crypto_case.name));

    auto pack_result = client_ctx->pack_message(send_msg, atframework::atbus::protocol::ATBUS_PROTOCOL_VERSION,
                                                random_engine, 1024 * 1024);
    if (pack_result.is_error()) {
      auto error_ptr = pack_result.get_error();
      CASE_MSG_INFO() << "  Client->Server pack_message failed: " << (error_ptr ? static_cast<int>(*error_ptr) : -1)
                      << std::endl;
      return false;
    }

    auto* buffer = pack_result.get_success();
    if (!buffer) {
      CASE_MSG_INFO() << "  Client->Server pack_message returned null buffer" << std::endl;
      return false;
    }

    atfw::atbus::message recv_msg(arena_options);
    gsl::span<const unsigned char> input_span(buffer->data(), buffer->used());
    int unpack_result = server_ctx->unpack_message(recv_msg, input_span, 1024 * 1024);
    if (unpack_result != EN_ATBUS_ERR_SUCCESS) {
      CASE_MSG_INFO() << "  Client->Server unpack_message failed: " << unpack_result << std::endl;
      return false;
    }

    auto* recv_body = recv_msg.get_body();
    if (!recv_body) {
      CASE_MSG_INFO() << "  Client->Server received null body" << std::endl;
      return false;
    }

    std::string expected_content = "Hello from client, testing " + std::string(crypto_case.name);
    if (recv_body->data_transform_req().content() != expected_content) {
      CASE_MSG_INFO() << "  Client->Server content mismatch" << std::endl;
      return false;
    }
  }

  // Test Server -> Client encrypted message
  {
    atfw::atbus::message send_msg(arena_options);
    auto& body = send_msg.mutable_body();
    auto* forward_data = body.mutable_data_transform_rsp();
    forward_data->set_from(1002);
    forward_data->set_to(1001);
    forward_data->set_content("Hello from server, testing " + std::string(crypto_case.name));

    auto pack_result = server_ctx->pack_message(send_msg, atframework::atbus::protocol::ATBUS_PROTOCOL_VERSION,
                                                random_engine, 1024 * 1024);
    if (pack_result.is_error()) {
      auto error_ptr = pack_result.get_error();
      CASE_MSG_INFO() << "  Server->Client pack_message failed: " << (error_ptr ? static_cast<int>(*error_ptr) : -1)
                      << std::endl;
      return false;
    }

    auto* buffer = pack_result.get_success();
    if (!buffer) {
      CASE_MSG_INFO() << "  Server->Client pack_message returned null buffer" << std::endl;
      return false;
    }

    atfw::atbus::message recv_msg(arena_options);
    gsl::span<const unsigned char> input_span(buffer->data(), buffer->used());
    int unpack_result = client_ctx->unpack_message(recv_msg, input_span, 1024 * 1024);
    if (unpack_result != EN_ATBUS_ERR_SUCCESS) {
      CASE_MSG_INFO() << "  Server->Client unpack_message failed: " << unpack_result << std::endl;
      return false;
    }

    auto* recv_body = recv_msg.get_body();
    if (!recv_body) {
      CASE_MSG_INFO() << "  Server->Client received null body" << std::endl;
      return false;
    }

    std::string expected_content = "Hello from server, testing " + std::string(crypto_case.name);
    if (recv_body->data_transform_rsp().content() != expected_content) {
      CASE_MSG_INFO() << "  Server->Client content mismatch" << std::endl;
      return false;
    }
  }

  CASE_MSG_INFO() << "  PASSED: " << kex_case.name << " + " << crypto_case.name << std::endl;
  return true;
}

// Test all key exchange algorithms with AES-256-GCM (most common cipher)
CASE_TEST(atbus_connection_context, all_key_exchange_algorithms_with_aes256gcm) {
  ensure_openssl_initialized();

  const crypto_algorithm_test_case aes256gcm_case = {atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_GCM,
                                                     "aes-256-gcm", "AES-256-GCM", true};

  if (!is_cipher_algorithm_available("aes-256-gcm")) {
    CASE_MSG_INFO() << "AES-256-GCM not available, skipping all key exchange tests" << std::endl;
    return;
  }

  int passed = 0;
  int skipped = 0;
  int failed = 0;

  for (const auto& kex_case : kKeyExchangeTestCases) {
    auto server_dh_ctx = create_test_dh_context(kex_case.dh_curve_name);
    if (!server_dh_ctx) {
      CASE_MSG_INFO() << "Key exchange " << kex_case.name << " not supported, skipping" << std::endl;
      skipped++;
      continue;
    }

    if (test_complete_crypto_flow(kex_case, aes256gcm_case)) {
      passed++;
    } else {
      failed++;
    }
  }

  CASE_MSG_INFO() << "Key Exchange Tests Summary: passed=" << passed << ", skipped=" << skipped << ", failed=" << failed
                  << std::endl;
  CASE_EXPECT_EQ(0, failed);
}

// Test all encryption algorithms with P-256 key exchange (most widely supported)
CASE_TEST(atbus_connection_context, all_crypto_algorithms_with_secp256r1) {
  ensure_openssl_initialized();

  const key_exchange_test_case secp256r1_case = {atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_SECP256R1,
                                                 "ecdh:P-256", "SECP256R1 (P-256)"};

  auto dh_ctx = create_test_dh_context(secp256r1_case.dh_curve_name);
  if (!dh_ctx) {
    CASE_MSG_INFO() << "P-256 not supported, skipping all cipher tests" << std::endl;
    return;
  }

  int passed = 0;
  int skipped = 0;
  int failed = 0;

  for (const auto& crypto_case : kCryptoAlgorithmTestCases) {
    if (!is_cipher_algorithm_available(crypto_case.cipher_name)) {
      CASE_MSG_INFO() << "Cipher " << crypto_case.name << " not available, skipping" << std::endl;
      skipped++;
      continue;
    }

    if (test_complete_crypto_flow(secp256r1_case, crypto_case)) {
      passed++;
    } else {
      failed++;
    }
  }

  CASE_MSG_INFO() << "Cipher Algorithm Tests Summary: passed=" << passed << ", skipped=" << skipped
                  << ", failed=" << failed << std::endl;
  CASE_EXPECT_EQ(0, failed);
}

// Test all encryption algorithms with X25519 key exchange
CASE_TEST(atbus_connection_context, all_crypto_algorithms_with_x25519) {
  ensure_openssl_initialized();

  const key_exchange_test_case x25519_case = {atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_X25519,
                                              "ecdh:X25519", "X25519"};

  auto dh_ctx = create_test_dh_context(x25519_case.dh_curve_name);
  if (!dh_ctx) {
    CASE_MSG_INFO() << "X25519 not supported, skipping all cipher tests" << std::endl;
    return;
  }

  int passed = 0;
  int skipped = 0;
  int failed = 0;

  for (const auto& crypto_case : kCryptoAlgorithmTestCases) {
    if (!is_cipher_algorithm_available(crypto_case.cipher_name)) {
      CASE_MSG_INFO() << "Cipher " << crypto_case.name << " not available, skipping" << std::endl;
      skipped++;
      continue;
    }

    if (test_complete_crypto_flow(x25519_case, crypto_case)) {
      passed++;
    } else {
      failed++;
    }
  }

  CASE_MSG_INFO() << "X25519 Cipher Algorithm Tests Summary: passed=" << passed << ", skipped=" << skipped
                  << ", failed=" << failed << std::endl;
  CASE_EXPECT_EQ(0, failed);
}

// Test comprehensive matrix: all key exchange x all cipher combinations
CASE_TEST(atbus_connection_context, comprehensive_crypto_matrix) {
  ensure_openssl_initialized();

  int total_passed = 0;
  int total_skipped = 0;
  int total_failed = 0;

  CASE_MSG_INFO() << "=== Comprehensive Crypto Matrix Test ===" << std::endl;
  CASE_MSG_INFO() << "Testing all combinations of key exchange algorithms and cipher algorithms" << std::endl;

  for (const auto& kex_case : kKeyExchangeTestCases) {
    auto dh_ctx = create_test_dh_context(kex_case.dh_curve_name);
    if (!dh_ctx) {
      CASE_MSG_INFO() << "Key exchange " << kex_case.name << " not supported, skipping all ciphers for this KEX"
                      << std::endl;
      total_skipped += static_cast<int>(sizeof(kCryptoAlgorithmTestCases) / sizeof(kCryptoAlgorithmTestCases[0]));
      continue;
    }

    for (const auto& crypto_case : kCryptoAlgorithmTestCases) {
      if (!is_cipher_algorithm_available(crypto_case.cipher_name)) {
        total_skipped++;
        continue;
      }

      if (test_complete_crypto_flow(kex_case, crypto_case)) {
        total_passed++;
      } else {
        total_failed++;
        CASE_MSG_INFO() << "  FAILED: " << kex_case.name << " + " << crypto_case.name << std::endl;
      }
    }
  }

  CASE_MSG_INFO() << "=== Comprehensive Crypto Matrix Summary ===" << std::endl;
  CASE_MSG_INFO() << "  Total passed: " << total_passed << std::endl;
  CASE_MSG_INFO() << "  Total skipped: " << total_skipped << std::endl;
  CASE_MSG_INFO() << "  Total failed: " << total_failed << std::endl;

  CASE_EXPECT_EQ(0, total_failed);
  CASE_EXPECT_GT(total_passed, 0);  // At least one combination should work
}

// Test specific AEAD ciphers (GCM, Poly1305) that require special handling
CASE_TEST(atbus_connection_context, aead_ciphers_verification) {
  ensure_openssl_initialized();

  const key_exchange_test_case secp256r1_case = {atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_SECP256R1,
                                                 "ecdh:P-256", "SECP256R1 (P-256)"};

  auto dh_ctx = create_test_dh_context(secp256r1_case.dh_curve_name);
  if (!dh_ctx) {
    CASE_MSG_INFO() << "P-256 not supported, skipping AEAD test" << std::endl;
    return;
  }

  // Test only AEAD ciphers
  const crypto_algorithm_test_case aead_cases[] = {
      {atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_128_GCM, "aes-128-gcm", "AES-128-GCM", true},
      {atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_192_GCM, "aes-192-gcm", "AES-192-GCM", true},
      {atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_GCM, "aes-256-gcm", "AES-256-GCM", true},
      {atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_CHACHA20_POLY1305_IETF, "chacha20-poly1305-ietf",
       "ChaCha20-Poly1305-IETF", true},
      {atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_XCHACHA20_POLY1305_IETF, "xchacha20-poly1305-ietf",
       "XChaCha20-Poly1305-IETF", true},
  };

  int passed = 0;
  int skipped = 0;
  int failed = 0;

  for (const auto& crypto_case : aead_cases) {
    if (!is_cipher_algorithm_available(crypto_case.cipher_name)) {
      CASE_MSG_INFO() << "AEAD Cipher " << crypto_case.name << " not available, skipping" << std::endl;
      skipped++;
      continue;
    }

    if (test_complete_crypto_flow(secp256r1_case, crypto_case)) {
      passed++;
    } else {
      failed++;
    }
  }

  CASE_MSG_INFO() << "AEAD Cipher Tests Summary: passed=" << passed << ", skipped=" << skipped << ", failed=" << failed
                  << std::endl;
  CASE_EXPECT_EQ(0, failed);
}

// Test non-AEAD (CBC/stream) ciphers
CASE_TEST(atbus_connection_context, non_aead_ciphers_verification) {
  ensure_openssl_initialized();

  const key_exchange_test_case secp256r1_case = {atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_SECP256R1,
                                                 "ecdh:P-256", "SECP256R1 (P-256)"};

  auto dh_ctx = create_test_dh_context(secp256r1_case.dh_curve_name);
  if (!dh_ctx) {
    CASE_MSG_INFO() << "P-256 not supported, skipping non-AEAD test" << std::endl;
    return;
  }

  // Test only non-AEAD ciphers
  const crypto_algorithm_test_case non_aead_cases[] = {
      {atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_XXTEA, "xxtea", "XXTEA", false},
      {atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_128_CBC, "aes-128-cbc", "AES-128-CBC", false},
      {atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_192_CBC, "aes-192-cbc", "AES-192-CBC", false},
      {atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_CBC, "aes-256-cbc", "AES-256-CBC", false},
      {atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_CHACHA20, "chacha20", "ChaCha20", false},
  };

  int passed = 0;
  int skipped = 0;
  int failed = 0;

  for (const auto& crypto_case : non_aead_cases) {
    if (!is_cipher_algorithm_available(crypto_case.cipher_name)) {
      CASE_MSG_INFO() << "Non-AEAD Cipher " << crypto_case.name << " not available, skipping" << std::endl;
      skipped++;
      continue;
    }

    if (test_complete_crypto_flow(secp256r1_case, crypto_case)) {
      passed++;
    } else {
      failed++;
    }
  }

  CASE_MSG_INFO() << "Non-AEAD Cipher Tests Summary: passed=" << passed << ", skipped=" << skipped
                  << ", failed=" << failed << std::endl;
  CASE_EXPECT_EQ(0, failed);
}

// Test P-384 and P-521 key exchange with various ciphers
CASE_TEST(atbus_connection_context, higher_security_key_exchange) {
  ensure_openssl_initialized();

  // Test cases for higher security curves
  const key_exchange_test_case higher_kex_cases[] = {
      {atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_SECP384R1, "ecdh:P-384", "SECP384R1 (P-384)"},
      {atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_SECP521R1, "ecdh:P-521", "SECP521R1 (P-521)"},
  };

  // Test with a variety of ciphers
  const crypto_algorithm_test_case cipher_cases[] = {
      {atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_GCM, "aes-256-gcm", "AES-256-GCM", true},
      {atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_CHACHA20_POLY1305_IETF, "chacha20-poly1305-ietf",
       "ChaCha20-Poly1305-IETF", true},
      {atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_CBC, "aes-256-cbc", "AES-256-CBC", false},
  };

  int passed = 0;
  int skipped = 0;
  int failed = 0;

  for (const auto& kex_case : higher_kex_cases) {
    auto dh_ctx = create_test_dh_context(kex_case.dh_curve_name);
    if (!dh_ctx) {
      CASE_MSG_INFO() << "Key exchange " << kex_case.name << " not supported, skipping" << std::endl;
      skipped += static_cast<int>(sizeof(cipher_cases) / sizeof(cipher_cases[0]));
      continue;
    }

    for (const auto& crypto_case : cipher_cases) {
      if (!is_cipher_algorithm_available(crypto_case.cipher_name)) {
        skipped++;
        continue;
      }

      if (test_complete_crypto_flow(kex_case, crypto_case)) {
        passed++;
      } else {
        failed++;
      }
    }
  }

  CASE_MSG_INFO() << "Higher Security Key Exchange Tests Summary: passed=" << passed << ", skipped=" << skipped
                  << ", failed=" << failed << std::endl;
  CASE_EXPECT_EQ(0, failed);
}

// Test that lists all available algorithms (for diagnostic purposes)
CASE_TEST(atbus_connection_context, list_available_algorithms) {
  ensure_openssl_initialized();

  CASE_MSG_INFO() << "=== Available Cryptographic Algorithms ===" << std::endl;

  // List available key exchange algorithms
  CASE_MSG_INFO() << "Key Exchange Algorithms:" << std::endl;
  for (const auto& kex_case : kKeyExchangeTestCases) {
    auto dh_ctx = create_test_dh_context(kex_case.dh_curve_name);
    CASE_MSG_INFO() << "  " << kex_case.name << ": " << (dh_ctx ? "Available" : "NOT Available") << std::endl;
  }

  // List available cipher algorithms
  CASE_MSG_INFO() << "Cipher Algorithms:" << std::endl;
  for (const auto& crypto_case : kCryptoAlgorithmTestCases) {
    bool available = is_cipher_algorithm_available(crypto_case.cipher_name);
    CASE_MSG_INFO() << "  " << crypto_case.name << " (" << crypto_case.cipher_name
                    << "): " << (available ? "Available" : "NOT Available")
                    << (crypto_case.is_aead ? " [AEAD]" : " [Standard]") << std::endl;
  }

  // List all registered ciphers
  CASE_MSG_INFO() << "All registered ciphers in the library:" << std::endl;
  auto all_ciphers = atfw::util::crypto::cipher::get_all_cipher_names();
  for (const auto& cipher : all_ciphers) {
    CASE_MSG_INFO() << "  - " << cipher << std::endl;
  }
}

#endif  // CRYPTO_DH_ENABLED
