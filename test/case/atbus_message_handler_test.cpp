// Copyright 2026 atframework

#include <atbus_message_handler.h>
#include <libatbus_protocol.h>

#include <algorithm/crypto_hmac.h>
#include <algorithm/sha.h>
#include <gsl/select-gsl.h>
#include <string/string_format.h>
#include <time/time_utility.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "frame/test_macros.h"

namespace {

// Helper function to convert a string to a vector of unsigned chars
static std::vector<unsigned char> string_to_bytes(const std::string& str) {
  return std::vector<unsigned char>(str.begin(), str.end());
}

}  // namespace

// =============================================================================
// Tests for make_access_data_plaintext with crypto_handshake_data
// =============================================================================

CASE_TEST(atbus_message_handler, make_access_data_plaintext_crypto_without_public_key) {
  ::atframework::atbus::protocol::access_data ad;
  ad.set_timestamp(1735200000);  // Fixed timestamp for testing
  ad.set_nonce1(12345678901234);
  ad.set_nonce2(98765432109876);

  ::atframework::atbus::protocol::crypto_handshake_data hd;
  // Empty public key

  uint64_t bus_id = 0x12345678;

  std::string plaintext = atbus::message_handler::make_access_data_plaintext(bus_id, ad, hd);

  // Expected format: "timestamp:nonce1-nonce2:bus_id"
  std::string expected = atfw::util::string::format("{}:{}-{}:{}", ad.timestamp(), ad.nonce1(), ad.nonce2(), bus_id);
  CASE_EXPECT_EQ(expected, plaintext);
}

CASE_TEST(atbus_message_handler, make_access_data_plaintext_crypto_with_public_key) {
  ::atframework::atbus::protocol::access_data ad;
  ad.set_timestamp(1735200000);
  ad.set_nonce1(11111111111111);
  ad.set_nonce2(22222222222222);

  ::atframework::atbus::protocol::crypto_handshake_data hd;
  hd.set_type(::atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_X25519);
  hd.set_public_key("test_public_key_data");

  uint64_t bus_id = 0xABCD1234;

  std::string plaintext = atbus::message_handler::make_access_data_plaintext(bus_id, ad, hd);

  // Expected format: "timestamp:nonce1-nonce2:bus_id:type:hex(sha256(public_key))"
  std::string public_key_hash = atfw::util::hash::sha::hash_to_hex(atfw::util::hash::sha::EN_ALGORITHM_SHA256,
                                                                   hd.public_key().data(), hd.public_key().size());
  std::string expected = atfw::util::string::format("{}:{}-{}:{}:{}:{}", ad.timestamp(), ad.nonce1(), ad.nonce2(),
                                                    bus_id, static_cast<int>(hd.type()), public_key_hash);
  CASE_EXPECT_EQ(expected, plaintext);
}

CASE_TEST(atbus_message_handler, make_access_data_plaintext_crypto_different_key_exchange_types) {
  ::atframework::atbus::protocol::access_data ad;
  ad.set_timestamp(1735200000);
  ad.set_nonce1(33333333333333);
  ad.set_nonce2(44444444444444);

  uint64_t bus_id = 0x5555AAAA;

  // Test with SECP256R1
  {
    ::atframework::atbus::protocol::crypto_handshake_data hd;
    hd.set_type(::atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_SECP256R1);
    hd.set_public_key("secp256r1_public_key");

    std::string plaintext = atbus::message_handler::make_access_data_plaintext(bus_id, ad, hd);

    std::string public_key_hash = atfw::util::hash::sha::hash_to_hex(atfw::util::hash::sha::EN_ALGORITHM_SHA256,
                                                                     hd.public_key().data(), hd.public_key().size());
    std::string expected = atfw::util::string::format("{}:{}-{}:{}:{}:{}", ad.timestamp(), ad.nonce1(), ad.nonce2(),
                                                      bus_id, static_cast<int>(hd.type()), public_key_hash);
    CASE_EXPECT_EQ(expected, plaintext);
  }

  // Test with SECP384R1
  {
    ::atframework::atbus::protocol::crypto_handshake_data hd;
    hd.set_type(::atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_SECP384R1);
    hd.set_public_key("secp384r1_public_key_larger");

    std::string plaintext = atbus::message_handler::make_access_data_plaintext(bus_id, ad, hd);

    std::string public_key_hash = atfw::util::hash::sha::hash_to_hex(atfw::util::hash::sha::EN_ALGORITHM_SHA256,
                                                                     hd.public_key().data(), hd.public_key().size());
    std::string expected = atfw::util::string::format("{}:{}-{}:{}:{}:{}", ad.timestamp(), ad.nonce1(), ad.nonce2(),
                                                      bus_id, static_cast<int>(hd.type()), public_key_hash);
    CASE_EXPECT_EQ(expected, plaintext);
  }
}

// =============================================================================
// Tests for make_access_data_plaintext with custom_command_data
// =============================================================================

CASE_TEST(atbus_message_handler, make_access_data_plaintext_custom_command_empty) {
  ::atframework::atbus::protocol::access_data ad;
  ad.set_timestamp(1735200000);
  ad.set_nonce1(55555555555555);
  ad.set_nonce2(66666666666666);

  ::atframework::atbus::protocol::custom_command_data csarg;
  // No commands

  uint64_t bus_id = 0xDEADBEEF;

  std::string plaintext = atbus::message_handler::make_access_data_plaintext(bus_id, ad, csarg);

  // Expected format: "timestamp:nonce1-nonce2:bus_id:hex(sha256(concatenated_commands))"
  std::string empty_hash = atfw::util::hash::sha::hash_to_hex(atfw::util::hash::sha::EN_ALGORITHM_SHA256, nullptr, 0);
  std::string expected =
      atfw::util::string::format("{}:{}-{}:{}:{}", ad.timestamp(), ad.nonce1(), ad.nonce2(), bus_id, empty_hash);
  CASE_EXPECT_EQ(expected, plaintext);
}

CASE_TEST(atbus_message_handler, make_access_data_plaintext_custom_command_single) {
  ::atframework::atbus::protocol::access_data ad;
  ad.set_timestamp(1735200000);
  ad.set_nonce1(77777777777777);
  ad.set_nonce2(88888888888888);

  ::atframework::atbus::protocol::custom_command_data csarg;
  auto* cmd = csarg.add_commands();
  cmd->set_arg("test_command_1");

  uint64_t bus_id = 0xCAFEBABE;

  std::string plaintext = atbus::message_handler::make_access_data_plaintext(bus_id, ad, csarg);

  // Calculate expected hash
  std::string concatenated_data = "test_command_1";
  std::string data_hash = atfw::util::hash::sha::hash_to_hex(atfw::util::hash::sha::EN_ALGORITHM_SHA256,
                                                             concatenated_data.data(), concatenated_data.size());
  std::string expected =
      atfw::util::string::format("{}:{}-{}:{}:{}", ad.timestamp(), ad.nonce1(), ad.nonce2(), bus_id, data_hash);
  CASE_EXPECT_EQ(expected, plaintext);
}

CASE_TEST(atbus_message_handler, make_access_data_plaintext_custom_command_multiple) {
  ::atframework::atbus::protocol::access_data ad;
  ad.set_timestamp(1735200000);
  ad.set_nonce1(99999999999999);
  ad.set_nonce2(10101010101010);

  ::atframework::atbus::protocol::custom_command_data csarg;
  auto* cmd1 = csarg.add_commands();
  cmd1->set_arg("command_a");
  auto* cmd2 = csarg.add_commands();
  cmd2->set_arg("command_b");
  auto* cmd3 = csarg.add_commands();
  cmd3->set_arg("command_c");

  uint64_t bus_id = 0x12345678;

  std::string plaintext = atbus::message_handler::make_access_data_plaintext(bus_id, ad, csarg);

  // Calculate expected hash - concatenation of all commands
  std::string concatenated_data = "command_acommand_bcommand_c";
  std::string data_hash = atfw::util::hash::sha::hash_to_hex(atfw::util::hash::sha::EN_ALGORITHM_SHA256,
                                                             concatenated_data.data(), concatenated_data.size());
  std::string expected =
      atfw::util::string::format("{}:{}-{}:{}:{}", ad.timestamp(), ad.nonce1(), ad.nonce2(), bus_id, data_hash);
  CASE_EXPECT_EQ(expected, plaintext);
}

// =============================================================================
// Tests for calculate_access_data_signature
// =============================================================================

CASE_TEST(atbus_message_handler, calculate_access_data_signature_basic) {
  ::atframework::atbus::protocol::access_data ad;
  ad.set_algorithm(::atframework::atbus::protocol::ATBUS_ACCESS_DATA_ALGORITHM_HMAC_SHA256);
  ad.set_timestamp(1735200000);
  ad.set_nonce1(12345678901234);
  ad.set_nonce2(98765432109876);

  std::vector<unsigned char> access_token = string_to_bytes("test_access_token_secret");
  std::string plaintext = "1735200000:12345678901234-98765432109876:305419896";

  std::string signature = atbus::message_handler::calculate_access_data_signature(
      ad, gsl::span<const unsigned char>{access_token.data(), access_token.size()}, plaintext);

  // Verify the signature is not empty
  CASE_EXPECT_FALSE(signature.empty());

  // Verify the signature length matches HMAC-SHA256 output (32 bytes)
  CASE_EXPECT_EQ(static_cast<size_t>(32), signature.size());

  // Calculate expected signature using the same HMAC algorithm
  ::atfw::util::crypto::hmac hmac_algo;
  std::string expected_signature;

  // Must call init() before get_output_length()
  hmac_algo.init(atfw::util::crypto::digest_type_t::kSha256, access_token.data(), access_token.size());
  size_t output_length = hmac_algo.get_output_length();
  expected_signature.resize(output_length);

  hmac_algo.update(reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size());
  hmac_algo.final(reinterpret_cast<unsigned char*>(expected_signature.data()), &output_length);

  CASE_EXPECT_EQ(expected_signature, signature);
}

CASE_TEST(atbus_message_handler, calculate_access_data_signature_different_tokens) {
  ::atframework::atbus::protocol::access_data ad;
  ad.set_algorithm(::atframework::atbus::protocol::ATBUS_ACCESS_DATA_ALGORITHM_HMAC_SHA256);
  ad.set_timestamp(1735200000);
  ad.set_nonce1(11111111111111);
  ad.set_nonce2(22222222222222);

  std::string plaintext = "test_plaintext_for_signature";

  std::vector<unsigned char> token1 = string_to_bytes("secret_token_1");
  std::vector<unsigned char> token2 = string_to_bytes("secret_token_2");

  std::string signature1 = atbus::message_handler::calculate_access_data_signature(
      ad, gsl::span<const unsigned char>{token1.data(), token1.size()}, plaintext);

  std::string signature2 = atbus::message_handler::calculate_access_data_signature(
      ad, gsl::span<const unsigned char>{token2.data(), token2.size()}, plaintext);

  // Different tokens should produce different signatures
  CASE_EXPECT_NE(signature1, signature2);
}

CASE_TEST(atbus_message_handler, calculate_access_data_signature_different_plaintexts) {
  ::atframework::atbus::protocol::access_data ad;
  ad.set_algorithm(::atframework::atbus::protocol::ATBUS_ACCESS_DATA_ALGORITHM_HMAC_SHA256);
  ad.set_timestamp(1735200000);
  ad.set_nonce1(33333333333333);
  ad.set_nonce2(44444444444444);

  std::vector<unsigned char> access_token = string_to_bytes("same_secret_token");

  std::string plaintext1 = "plaintext_data_1";
  std::string plaintext2 = "plaintext_data_2";

  std::string signature1 = atbus::message_handler::calculate_access_data_signature(
      ad, gsl::span<const unsigned char>{access_token.data(), access_token.size()}, plaintext1);

  std::string signature2 = atbus::message_handler::calculate_access_data_signature(
      ad, gsl::span<const unsigned char>{access_token.data(), access_token.size()}, plaintext2);

  // Different plaintexts should produce different signatures
  CASE_EXPECT_NE(signature1, signature2);
}

CASE_TEST(atbus_message_handler, calculate_access_data_signature_empty_plaintext) {
  ::atframework::atbus::protocol::access_data ad;
  ad.set_algorithm(::atframework::atbus::protocol::ATBUS_ACCESS_DATA_ALGORITHM_HMAC_SHA256);
  ad.set_timestamp(1735200000);
  ad.set_nonce1(55555555555555);
  ad.set_nonce2(66666666666666);

  std::vector<unsigned char> access_token = string_to_bytes("test_token");
  std::string empty_plaintext;

  std::string signature = atbus::message_handler::calculate_access_data_signature(
      ad, gsl::span<const unsigned char>{access_token.data(), access_token.size()}, empty_plaintext);

  // Empty plaintext should still produce a valid signature
  CASE_EXPECT_FALSE(signature.empty());
  CASE_EXPECT_EQ(static_cast<size_t>(32), signature.size());
}

CASE_TEST(atbus_message_handler, calculate_access_data_signature_large_token) {
  ::atframework::atbus::protocol::access_data ad;
  ad.set_algorithm(::atframework::atbus::protocol::ATBUS_ACCESS_DATA_ALGORITHM_HMAC_SHA256);
  ad.set_timestamp(1735200000);
  ad.set_nonce1(77777777777777);
  ad.set_nonce2(88888888888888);

  // Create a large token (larger than the limit of 32868 bytes)
  std::vector<unsigned char> large_token(40000, 0x42);
  std::string plaintext = "test_plaintext";

  std::string signature = atbus::message_handler::calculate_access_data_signature(
      ad, gsl::span<const unsigned char>{large_token.data(), large_token.size()}, plaintext);

  // Should still produce a valid signature (truncated to 32868 bytes)
  CASE_EXPECT_FALSE(signature.empty());
  CASE_EXPECT_EQ(static_cast<size_t>(32), signature.size());
}

// =============================================================================
// Tests for generate_access_data with crypto_handshake_data
// =============================================================================

CASE_TEST(atbus_message_handler, generate_access_data_crypto_single_token) {
  ::atframework::atbus::protocol::access_data ad;
  uint64_t bus_id = 0x12345678;
  uint64_t nonce1 = 11111111111111;
  uint64_t nonce2 = 22222222222222;

  std::vector<std::vector<unsigned char>> access_tokens;
  access_tokens.push_back(string_to_bytes("token_1"));

  ::atframework::atbus::protocol::crypto_handshake_data hd;
  hd.set_type(::atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_X25519);
  hd.set_public_key("test_public_key");

  atbus::message_handler::generate_access_data(
      ad, bus_id, nonce1, nonce2,
      gsl::span<const std::vector<unsigned char>>{access_tokens.data(), access_tokens.size()}, hd);

  // Verify access_data is properly set
  CASE_EXPECT_EQ(::atframework::atbus::protocol::ATBUS_ACCESS_DATA_ALGORITHM_HMAC_SHA256, ad.algorithm());
  CASE_EXPECT_EQ(nonce1, ad.nonce1());
  CASE_EXPECT_EQ(nonce2, ad.nonce2());
  CASE_EXPECT_EQ(1, ad.signature_size());

  // Verify the signature is correct
  std::string expected_plaintext = atbus::message_handler::make_access_data_plaintext(bus_id, ad, hd);
  std::string expected_signature = atbus::message_handler::calculate_access_data_signature(
      ad, gsl::span<const unsigned char>{access_tokens[0].data(), access_tokens[0].size()}, expected_plaintext);
  CASE_EXPECT_EQ(expected_signature, ad.signature(0));
}

CASE_TEST(atbus_message_handler, generate_access_data_crypto_multiple_tokens) {
  ::atframework::atbus::protocol::access_data ad;
  uint64_t bus_id = 0xABCDEF12;
  uint64_t nonce1 = 33333333333333;
  uint64_t nonce2 = 44444444444444;

  std::vector<std::vector<unsigned char>> access_tokens;
  access_tokens.push_back(string_to_bytes("token_a"));
  access_tokens.push_back(string_to_bytes("token_b"));
  access_tokens.push_back(string_to_bytes("token_c"));

  ::atframework::atbus::protocol::crypto_handshake_data hd;

  atbus::message_handler::generate_access_data(
      ad, bus_id, nonce1, nonce2,
      gsl::span<const std::vector<unsigned char>>{access_tokens.data(), access_tokens.size()}, hd);

  // Verify access_data is properly set
  CASE_EXPECT_EQ(::atframework::atbus::protocol::ATBUS_ACCESS_DATA_ALGORITHM_HMAC_SHA256, ad.algorithm());
  CASE_EXPECT_EQ(nonce1, ad.nonce1());
  CASE_EXPECT_EQ(nonce2, ad.nonce2());
  CASE_EXPECT_EQ(3, ad.signature_size());

  // Verify each signature
  std::string expected_plaintext = atbus::message_handler::make_access_data_plaintext(bus_id, ad, hd);
  for (size_t i = 0; i < access_tokens.size(); ++i) {
    std::string expected_signature = atbus::message_handler::calculate_access_data_signature(
        ad, gsl::span<const unsigned char>{access_tokens[i].data(), access_tokens[i].size()}, expected_plaintext);
    CASE_EXPECT_EQ(expected_signature, ad.signature(static_cast<int>(i)));
  }
}

CASE_TEST(atbus_message_handler, generate_access_data_crypto_empty_tokens) {
  ::atframework::atbus::protocol::access_data ad;
  uint64_t bus_id = 0x55556666;
  uint64_t nonce1 = 55555555555555;
  uint64_t nonce2 = 66666666666666;

  std::vector<std::vector<unsigned char>> access_tokens;  // Empty

  ::atframework::atbus::protocol::crypto_handshake_data hd;

  atbus::message_handler::generate_access_data(
      ad, bus_id, nonce1, nonce2,
      gsl::span<const std::vector<unsigned char>>{access_tokens.data(), access_tokens.size()}, hd);

  // Should have no signatures
  CASE_EXPECT_EQ(0, ad.signature_size());
  CASE_EXPECT_EQ(nonce1, ad.nonce1());
  CASE_EXPECT_EQ(nonce2, ad.nonce2());
}

// =============================================================================
// Tests for generate_access_data with custom_command_data
// =============================================================================

CASE_TEST(atbus_message_handler, generate_access_data_custom_command_single_token) {
  ::atframework::atbus::protocol::access_data ad;
  uint64_t bus_id = 0xDEADBEEF;
  uint64_t nonce1 = 77777777777777;
  uint64_t nonce2 = 88888888888888;

  std::vector<std::vector<unsigned char>> access_tokens;
  access_tokens.push_back(string_to_bytes("custom_token"));

  ::atframework::atbus::protocol::custom_command_data csarg;
  auto* cmd = csarg.add_commands();
  cmd->set_arg("custom_command_arg");

  atbus::message_handler::generate_access_data(
      ad, bus_id, nonce1, nonce2,
      gsl::span<const std::vector<unsigned char>>{access_tokens.data(), access_tokens.size()}, csarg);

  // Verify access_data is properly set
  CASE_EXPECT_EQ(::atframework::atbus::protocol::ATBUS_ACCESS_DATA_ALGORITHM_HMAC_SHA256, ad.algorithm());
  CASE_EXPECT_EQ(nonce1, ad.nonce1());
  CASE_EXPECT_EQ(nonce2, ad.nonce2());
  CASE_EXPECT_EQ(1, ad.signature_size());

  // Verify the signature is correct
  std::string expected_plaintext = atbus::message_handler::make_access_data_plaintext(bus_id, ad, csarg);
  std::string expected_signature = atbus::message_handler::calculate_access_data_signature(
      ad, gsl::span<const unsigned char>{access_tokens[0].data(), access_tokens[0].size()}, expected_plaintext);
  CASE_EXPECT_EQ(expected_signature, ad.signature(0));
}

CASE_TEST(atbus_message_handler, generate_access_data_custom_command_multiple_tokens) {
  ::atframework::atbus::protocol::access_data ad;
  uint64_t bus_id = 0xCAFEBABE;
  uint64_t nonce1 = 99999999999999;
  uint64_t nonce2 = 10101010101010;

  std::vector<std::vector<unsigned char>> access_tokens;
  access_tokens.push_back(string_to_bytes("token_x"));
  access_tokens.push_back(string_to_bytes("token_y"));

  ::atframework::atbus::protocol::custom_command_data csarg;
  auto* cmd1 = csarg.add_commands();
  cmd1->set_arg("arg_1");
  auto* cmd2 = csarg.add_commands();
  cmd2->set_arg("arg_2");

  atbus::message_handler::generate_access_data(
      ad, bus_id, nonce1, nonce2,
      gsl::span<const std::vector<unsigned char>>{access_tokens.data(), access_tokens.size()}, csarg);

  // Verify access_data is properly set
  CASE_EXPECT_EQ(::atframework::atbus::protocol::ATBUS_ACCESS_DATA_ALGORITHM_HMAC_SHA256, ad.algorithm());
  CASE_EXPECT_EQ(nonce1, ad.nonce1());
  CASE_EXPECT_EQ(nonce2, ad.nonce2());
  CASE_EXPECT_EQ(2, ad.signature_size());

  // Verify each signature
  std::string expected_plaintext = atbus::message_handler::make_access_data_plaintext(bus_id, ad, csarg);
  for (size_t i = 0; i < access_tokens.size(); ++i) {
    std::string expected_signature = atbus::message_handler::calculate_access_data_signature(
        ad, gsl::span<const unsigned char>{access_tokens[i].data(), access_tokens[i].size()}, expected_plaintext);
    CASE_EXPECT_EQ(expected_signature, ad.signature(static_cast<int>(i)));
  }
}

CASE_TEST(atbus_message_handler, generate_access_data_custom_command_empty_commands) {
  ::atframework::atbus::protocol::access_data ad;
  uint64_t bus_id = 0x11112222;
  uint64_t nonce1 = 12121212121212;
  uint64_t nonce2 = 34343434343434;

  std::vector<std::vector<unsigned char>> access_tokens;
  access_tokens.push_back(string_to_bytes("token_for_empty"));

  ::atframework::atbus::protocol::custom_command_data csarg;
  // Empty commands

  atbus::message_handler::generate_access_data(
      ad, bus_id, nonce1, nonce2,
      gsl::span<const std::vector<unsigned char>>{access_tokens.data(), access_tokens.size()}, csarg);

  // Should still generate signature
  CASE_EXPECT_EQ(1, ad.signature_size());
  CASE_EXPECT_FALSE(ad.signature(0).empty());
}

// =============================================================================
// Integration tests - verify consistency between functions
// =============================================================================

CASE_TEST(atbus_message_handler, integration_plaintext_and_signature_consistency) {
  ::atframework::atbus::protocol::access_data ad;
  uint64_t bus_id = 0xAAAABBBB;
  uint64_t nonce1 = 56565656565656;
  uint64_t nonce2 = 78787878787878;

  std::vector<std::vector<unsigned char>> access_tokens;
  access_tokens.push_back(string_to_bytes("integration_test_token"));

  ::atframework::atbus::protocol::crypto_handshake_data hd;
  hd.set_type(::atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_SECP521R1);
  hd.set_public_key("integration_public_key_data");

  // Generate access data
  atbus::message_handler::generate_access_data(
      ad, bus_id, nonce1, nonce2,
      gsl::span<const std::vector<unsigned char>>{access_tokens.data(), access_tokens.size()}, hd);

  // Manually compute plaintext and signature
  std::string manual_plaintext = atbus::message_handler::make_access_data_plaintext(bus_id, ad, hd);
  std::string manual_signature = atbus::message_handler::calculate_access_data_signature(
      ad, gsl::span<const unsigned char>{access_tokens[0].data(), access_tokens[0].size()}, manual_plaintext);

  // Verify consistency
  CASE_EXPECT_EQ(manual_signature, ad.signature(0));
}

CASE_TEST(atbus_message_handler, integration_deterministic_output) {
  uint64_t bus_id = 0xCCCCDDDD;
  uint64_t nonce1 = 90909090909090;
  uint64_t nonce2 = 12312312312312;

  std::vector<std::vector<unsigned char>> access_tokens;
  access_tokens.push_back(string_to_bytes("deterministic_token"));

  ::atframework::atbus::protocol::crypto_handshake_data hd;
  hd.set_public_key("deterministic_key");

  // Generate twice with same inputs
  ::atframework::atbus::protocol::access_data ad1;
  atbus::message_handler::generate_access_data(
      ad1, bus_id, nonce1, nonce2,
      gsl::span<const std::vector<unsigned char>>{access_tokens.data(), access_tokens.size()}, hd);

  ::atframework::atbus::protocol::access_data ad2;
  atbus::message_handler::generate_access_data(
      ad2, bus_id, nonce1, nonce2,
      gsl::span<const std::vector<unsigned char>>{access_tokens.data(), access_tokens.size()}, hd);

  // Both signatures should be identical (same nonce values)
  CASE_EXPECT_EQ(ad1.nonce1(), ad2.nonce1());
  CASE_EXPECT_EQ(ad1.nonce2(), ad2.nonce2());

  // Plaintext generation should be identical
  std::string plaintext1 = atbus::message_handler::make_access_data_plaintext(bus_id, ad1, hd);
  std::string plaintext2 = atbus::message_handler::make_access_data_plaintext(bus_id, ad2, hd);
  CASE_EXPECT_EQ(plaintext1, plaintext2);
}

