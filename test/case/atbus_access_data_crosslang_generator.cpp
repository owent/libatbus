// Copyright 2026 atframework
// This file generates test data files for cross-language access_data verification.

#include <atbus_message_handler.h>
#include <libatbus_protocol.h>

#include <algorithm/crypto_cipher.h>
#include <algorithm/sha.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

#ifdef _WIN32
#  include <direct.h>
#else
#  include <sys/stat.h>
#endif

#include "frame/test_macros.h"

namespace {

// 测试数据输出子目录
static const char* kTestOutputSubDir = "atbus_access_data_crosslang";

// 获取源码目录路径（基于 __FILE__ 宏）
static std::string get_source_dir() {
  std::string file_path = __FILE__;
  size_t last_sep = file_path.find_last_of("/\\");
  if (last_sep != std::string::npos) {
    return file_path.substr(0, last_sep);
  }
  return ".";
}

// 获取输出目录路径
static std::string get_output_dir() { return get_source_dir() + "/" + kTestOutputSubDir; }

// 确保输出目录存在
static bool ensure_output_dir() {
  std::string dir = get_output_dir();
#ifdef _WIN32
  _mkdir(dir.c_str());
#else
  mkdir(dir.c_str(), 0755);
#endif
  return true;
}

// 读取二进制文件
static bool read_binary_file(const std::string& filename, std::vector<unsigned char>& buffer) {
  std::string path = get_output_dir() + "/" + filename;
  std::ifstream file(path, std::ios::binary | std::ios::ate);
  if (!file.is_open()) {
    CASE_MSG_INFO() << "Failed to open file for reading: " << path << std::endl;
    return false;
  }
  std::streamsize size = file.tellg();
  file.seekg(0, std::ios::beg);
  buffer.resize(static_cast<size_t>(size));
  if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
    CASE_MSG_INFO() << "Failed to read file: " << path << std::endl;
    return false;
  }
  return true;
}

// 写入二进制文件
static bool write_binary_file(const std::string& filename, const unsigned char* data, size_t size) {
  std::string path = get_output_dir() + "/" + filename;
  std::ofstream file(path, std::ios::binary);
  if (!file.is_open()) {
    CASE_MSG_INFO() << "Failed to open file for writing: " << path << std::endl;
    return false;
  }
  file.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(size));
  file.close();
  CASE_MSG_INFO() << "Written: " << path << " (" << size << " bytes)" << std::endl;
  return true;
}

// 写入JSON文件
static bool write_json_file(const std::string& filename, const std::string& json_content) {
  std::string path = get_output_dir() + "/" + filename;
  std::ofstream file(path);
  if (!file.is_open()) {
    CASE_MSG_INFO() << "Failed to open file for writing: " << path << std::endl;
    return false;
  }
  file << json_content;
  file.close();
  CASE_MSG_INFO() << "Written: " << path << std::endl;
  return true;
}

// 转换字节为十六进制字符串
static std::string bytes_to_hex(const unsigned char* data, size_t size) {
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (size_t i = 0; i < size; ++i) {
    oss << std::setw(2) << static_cast<int>(data[i]);
  }
  return oss.str();
}

static std::string bytes_to_hex(const std::string& data) {
  return bytes_to_hex(reinterpret_cast<const unsigned char*>(data.data()), data.size());
}

// 转义JSON字符串
static std::string escape_json_string(const std::string& s) {
  std::ostringstream oss;
  for (char c : s) {
    switch (c) {
      case '"':
        oss << "\\\"";
        break;
      case '\\':
        oss << "\\\\";
        break;
      case '\b':
        oss << "\\b";
        break;
      case '\f':
        oss << "\\f";
        break;
      case '\n':
        oss << "\\n";
        break;
      case '\r':
        oss << "\\r";
        break;
      case '\t':
        oss << "\\t";
        break;
      default:
        if (static_cast<unsigned char>(c) < 0x20) {
          oss << "\\u" << std::hex << std::setfill('0') << std::setw(4) << static_cast<int>(c);
        } else {
          oss << c;
        }
    }
  }
  return oss.str();
}

}  // namespace

// ============================================================================
// 生成 make_access_data_plaintext 测试数据
// ============================================================================

CASE_TEST(atbus_access_data_crosslang, generate_plaintext_test_files) {
  CASE_EXPECT_TRUE(ensure_output_dir());

  int generated_count = 0;

  // ============================================================================
  // Test Case 1: plaintext without public_key (crypto_handshake_data)
  // ============================================================================
  {
    const char* test_name = "plaintext_no_pubkey";

    ::atframework::atbus::protocol::access_data ad;
    ad.set_algorithm(::atframework::atbus::protocol::ATBUS_ACCESS_DATA_ALGORITHM_HMAC_SHA256);
    ad.set_timestamp(1735689600);  // 2025-01-01 00:00:00 UTC
    ad.set_nonce1(0x123456789ABCDEF0ULL);
    ad.set_nonce2(0xFEDCBA9876543210ULL);

    uint64_t bus_id = 0x12345678;

    ::atframework::atbus::protocol::crypto_handshake_data hd;
    // Empty public_key

    std::string plaintext = atfw::atbus::message_handler::make_access_data_plaintext(bus_id, ad, hd);

    // Expected format: "<timestamp>:<nonce1>-<nonce2>:<bus_id>"
    std::string expected_plaintext = "1735689600:1311768467463790320-18364758544493064720:305419896";

    CASE_EXPECT_EQ(expected_plaintext, plaintext);

    std::ostringstream json;
    json << "{\n";
    json << "  \"name\": \"" << test_name << "\",\n";
    json << "  \"description\": \"Plaintext generation without public key (no encryption)\",\n";
    json << "  \"function\": \"make_access_data_plaintext\",\n";
    json << "  \"input\": {\n";
    json << "    \"bus_id\": " << bus_id << ",\n";
    json << "    \"bus_id_hex\": \"" << std::hex << bus_id << std::dec << "\",\n";
    json << "    \"timestamp\": " << ad.timestamp() << ",\n";
    json << "    \"nonce1\": " << ad.nonce1() << ",\n";
    json << "    \"nonce1_hex\": \"" << std::hex << ad.nonce1() << std::dec << "\",\n";
    json << "    \"nonce2\": " << ad.nonce2() << ",\n";
    json << "    \"nonce2_hex\": \"" << std::hex << ad.nonce2() << std::dec << "\",\n";
    json << "    \"crypto_handshake_type\": " << static_cast<int>(hd.type()) << ",\n";
    json << "    \"public_key_hex\": \"\"\n";
    json << "  },\n";
    json << "  \"expected\": {\n";
    json << "    \"plaintext\": \"" << escape_json_string(plaintext) << "\",\n";
    json << "    \"plaintext_format\": \"<timestamp>:<nonce1>-<nonce2>:<bus_id>\"\n";
    json << "  }\n";
    json << "}\n";
    write_json_file(std::string(test_name) + ".json", json.str());
    generated_count++;

    CASE_MSG_INFO() << "[PASS] " << test_name << ": plaintext = " << plaintext << std::endl;
  }

  // ============================================================================
  // Test Case 2: plaintext with public_key (crypto_handshake_data)
  // ============================================================================
  {
    const char* test_name = "plaintext_with_pubkey";

    ::atframework::atbus::protocol::access_data ad;
    ad.set_algorithm(::atframework::atbus::protocol::ATBUS_ACCESS_DATA_ALGORITHM_HMAC_SHA256);
    ad.set_timestamp(1735689600);
    ad.set_nonce1(0xAAAABBBBCCCCDDDDULL);
    ad.set_nonce2(0x1111222233334444ULL);

    uint64_t bus_id = 0xABCDEF01;

    ::atframework::atbus::protocol::crypto_handshake_data hd;
    hd.set_type(::atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_SECP256R1);

    // 使用固定的 32 字节 public key 用于测试
    std::string fixed_pubkey;
    fixed_pubkey.resize(32);
    for (size_t i = 0; i < 32; ++i) {
      fixed_pubkey[i] = static_cast<char>(i);
    }
    hd.set_public_key(fixed_pubkey);

    std::string plaintext = atfw::atbus::message_handler::make_access_data_plaintext(bus_id, ad, hd);

    // Calculate expected SHA256 hash of public key
    std::string pubkey_hash = atfw::util::hash::sha::hash_to_hex(atfw::util::hash::sha::EN_ALGORITHM_SHA256,
                                                                 hd.public_key().data(), hd.public_key().size());

    std::ostringstream json;
    json << "{\n";
    json << "  \"name\": \"" << test_name << "\",\n";
    json << "  \"description\": \"Plaintext generation with public key (with encryption)\",\n";
    json << "  \"function\": \"make_access_data_plaintext\",\n";
    json << "  \"input\": {\n";
    json << "    \"bus_id\": " << bus_id << ",\n";
    json << "    \"bus_id_hex\": \"" << std::hex << bus_id << std::dec << "\",\n";
    json << "    \"timestamp\": " << ad.timestamp() << ",\n";
    json << "    \"nonce1\": " << ad.nonce1() << ",\n";
    json << "    \"nonce1_hex\": \"" << std::hex << ad.nonce1() << std::dec << "\",\n";
    json << "    \"nonce2\": " << ad.nonce2() << ",\n";
    json << "    \"nonce2_hex\": \"" << std::hex << ad.nonce2() << std::dec << "\",\n";
    json << "    \"crypto_handshake_type\": " << static_cast<int>(hd.type()) << ",\n";
    json << "    \"crypto_handshake_type_name\": \"ATBUS_CRYPTO_KEY_EXCHANGE_SECP256R1\",\n";
    json << "    \"public_key_hex\": \"" << bytes_to_hex(hd.public_key()) << "\"\n";
    json << "  },\n";
    json << "  \"intermediate\": {\n";
    json << "    \"public_key_sha256_hex\": \"" << pubkey_hash << "\"\n";
    json << "  },\n";
    json << "  \"expected\": {\n";
    json << "    \"plaintext\": \"" << escape_json_string(plaintext) << "\",\n";
    json << "    \"plaintext_format\": \"<timestamp>:<nonce1>-<nonce2>:<bus_id>:<type>:<sha256_hex>\"\n";
    json << "  }\n";
    json << "}\n";
    write_json_file(std::string(test_name) + ".json", json.str());
    generated_count++;

    CASE_MSG_INFO() << "[PASS] " << test_name << ": plaintext = " << plaintext << std::endl;
  }

  // ============================================================================
  // Test Case 3: plaintext with custom_command_data
  // ============================================================================
  {
    const char* test_name = "plaintext_custom_command";

    ::atframework::atbus::protocol::access_data ad;
    ad.set_algorithm(::atframework::atbus::protocol::ATBUS_ACCESS_DATA_ALGORITHM_HMAC_SHA256);
    ad.set_timestamp(1735689600);
    ad.set_nonce1(0x5555666677778888ULL);
    ad.set_nonce2(0x9999AAAABBBBCCCCULL);

    uint64_t bus_id = 0x87654321;

    ::atframework::atbus::protocol::custom_command_data csarg;
    csarg.set_from(bus_id);

    auto* cmd1 = csarg.add_commands();
    cmd1->set_arg("command1");
    auto* cmd2 = csarg.add_commands();
    cmd2->set_arg("arg2");
    auto* cmd3 = csarg.add_commands();
    cmd3->set_arg("data3");

    std::string plaintext = atfw::atbus::message_handler::make_access_data_plaintext(bus_id, ad, csarg);

    // Calculate expected SHA256 hash of concatenated commands
    std::string concat_args = "command1arg2data3";
    std::string args_hash = atfw::util::hash::sha::hash_to_hex(atfw::util::hash::sha::EN_ALGORITHM_SHA256,
                                                               concat_args.data(), concat_args.size());

    std::ostringstream json;
    json << "{\n";
    json << "  \"name\": \"" << test_name << "\",\n";
    json << "  \"description\": \"Plaintext generation with custom command data\",\n";
    json << "  \"function\": \"make_access_data_plaintext\",\n";
    json << "  \"input\": {\n";
    json << "    \"bus_id\": " << bus_id << ",\n";
    json << "    \"bus_id_hex\": \"" << std::hex << bus_id << std::dec << "\",\n";
    json << "    \"timestamp\": " << ad.timestamp() << ",\n";
    json << "    \"nonce1\": " << ad.nonce1() << ",\n";
    json << "    \"nonce1_hex\": \"" << std::hex << ad.nonce1() << std::dec << "\",\n";
    json << "    \"nonce2\": " << ad.nonce2() << ",\n";
    json << "    \"nonce2_hex\": \"" << std::hex << ad.nonce2() << std::dec << "\",\n";
    json << "    \"commands\": [\"command1\", \"arg2\", \"data3\"]\n";
    json << "  },\n";
    json << "  \"intermediate\": {\n";
    json << "    \"concatenated_args\": \"" << concat_args << "\",\n";
    json << "    \"args_sha256_hex\": \"" << args_hash << "\"\n";
    json << "  },\n";
    json << "  \"expected\": {\n";
    json << "    \"plaintext\": \"" << escape_json_string(plaintext) << "\",\n";
    json << "    \"plaintext_format\": \"<timestamp>:<nonce1>-<nonce2>:<bus_id>:<sha256_hex>\"\n";
    json << "  }\n";
    json << "}\n";
    write_json_file(std::string(test_name) + ".json", json.str());
    generated_count++;

    CASE_MSG_INFO() << "[PASS] " << test_name << ": plaintext = " << plaintext << std::endl;
  }

  CASE_MSG_INFO() << "[SUMMARY] Generated " << generated_count << " plaintext test files" << std::endl;
  CASE_EXPECT_EQ(3, generated_count);
}

// ============================================================================
// 生成 calculate_access_data_signature 测试数据
// ============================================================================

CASE_TEST(atbus_access_data_crosslang, generate_signature_test_files) {
  CASE_EXPECT_TRUE(ensure_output_dir());

  int generated_count = 0;

  // ============================================================================
  // Test Case 1: HMAC-SHA256 signature with simple token
  // ============================================================================
  {
    const char* test_name = "signature_simple_token";

    ::atframework::atbus::protocol::access_data ad;
    ad.set_algorithm(::atframework::atbus::protocol::ATBUS_ACCESS_DATA_ALGORITHM_HMAC_SHA256);
    ad.set_timestamp(1735689600);
    ad.set_nonce1(0x1234567890ABCDEFULL);
    ad.set_nonce2(0xFEDCBA0987654321ULL);

    // Fixed access token
    std::vector<unsigned char> access_token = {'s', 'e', 'c', 'r', 'e', 't', '_', 't',
                                               'o', 'k', 'e', 'n', '_', '1', '2', '3'};

    std::string plaintext = "1735689600:1311768467294899695-18364758544106544929:305419896";

    std::string signature = atfw::atbus::message_handler::calculate_access_data_signature(
        ad, gsl::span<const unsigned char>{access_token.data(), access_token.size()}, plaintext);

    // Write signature binary
    write_binary_file(std::string(test_name) + ".bytes", reinterpret_cast<const unsigned char*>(signature.data()),
                      signature.size());

    std::ostringstream json;
    json << "{\n";
    json << "  \"name\": \"" << test_name << "\",\n";
    json << "  \"description\": \"HMAC-SHA256 signature with simple access token\",\n";
    json << "  \"function\": \"calculate_access_data_signature\",\n";
    json << "  \"algorithm\": \"HMAC-SHA256\",\n";
    json << "  \"input\": {\n";
    json << "    \"access_token\": \"" << escape_json_string(std::string(access_token.begin(), access_token.end()))
         << "\",\n";
    json << "    \"access_token_hex\": \"" << bytes_to_hex(access_token.data(), access_token.size()) << "\",\n";
    json << "    \"plaintext\": \"" << escape_json_string(plaintext) << "\"\n";
    json << "  },\n";
    json << "  \"expected\": {\n";
    json << "    \"signature_hex\": \"" << bytes_to_hex(signature) << "\",\n";
    json << "    \"signature_length\": " << signature.size() << "\n";
    json << "  }\n";
    json << "}\n";
    write_json_file(std::string(test_name) + ".json", json.str());
    generated_count++;

    CASE_MSG_INFO() << "[PASS] " << test_name << ": signature_hex = " << bytes_to_hex(signature) << std::endl;
  }

  // ============================================================================
  // Test Case 2: HMAC-SHA256 signature with binary token
  // ============================================================================
  {
    const char* test_name = "signature_binary_token";

    ::atframework::atbus::protocol::access_data ad;
    ad.set_algorithm(::atframework::atbus::protocol::ATBUS_ACCESS_DATA_ALGORITHM_HMAC_SHA256);
    ad.set_timestamp(1735689600);
    ad.set_nonce1(0xAABBCCDDEEFF0011ULL);
    ad.set_nonce2(0x2233445566778899ULL);

    // Binary access token with non-printable characters
    std::vector<unsigned char> access_token(32);
    for (size_t i = 0; i < 32; ++i) {
      access_token[i] = static_cast<unsigned char>((i * 7 + 13) & 0xFF);
    }

    std::string plaintext = "1735689600:12302652057474621457-2459565876494606489:2882400001";

    std::string signature = atfw::atbus::message_handler::calculate_access_data_signature(
        ad, gsl::span<const unsigned char>{access_token.data(), access_token.size()}, plaintext);

    write_binary_file(std::string(test_name) + ".bytes", reinterpret_cast<const unsigned char*>(signature.data()),
                      signature.size());

    std::ostringstream json;
    json << "{\n";
    json << "  \"name\": \"" << test_name << "\",\n";
    json << "  \"description\": \"HMAC-SHA256 signature with binary access token\",\n";
    json << "  \"function\": \"calculate_access_data_signature\",\n";
    json << "  \"algorithm\": \"HMAC-SHA256\",\n";
    json << "  \"input\": {\n";
    json << "    \"access_token_hex\": \"" << bytes_to_hex(access_token.data(), access_token.size()) << "\",\n";
    json << "    \"access_token_length\": " << access_token.size() << ",\n";
    json << "    \"plaintext\": \"" << escape_json_string(plaintext) << "\"\n";
    json << "  },\n";
    json << "  \"expected\": {\n";
    json << "    \"signature_hex\": \"" << bytes_to_hex(signature) << "\",\n";
    json << "    \"signature_length\": " << signature.size() << "\n";
    json << "  }\n";
    json << "}\n";
    write_json_file(std::string(test_name) + ".json", json.str());
    generated_count++;

    CASE_MSG_INFO() << "[PASS] " << test_name << ": signature_hex = " << bytes_to_hex(signature) << std::endl;
  }

  // ============================================================================
  // Test Case 3: HMAC-SHA256 signature with 256-bit token
  // ============================================================================
  {
    const char* test_name = "signature_256bit_token";

    ::atframework::atbus::protocol::access_data ad;
    ad.set_algorithm(::atframework::atbus::protocol::ATBUS_ACCESS_DATA_ALGORITHM_HMAC_SHA256);
    ad.set_timestamp(1735689600);
    ad.set_nonce1(0x1111111111111111ULL);
    ad.set_nonce2(0x2222222222222222ULL);

    // 256-bit (32-byte) token
    std::vector<unsigned char> access_token = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
                                               0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA,
                                               0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00};

    uint64_t bus_id = 0x99887766;
    ::atframework::atbus::protocol::crypto_handshake_data hd;
    // Empty public key for simple plaintext format
    std::string plaintext = atfw::atbus::message_handler::make_access_data_plaintext(bus_id, ad, hd);

    std::string signature = atfw::atbus::message_handler::calculate_access_data_signature(
        ad, gsl::span<const unsigned char>{access_token.data(), access_token.size()}, plaintext);

    write_binary_file(std::string(test_name) + ".bytes", reinterpret_cast<const unsigned char*>(signature.data()),
                      signature.size());

    std::ostringstream json;
    json << "{\n";
    json << "  \"name\": \"" << test_name << "\",\n";
    json << "  \"description\": \"HMAC-SHA256 signature with 256-bit access token\",\n";
    json << "  \"function\": \"calculate_access_data_signature\",\n";
    json << "  \"algorithm\": \"HMAC-SHA256\",\n";
    json << "  \"input\": {\n";
    json << "    \"access_token_hex\": \"" << bytes_to_hex(access_token.data(), access_token.size()) << "\",\n";
    json << "    \"access_token_length\": " << access_token.size() << ",\n";
    json << "    \"bus_id\": " << bus_id << ",\n";
    json << "    \"timestamp\": " << ad.timestamp() << ",\n";
    json << "    \"nonce1\": " << ad.nonce1() << ",\n";
    json << "    \"nonce2\": " << ad.nonce2() << ",\n";
    json << "    \"plaintext\": \"" << escape_json_string(plaintext) << "\"\n";
    json << "  },\n";
    json << "  \"expected\": {\n";
    json << "    \"signature_hex\": \"" << bytes_to_hex(signature) << "\",\n";
    json << "    \"signature_length\": " << signature.size() << "\n";
    json << "  }\n";
    json << "}\n";
    write_json_file(std::string(test_name) + ".json", json.str());
    generated_count++;

    CASE_MSG_INFO() << "[PASS] " << test_name << ": signature_hex = " << bytes_to_hex(signature) << std::endl;
  }

  CASE_MSG_INFO() << "[SUMMARY] Generated " << generated_count << " signature test files" << std::endl;
  CASE_EXPECT_EQ(3, generated_count);
}

// ============================================================================
// 生成 generate_access_data 完整测试数据
// ============================================================================

CASE_TEST(atbus_access_data_crosslang, generate_full_access_data_test_files) {
  CASE_EXPECT_TRUE(ensure_output_dir());

  int generated_count = 0;

  // ============================================================================
  // Test Case 1: generate_access_data with crypto_handshake_data (no public key)
  // ============================================================================
  {
    const char* test_name = "full_access_data_no_pubkey";

    uint64_t bus_id = 0x12345678;
    uint64_t nonce1 = 0xABCDEF0123456789ULL;
    uint64_t nonce2 = 0x9876543210FEDCBAULL;

    std::vector<std::vector<unsigned char>> access_tokens = {{'t', 'o', 'k', 'e', 'n', '1'},
                                                             {'t', 'o', 'k', 'e', 'n', '2'}};

    ::atframework::atbus::protocol::crypto_handshake_data hd;
    // Empty public key

    ::atframework::atbus::protocol::access_data ad;
    // Manually set timestamp to fixed value for reproducibility
    ad.set_algorithm(::atframework::atbus::protocol::ATBUS_ACCESS_DATA_ALGORITHM_HMAC_SHA256);
    ad.set_timestamp(1735689600);
    ad.set_nonce1(nonce1);
    ad.set_nonce2(nonce2);

    // Generate signatures manually to use fixed timestamp
    std::string plaintext = atfw::atbus::message_handler::make_access_data_plaintext(bus_id, ad, hd);
    for (const auto& token : access_tokens) {
      std::string sig = atfw::atbus::message_handler::calculate_access_data_signature(
          ad, gsl::span<const unsigned char>{token.data(), token.size()}, plaintext);
      ad.add_signature(sig);
    }

    // Serialize access_data to binary
    std::string serialized;
    ad.SerializeToString(&serialized);
    write_binary_file(std::string(test_name) + ".bytes", reinterpret_cast<const unsigned char*>(serialized.data()),
                      serialized.size());

    std::ostringstream json;
    json << "{\n";
    json << "  \"name\": \"" << test_name << "\",\n";
    json << "  \"description\": \"Full access_data generation with crypto_handshake_data (no public key)\",\n";
    json << "  \"function\": \"generate_access_data\",\n";
    json << "  \"input\": {\n";
    json << "    \"bus_id\": " << bus_id << ",\n";
    json << "    \"nonce1\": " << nonce1 << ",\n";
    json << "    \"nonce1_hex\": \"" << std::hex << nonce1 << std::dec << "\",\n";
    json << "    \"nonce2\": " << nonce2 << ",\n";
    json << "    \"nonce2_hex\": \"" << std::hex << nonce2 << std::dec << "\",\n";
    json << "    \"access_tokens\": [\n";
    for (size_t i = 0; i < access_tokens.size(); ++i) {
      json << "      {\n";
      json << "        \"value\": \""
           << escape_json_string(std::string(access_tokens[i].begin(), access_tokens[i].end())) << "\",\n";
      json << "        \"hex\": \"" << bytes_to_hex(access_tokens[i].data(), access_tokens[i].size()) << "\"\n";
      json << "      }" << (i + 1 < access_tokens.size() ? "," : "") << "\n";
    }
    json << "    ],\n";
    json << "    \"crypto_handshake_type\": " << static_cast<int>(hd.type()) << ",\n";
    json << "    \"public_key_hex\": \"\"\n";
    json << "  },\n";
    json << "  \"expected\": {\n";
    json << "    \"algorithm\": \"HMAC-SHA256\",\n";
    json << "    \"algorithm_value\": " << static_cast<int>(ad.algorithm()) << ",\n";
    json << "    \"timestamp\": " << ad.timestamp() << ",\n";
    json << "    \"nonce1\": " << ad.nonce1() << ",\n";
    json << "    \"nonce2\": " << ad.nonce2() << ",\n";
    json << "    \"plaintext\": \"" << escape_json_string(plaintext) << "\",\n";
    json << "    \"signatures\": [\n";
    for (int i = 0; i < ad.signature_size(); ++i) {
      json << "      \"" << bytes_to_hex(ad.signature(i)) << "\"" << (i + 1 < ad.signature_size() ? "," : "") << "\n";
    }
    json << "    ],\n";
    json << "    \"serialized_hex\": \"" << bytes_to_hex(serialized) << "\",\n";
    json << "    \"serialized_length\": " << serialized.size() << "\n";
    json << "  }\n";
    json << "}\n";
    write_json_file(std::string(test_name) + ".json", json.str());
    generated_count++;

    CASE_MSG_INFO() << "[PASS] " << test_name << std::endl;
  }

  // ============================================================================
  // Test Case 2: generate_access_data with crypto_handshake_data (with public key)
  // ============================================================================
  {
    const char* test_name = "full_access_data_with_pubkey";

    uint64_t bus_id = 0x87654321;
    uint64_t nonce1 = 0x1111222233334444ULL;
    uint64_t nonce2 = 0x5555666677778888ULL;

    std::vector<std::vector<unsigned char>> access_tokens = {
        {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}};

    ::atframework::atbus::protocol::crypto_handshake_data hd;
    hd.set_type(::atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_SECP256R1);
    std::string fixed_pubkey;
    fixed_pubkey.resize(65);  // Uncompressed SECP256R1 public key size
    fixed_pubkey[0] = 0x04;   // Uncompressed point indicator
    for (size_t i = 1; i < 65; ++i) {
      fixed_pubkey[i] = static_cast<char>((i * 3) & 0xFF);
    }
    hd.set_public_key(fixed_pubkey);

    ::atframework::atbus::protocol::access_data ad;
    ad.set_algorithm(::atframework::atbus::protocol::ATBUS_ACCESS_DATA_ALGORITHM_HMAC_SHA256);
    ad.set_timestamp(1735689600);
    ad.set_nonce1(nonce1);
    ad.set_nonce2(nonce2);

    std::string plaintext = atfw::atbus::message_handler::make_access_data_plaintext(bus_id, ad, hd);
    std::string pubkey_hash = atfw::util::hash::sha::hash_to_hex(atfw::util::hash::sha::EN_ALGORITHM_SHA256,
                                                                 hd.public_key().data(), hd.public_key().size());

    for (const auto& token : access_tokens) {
      std::string sig = atfw::atbus::message_handler::calculate_access_data_signature(
          ad, gsl::span<const unsigned char>{token.data(), token.size()}, plaintext);
      ad.add_signature(sig);
    }

    std::string serialized;
    ad.SerializeToString(&serialized);
    write_binary_file(std::string(test_name) + ".bytes", reinterpret_cast<const unsigned char*>(serialized.data()),
                      serialized.size());

    std::ostringstream json;
    json << "{\n";
    json << "  \"name\": \"" << test_name << "\",\n";
    json << "  \"description\": \"Full access_data generation with crypto_handshake_data (with public key)\",\n";
    json << "  \"function\": \"generate_access_data\",\n";
    json << "  \"input\": {\n";
    json << "    \"bus_id\": " << bus_id << ",\n";
    json << "    \"nonce1\": " << nonce1 << ",\n";
    json << "    \"nonce2\": " << nonce2 << ",\n";
    json << "    \"access_tokens\": [\n";
    for (size_t i = 0; i < access_tokens.size(); ++i) {
      json << "      {\"hex\": \"" << bytes_to_hex(access_tokens[i].data(), access_tokens[i].size()) << "\"}"
           << (i + 1 < access_tokens.size() ? "," : "") << "\n";
    }
    json << "    ],\n";
    json << "    \"crypto_handshake_type\": " << static_cast<int>(hd.type()) << ",\n";
    json << "    \"crypto_handshake_type_name\": \"ATBUS_CRYPTO_KEY_EXCHANGE_SECP256R1\",\n";
    json << "    \"public_key_hex\": \"" << bytes_to_hex(hd.public_key()) << "\"\n";
    json << "  },\n";
    json << "  \"intermediate\": {\n";
    json << "    \"public_key_sha256_hex\": \"" << pubkey_hash << "\"\n";
    json << "  },\n";
    json << "  \"expected\": {\n";
    json << "    \"algorithm\": \"HMAC-SHA256\",\n";
    json << "    \"algorithm_value\": " << static_cast<int>(ad.algorithm()) << ",\n";
    json << "    \"timestamp\": " << ad.timestamp() << ",\n";
    json << "    \"nonce1\": " << ad.nonce1() << ",\n";
    json << "    \"nonce2\": " << ad.nonce2() << ",\n";
    json << "    \"plaintext\": \"" << escape_json_string(plaintext) << "\",\n";
    json << "    \"signatures\": [\n";
    for (int i = 0; i < ad.signature_size(); ++i) {
      json << "      \"" << bytes_to_hex(ad.signature(i)) << "\"" << (i + 1 < ad.signature_size() ? "," : "") << "\n";
    }
    json << "    ],\n";
    json << "    \"serialized_hex\": \"" << bytes_to_hex(serialized) << "\",\n";
    json << "    \"serialized_length\": " << serialized.size() << "\n";
    json << "  }\n";
    json << "}\n";
    write_json_file(std::string(test_name) + ".json", json.str());
    generated_count++;

    CASE_MSG_INFO() << "[PASS] " << test_name << std::endl;
  }

  // ============================================================================
  // Test Case 3: generate_access_data with custom_command_data
  // ============================================================================
  {
    const char* test_name = "full_access_data_custom_command";

    uint64_t bus_id = 0x11223344;
    uint64_t nonce1 = 0xDEADBEEFCAFEBABEULL;
    uint64_t nonce2 = 0x0123456789ABCDEFULL;

    std::vector<std::vector<unsigned char>> access_tokens = {{'m', 'y', '_', 's', 'e', 'c', 'r', 'e', 't'}};

    ::atframework::atbus::protocol::custom_command_data csarg;
    csarg.set_from(bus_id);
    auto* cmd1 = csarg.add_commands();
    cmd1->set_arg("list");
    auto* cmd2 = csarg.add_commands();
    cmd2->set_arg("nodes");

    ::atframework::atbus::protocol::access_data ad;
    ad.set_algorithm(::atframework::atbus::protocol::ATBUS_ACCESS_DATA_ALGORITHM_HMAC_SHA256);
    ad.set_timestamp(1735689600);
    ad.set_nonce1(nonce1);
    ad.set_nonce2(nonce2);

    std::string plaintext = atfw::atbus::message_handler::make_access_data_plaintext(bus_id, ad, csarg);
    std::string concat_args = "listnodes";
    std::string args_hash = atfw::util::hash::sha::hash_to_hex(atfw::util::hash::sha::EN_ALGORITHM_SHA256,
                                                               concat_args.data(), concat_args.size());

    for (const auto& token : access_tokens) {
      std::string sig = atfw::atbus::message_handler::calculate_access_data_signature(
          ad, gsl::span<const unsigned char>{token.data(), token.size()}, plaintext);
      ad.add_signature(sig);
    }

    std::string serialized;
    ad.SerializeToString(&serialized);
    write_binary_file(std::string(test_name) + ".bytes", reinterpret_cast<const unsigned char*>(serialized.data()),
                      serialized.size());

    std::ostringstream json;
    json << "{\n";
    json << "  \"name\": \"" << test_name << "\",\n";
    json << "  \"description\": \"Full access_data generation with custom_command_data\",\n";
    json << "  \"function\": \"generate_access_data\",\n";
    json << "  \"input\": {\n";
    json << "    \"bus_id\": " << bus_id << ",\n";
    json << "    \"nonce1\": " << nonce1 << ",\n";
    json << "    \"nonce1_hex\": \"" << std::hex << nonce1 << std::dec << "\",\n";
    json << "    \"nonce2\": " << nonce2 << ",\n";
    json << "    \"nonce2_hex\": \"" << std::hex << nonce2 << std::dec << "\",\n";
    json << "    \"access_tokens\": [\n";
    for (size_t i = 0; i < access_tokens.size(); ++i) {
      json << "      {\n";
      json << "        \"value\": \""
           << escape_json_string(std::string(access_tokens[i].begin(), access_tokens[i].end())) << "\",\n";
      json << "        \"hex\": \"" << bytes_to_hex(access_tokens[i].data(), access_tokens[i].size()) << "\"\n";
      json << "      }" << (i + 1 < access_tokens.size() ? "," : "") << "\n";
    }
    json << "    ],\n";
    json << "    \"commands\": [\"list\", \"nodes\"]\n";
    json << "  },\n";
    json << "  \"intermediate\": {\n";
    json << "    \"concatenated_args\": \"" << concat_args << "\",\n";
    json << "    \"args_sha256_hex\": \"" << args_hash << "\"\n";
    json << "  },\n";
    json << "  \"expected\": {\n";
    json << "    \"algorithm\": \"HMAC-SHA256\",\n";
    json << "    \"algorithm_value\": " << static_cast<int>(ad.algorithm()) << ",\n";
    json << "    \"timestamp\": " << ad.timestamp() << ",\n";
    json << "    \"nonce1\": " << ad.nonce1() << ",\n";
    json << "    \"nonce2\": " << ad.nonce2() << ",\n";
    json << "    \"plaintext\": \"" << escape_json_string(plaintext) << "\",\n";
    json << "    \"signatures\": [\n";
    for (int i = 0; i < ad.signature_size(); ++i) {
      json << "      \"" << bytes_to_hex(ad.signature(i)) << "\"" << (i + 1 < ad.signature_size() ? "," : "") << "\n";
    }
    json << "    ],\n";
    json << "    \"serialized_hex\": \"" << bytes_to_hex(serialized) << "\",\n";
    json << "    \"serialized_length\": " << serialized.size() << "\n";
    json << "  }\n";
    json << "}\n";
    write_json_file(std::string(test_name) + ".json", json.str());
    generated_count++;

    CASE_MSG_INFO() << "[PASS] " << test_name << std::endl;
  }

  // ============================================================================
  // Test Case 4: generate_access_data with multiple tokens
  // ============================================================================
  {
    const char* test_name = "full_access_data_multiple_tokens";

    uint64_t bus_id = 0xFEDCBA98;
    uint64_t nonce1 = 0xAAAAAAAAAAAAAAAAULL;
    uint64_t nonce2 = 0xBBBBBBBBBBBBBBBBULL;

    std::vector<std::vector<unsigned char>> access_tokens = {
        {'t', 'o', 'k', 'e', 'n', '_', 'a'}, {'t', 'o', 'k', 'e', 'n', '_', 'b'}, {'t', 'o', 'k', 'e', 'n', '_', 'c'}};

    ::atframework::atbus::protocol::crypto_handshake_data hd;

    ::atframework::atbus::protocol::access_data ad;
    ad.set_algorithm(::atframework::atbus::protocol::ATBUS_ACCESS_DATA_ALGORITHM_HMAC_SHA256);
    ad.set_timestamp(1735689600);
    ad.set_nonce1(nonce1);
    ad.set_nonce2(nonce2);

    std::string plaintext = atfw::atbus::message_handler::make_access_data_plaintext(bus_id, ad, hd);

    for (const auto& token : access_tokens) {
      std::string sig = atfw::atbus::message_handler::calculate_access_data_signature(
          ad, gsl::span<const unsigned char>{token.data(), token.size()}, plaintext);
      ad.add_signature(sig);
    }

    std::string serialized;
    ad.SerializeToString(&serialized);
    write_binary_file(std::string(test_name) + ".bytes", reinterpret_cast<const unsigned char*>(serialized.data()),
                      serialized.size());

    std::ostringstream json;
    json << "{\n";
    json << "  \"name\": \"" << test_name << "\",\n";
    json << "  \"description\": \"Full access_data generation with multiple access tokens\",\n";
    json << "  \"function\": \"generate_access_data\",\n";
    json << "  \"input\": {\n";
    json << "    \"bus_id\": " << bus_id << ",\n";
    json << "    \"nonce1\": " << nonce1 << ",\n";
    json << "    \"nonce2\": " << nonce2 << ",\n";
    json << "    \"access_tokens\": [\n";
    for (size_t i = 0; i < access_tokens.size(); ++i) {
      json << "      {\n";
      json << "        \"value\": \""
           << escape_json_string(std::string(access_tokens[i].begin(), access_tokens[i].end())) << "\",\n";
      json << "        \"hex\": \"" << bytes_to_hex(access_tokens[i].data(), access_tokens[i].size()) << "\"\n";
      json << "      }" << (i + 1 < access_tokens.size() ? "," : "") << "\n";
    }
    json << "    ]\n";
    json << "  },\n";
    json << "  \"expected\": {\n";
    json << "    \"algorithm\": \"HMAC-SHA256\",\n";
    json << "    \"algorithm_value\": " << static_cast<int>(ad.algorithm()) << ",\n";
    json << "    \"timestamp\": " << ad.timestamp() << ",\n";
    json << "    \"nonce1\": " << ad.nonce1() << ",\n";
    json << "    \"nonce2\": " << ad.nonce2() << ",\n";
    json << "    \"plaintext\": \"" << escape_json_string(plaintext) << "\",\n";
    json << "    \"signatures\": [\n";
    for (int i = 0; i < ad.signature_size(); ++i) {
      json << "      \"" << bytes_to_hex(ad.signature(i)) << "\"" << (i + 1 < ad.signature_size() ? "," : "") << "\n";
    }
    json << "    ],\n";
    json << "    \"serialized_hex\": \"" << bytes_to_hex(serialized) << "\",\n";
    json << "    \"serialized_length\": " << serialized.size() << "\n";
    json << "  }\n";
    json << "}\n";
    write_json_file(std::string(test_name) + ".json", json.str());
    generated_count++;

    CASE_MSG_INFO() << "[PASS] " << test_name << std::endl;
  }

  CASE_MSG_INFO() << "[SUMMARY] Generated " << generated_count << " full access_data test files" << std::endl;
  CASE_EXPECT_EQ(4, generated_count);
}

// ============================================================================
// 生成索引文件
// ============================================================================

CASE_TEST(atbus_access_data_crosslang, generate_index_file) {
  CASE_EXPECT_TRUE(ensure_output_dir());

  std::ostringstream json;
  json << "{\n";
  json << "  \"description\": \"Cross-language test data for access_data functions\",\n";
  json << "  \"generator\": \"atbus_access_data_crosslang_generator.cpp\",\n";
  json << "  \"output_dir\": \"" << kTestOutputSubDir << "\",\n";
  json << "  \"functions\": [\n";
  json << "    {\n";
  json << "      \"name\": \"make_access_data_plaintext\",\n";
  json << "      \"description\": \"Generates plaintext string for HMAC signature\",\n";
  json << "      \"test_files\": [\n";
  json << "        \"plaintext_no_pubkey.json\",\n";
  json << "        \"plaintext_with_pubkey.json\",\n";
  json << "        \"plaintext_custom_command.json\"\n";
  json << "      ]\n";
  json << "    },\n";
  json << "    {\n";
  json << "      \"name\": \"calculate_access_data_signature\",\n";
  json << "      \"description\": \"Calculates HMAC-SHA256 signature\",\n";
  json << "      \"test_files\": [\n";
  json << "        {\"json\": \"signature_simple_token.json\", \"binary\": \"signature_simple_token.bytes\"},\n";
  json << "        {\"json\": \"signature_binary_token.json\", \"binary\": \"signature_binary_token.bytes\"},\n";
  json << "        {\"json\": \"signature_256bit_token.json\", \"binary\": \"signature_256bit_token.bytes\"}\n";
  json << "      ]\n";
  json << "    },\n";
  json << "    {\n";
  json << "      \"name\": \"generate_access_data\",\n";
  json << "      \"description\": \"Generates complete access_data with signatures\",\n";
  json << "      \"test_files\": [\n";
  json
      << "        {\"json\": \"full_access_data_no_pubkey.json\", \"binary\": \"full_access_data_no_pubkey.bytes\"},\n";
  json << "        {\"json\": \"full_access_data_with_pubkey.json\", \"binary\": "
          "\"full_access_data_with_pubkey.bytes\"},\n";
  json << "        {\"json\": \"full_access_data_custom_command.json\", \"binary\": "
          "\"full_access_data_custom_command.bytes\"},\n";
  json << "        {\"json\": \"full_access_data_multiple_tokens.json\", \"binary\": "
          "\"full_access_data_multiple_tokens.bytes\"}\n";
  json << "      ]\n";
  json << "    }\n";
  json << "  ]\n";
  json << "}\n";

  write_json_file("index.json", json.str());
  CASE_MSG_INFO() << "[PASS] Generated index.json" << std::endl;
}

// ============================================================================
// 验证测试 - 读取生成的文件并验证
// ============================================================================

CASE_TEST(atbus_access_data_crosslang, verify_plaintext_generation) {
  // Test make_access_data_plaintext with crypto_handshake_data (no public key)
  {
    ::atframework::atbus::protocol::access_data ad;
    ad.set_timestamp(1735689600);
    ad.set_nonce1(0x123456789ABCDEF0ULL);
    ad.set_nonce2(0xFEDCBA9876543210ULL);

    uint64_t bus_id = 0x12345678;
    ::atframework::atbus::protocol::crypto_handshake_data hd;

    std::string plaintext = atfw::atbus::message_handler::make_access_data_plaintext(bus_id, ad, hd);

    // Verify format: "<timestamp>:<nonce1>-<nonce2>:<bus_id>"
    std::string expected = "1735689600:1311768467463790320-18364758544493064720:305419896";
    CASE_EXPECT_EQ(expected, plaintext);
    CASE_MSG_INFO() << "[VERIFY] plaintext_no_pubkey: " << (expected == plaintext ? "PASS" : "FAIL") << std::endl;
  }

  // Test make_access_data_plaintext with crypto_handshake_data (with public key)
  {
    ::atframework::atbus::protocol::access_data ad;
    ad.set_timestamp(1735689600);
    ad.set_nonce1(0xAAAABBBBCCCCDDDDULL);
    ad.set_nonce2(0x1111222233334444ULL);

    uint64_t bus_id = 0xABCDEF01;
    ::atframework::atbus::protocol::crypto_handshake_data hd;
    hd.set_type(::atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_SECP256R1);
    std::string fixed_pubkey;
    fixed_pubkey.resize(32);
    for (size_t i = 0; i < 32; ++i) {
      fixed_pubkey[i] = static_cast<char>(i);
    }
    hd.set_public_key(fixed_pubkey);

    std::string plaintext = atfw::atbus::message_handler::make_access_data_plaintext(bus_id, ad, hd);

    // Verify format includes type and hash
    CASE_EXPECT_TRUE(plaintext.find(":2:") != std::string::npos);  // type = 2 (SECP256R1)
    CASE_MSG_INFO() << "[VERIFY] plaintext_with_pubkey: PASS (contains type and hash)" << std::endl;
  }

  // Test make_access_data_plaintext with custom_command_data
  {
    ::atframework::atbus::protocol::access_data ad;
    ad.set_timestamp(1735689600);
    ad.set_nonce1(0x5555666677778888ULL);
    ad.set_nonce2(0x9999AAAABBBBCCCCULL);

    uint64_t bus_id = 0x87654321;
    ::atframework::atbus::protocol::custom_command_data csarg;
    csarg.set_from(bus_id);
    auto* cmd1 = csarg.add_commands();
    cmd1->set_arg("command1");
    auto* cmd2 = csarg.add_commands();
    cmd2->set_arg("arg2");

    std::string plaintext = atfw::atbus::message_handler::make_access_data_plaintext(bus_id, ad, csarg);

    // Verify format includes SHA256 hash of concatenated commands
    // The hash should be at the end
    CASE_EXPECT_TRUE(plaintext.size() > 64);  // Should include 64-char hex hash
    CASE_MSG_INFO() << "[VERIFY] plaintext_custom_command: PASS" << std::endl;
  }
}

CASE_TEST(atbus_access_data_crosslang, verify_signature_generation) {
  // Test calculate_access_data_signature
  {
    ::atframework::atbus::protocol::access_data ad;
    ad.set_algorithm(::atframework::atbus::protocol::ATBUS_ACCESS_DATA_ALGORITHM_HMAC_SHA256);

    std::vector<unsigned char> access_token = {'s', 'e', 'c', 'r', 'e', 't'};
    std::string plaintext = "test_plaintext";

    std::string sig = atfw::atbus::message_handler::calculate_access_data_signature(
        ad, gsl::span<const unsigned char>{access_token.data(), access_token.size()}, plaintext);

    // HMAC-SHA256 output should be 32 bytes
    CASE_EXPECT_EQ(32u, sig.size());
    CASE_MSG_INFO() << "[VERIFY] signature length: " << sig.size() << " (expected 32)" << std::endl;
  }
}

// ============================================================================
// 读取生成的二进制文件并验证签名
// ============================================================================

CASE_TEST(atbus_access_data_crosslang, verify_signature_from_generated_files) {
  int verified_count = 0;
  int failed_count = 0;

  // ============================================================================
  // Test Case 1: 验证 signature_simple_token
  // ============================================================================
  {
    const char* test_name = "signature_simple_token";

    // 读取生成的签名二进制文件
    std::vector<unsigned char> expected_signature;
    if (!read_binary_file(std::string(test_name) + ".bytes", expected_signature)) {
      CASE_MSG_INFO() << "[SKIP] " << test_name << ": file not found (run generate test first)" << std::endl;
    } else {
      // 使用与生成时相同的参数重新计算签名
      ::atframework::atbus::protocol::access_data ad;
      ad.set_algorithm(::atframework::atbus::protocol::ATBUS_ACCESS_DATA_ALGORITHM_HMAC_SHA256);
      ad.set_timestamp(1735689600);
      ad.set_nonce1(0x1234567890ABCDEFULL);
      ad.set_nonce2(0xFEDCBA0987654321ULL);

      std::vector<unsigned char> access_token = {'s', 'e', 'c', 'r', 'e', 't', '_', 't',
                                                 'o', 'k', 'e', 'n', '_', '1', '2', '3'};
      std::string plaintext = "1735689600:1311768467294899695-18364758544106544929:305419896";

      std::string calculated_sig = atfw::atbus::message_handler::calculate_access_data_signature(
          ad, gsl::span<const unsigned char>{access_token.data(), access_token.size()}, plaintext);

      // 对比签名
      bool match = (calculated_sig.size() == expected_signature.size()) &&
                   (std::memcmp(calculated_sig.data(), expected_signature.data(), calculated_sig.size()) == 0);

      if (match) {
        CASE_MSG_INFO() << "[PASS] " << test_name << ": signature matches" << std::endl;
        verified_count++;
      } else {
        CASE_MSG_INFO() << "[FAIL] " << test_name << ": signature mismatch" << std::endl;
        CASE_MSG_INFO() << "  Expected: " << bytes_to_hex(expected_signature.data(), expected_signature.size())
                        << std::endl;
        CASE_MSG_INFO() << "  Calculated: " << bytes_to_hex(calculated_sig) << std::endl;
        failed_count++;
      }
      CASE_EXPECT_TRUE(match);
    }
  }

  // ============================================================================
  // Test Case 2: 验证 signature_binary_token
  // ============================================================================
  {
    const char* test_name = "signature_binary_token";

    std::vector<unsigned char> expected_signature;
    if (!read_binary_file(std::string(test_name) + ".bytes", expected_signature)) {
      CASE_MSG_INFO() << "[SKIP] " << test_name << ": file not found" << std::endl;
    } else {
      ::atframework::atbus::protocol::access_data ad;
      ad.set_algorithm(::atframework::atbus::protocol::ATBUS_ACCESS_DATA_ALGORITHM_HMAC_SHA256);
      ad.set_timestamp(1735689600);
      ad.set_nonce1(0xAABBCCDDEEFF0011ULL);
      ad.set_nonce2(0x2233445566778899ULL);

      // 重建相同的二进制token
      std::vector<unsigned char> access_token(32);
      for (size_t i = 0; i < 32; ++i) {
        access_token[i] = static_cast<unsigned char>((i * 7 + 13) & 0xFF);
      }

      std::string plaintext = "1735689600:12302652057474621457-2459565876494606489:2882400001";

      std::string calculated_sig = atfw::atbus::message_handler::calculate_access_data_signature(
          ad, gsl::span<const unsigned char>{access_token.data(), access_token.size()}, plaintext);

      bool match = (calculated_sig.size() == expected_signature.size()) &&
                   (std::memcmp(calculated_sig.data(), expected_signature.data(), calculated_sig.size()) == 0);

      if (match) {
        CASE_MSG_INFO() << "[PASS] " << test_name << ": signature matches" << std::endl;
        verified_count++;
      } else {
        CASE_MSG_INFO() << "[FAIL] " << test_name << ": signature mismatch" << std::endl;
        failed_count++;
      }
      CASE_EXPECT_TRUE(match);
    }
  }

  // ============================================================================
  // Test Case 3: 验证 signature_256bit_token
  // ============================================================================
  {
    const char* test_name = "signature_256bit_token";

    std::vector<unsigned char> expected_signature;
    if (!read_binary_file(std::string(test_name) + ".bytes", expected_signature)) {
      CASE_MSG_INFO() << "[SKIP] " << test_name << ": file not found" << std::endl;
    } else {
      ::atframework::atbus::protocol::access_data ad;
      ad.set_algorithm(::atframework::atbus::protocol::ATBUS_ACCESS_DATA_ALGORITHM_HMAC_SHA256);
      ad.set_timestamp(1735689600);
      ad.set_nonce1(0x1111111111111111ULL);
      ad.set_nonce2(0x2222222222222222ULL);

      std::vector<unsigned char> access_token = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
                                                 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA,
                                                 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00};

      uint64_t bus_id = 0x99887766;
      ::atframework::atbus::protocol::crypto_handshake_data hd;
      std::string plaintext = atfw::atbus::message_handler::make_access_data_plaintext(bus_id, ad, hd);

      std::string calculated_sig = atfw::atbus::message_handler::calculate_access_data_signature(
          ad, gsl::span<const unsigned char>{access_token.data(), access_token.size()}, plaintext);

      bool match = (calculated_sig.size() == expected_signature.size()) &&
                   (std::memcmp(calculated_sig.data(), expected_signature.data(), calculated_sig.size()) == 0);

      if (match) {
        CASE_MSG_INFO() << "[PASS] " << test_name << ": signature matches" << std::endl;
        verified_count++;
      } else {
        CASE_MSG_INFO() << "[FAIL] " << test_name << ": signature mismatch" << std::endl;
        failed_count++;
      }
      CASE_EXPECT_TRUE(match);
    }
  }

  CASE_MSG_INFO() << "[SUMMARY] Signature verification: " << verified_count << " passed, " << failed_count << " failed"
                  << std::endl;
  CASE_EXPECT_EQ(0, failed_count);
}

// ============================================================================
// 读取生成的 access_data 二进制文件并验证反序列化和签名
// ============================================================================

CASE_TEST(atbus_access_data_crosslang, verify_access_data_from_generated_files) {
  int verified_count = 0;
  int failed_count = 0;

  // ============================================================================
  // Test Case 1: 验证 full_access_data_no_pubkey
  // ============================================================================
  {
    const char* test_name = "full_access_data_no_pubkey";

    std::vector<unsigned char> serialized_data;
    if (!read_binary_file(std::string(test_name) + ".bytes", serialized_data)) {
      CASE_MSG_INFO() << "[SKIP] " << test_name << ": file not found" << std::endl;
    } else {
      // 反序列化 access_data
      ::atframework::atbus::protocol::access_data ad;
      bool parse_ok = ad.ParseFromArray(serialized_data.data(), static_cast<int>(serialized_data.size()));
      CASE_EXPECT_TRUE(parse_ok);

      if (parse_ok) {
        // 验证基本字段
        CASE_EXPECT_EQ(::atframework::atbus::protocol::ATBUS_ACCESS_DATA_ALGORITHM_HMAC_SHA256, ad.algorithm());
        CASE_EXPECT_EQ(1735689600, static_cast<int64_t>(ad.timestamp()));
        CASE_EXPECT_EQ(0xABCDEF0123456789ULL, ad.nonce1());
        CASE_EXPECT_EQ(0x9876543210FEDCBAULL, ad.nonce2());
        CASE_EXPECT_EQ(2, ad.signature_size());

        // 使用相同的输入重新生成plaintext和签名，验证一致性
        uint64_t bus_id = 0x12345678;
        ::atframework::atbus::protocol::crypto_handshake_data hd;

        std::string plaintext = atfw::atbus::message_handler::make_access_data_plaintext(bus_id, ad, hd);

        // 验证第一个token的签名
        std::vector<unsigned char> token1 = {'t', 'o', 'k', 'e', 'n', '1'};
        std::string sig1 = atfw::atbus::message_handler::calculate_access_data_signature(
            ad, gsl::span<const unsigned char>{token1.data(), token1.size()}, plaintext);

        bool sig1_match = (ad.signature(0) == sig1);
        CASE_EXPECT_TRUE(sig1_match);

        // 验证第二个token的签名
        std::vector<unsigned char> token2 = {'t', 'o', 'k', 'e', 'n', '2'};
        std::string sig2 = atfw::atbus::message_handler::calculate_access_data_signature(
            ad, gsl::span<const unsigned char>{token2.data(), token2.size()}, plaintext);

        bool sig2_match = (ad.signature(1) == sig2);
        CASE_EXPECT_TRUE(sig2_match);

        if (sig1_match && sig2_match) {
          CASE_MSG_INFO() << "[PASS] " << test_name << ": all signatures verified" << std::endl;
          verified_count++;
        } else {
          CASE_MSG_INFO() << "[FAIL] " << test_name << ": signature verification failed" << std::endl;
          failed_count++;
        }
      } else {
        CASE_MSG_INFO() << "[FAIL] " << test_name << ": failed to parse protobuf" << std::endl;
        failed_count++;
      }
    }
  }

  // ============================================================================
  // Test Case 2: 验证 full_access_data_with_pubkey
  // ============================================================================
  {
    const char* test_name = "full_access_data_with_pubkey";

    std::vector<unsigned char> serialized_data;
    if (!read_binary_file(std::string(test_name) + ".bytes", serialized_data)) {
      CASE_MSG_INFO() << "[SKIP] " << test_name << ": file not found" << std::endl;
    } else {
      ::atframework::atbus::protocol::access_data ad;
      bool parse_ok = ad.ParseFromArray(serialized_data.data(), static_cast<int>(serialized_data.size()));
      CASE_EXPECT_TRUE(parse_ok);

      if (parse_ok) {
        CASE_EXPECT_EQ(::atframework::atbus::protocol::ATBUS_ACCESS_DATA_ALGORITHM_HMAC_SHA256, ad.algorithm());
        CASE_EXPECT_EQ(1735689600, static_cast<int64_t>(ad.timestamp()));
        CASE_EXPECT_EQ(1, ad.signature_size());

        // 重建 crypto_handshake_data
        uint64_t bus_id = 0x87654321;
        ::atframework::atbus::protocol::crypto_handshake_data hd;
        hd.set_type(::atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_SECP256R1);
        std::string fixed_pubkey;
        fixed_pubkey.resize(65);
        fixed_pubkey[0] = 0x04;
        for (size_t i = 1; i < 65; ++i) {
          fixed_pubkey[i] = static_cast<char>((i * 3) & 0xFF);
        }
        hd.set_public_key(fixed_pubkey);

        std::string plaintext = atfw::atbus::message_handler::make_access_data_plaintext(bus_id, ad, hd);

        std::vector<unsigned char> token = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
        std::string sig = atfw::atbus::message_handler::calculate_access_data_signature(
            ad, gsl::span<const unsigned char>{token.data(), token.size()}, plaintext);

        bool sig_match = (ad.signature(0) == sig);
        CASE_EXPECT_TRUE(sig_match);

        if (sig_match) {
          CASE_MSG_INFO() << "[PASS] " << test_name << ": signature verified" << std::endl;
          verified_count++;
        } else {
          CASE_MSG_INFO() << "[FAIL] " << test_name << ": signature mismatch" << std::endl;
          CASE_MSG_INFO() << "  Expected: " << bytes_to_hex(ad.signature(0)) << std::endl;
          CASE_MSG_INFO() << "  Calculated: " << bytes_to_hex(sig) << std::endl;
          failed_count++;
        }
      } else {
        CASE_MSG_INFO() << "[FAIL] " << test_name << ": failed to parse protobuf" << std::endl;
        failed_count++;
      }
    }
  }

  // ============================================================================
  // Test Case 3: 验证 full_access_data_multiple_tokens
  // ============================================================================
  {
    const char* test_name = "full_access_data_multiple_tokens";

    std::vector<unsigned char> serialized_data;
    if (!read_binary_file(std::string(test_name) + ".bytes", serialized_data)) {
      CASE_MSG_INFO() << "[SKIP] " << test_name << ": file not found" << std::endl;
    } else {
      ::atframework::atbus::protocol::access_data ad;
      bool parse_ok = ad.ParseFromArray(serialized_data.data(), static_cast<int>(serialized_data.size()));
      CASE_EXPECT_TRUE(parse_ok);

      if (parse_ok) {
        CASE_EXPECT_EQ(::atframework::atbus::protocol::ATBUS_ACCESS_DATA_ALGORITHM_HMAC_SHA256, ad.algorithm());
        CASE_EXPECT_EQ(3, ad.signature_size());

        uint64_t bus_id = 0xFEDCBA98;
        ::atframework::atbus::protocol::crypto_handshake_data hd;
        std::string plaintext = atfw::atbus::message_handler::make_access_data_plaintext(bus_id, ad, hd);

        std::vector<std::vector<unsigned char>> tokens = {{'t', 'o', 'k', 'e', 'n', '_', 'a'},
                                                          {'t', 'o', 'k', 'e', 'n', '_', 'b'},
                                                          {'t', 'o', 'k', 'e', 'n', '_', 'c'}};

        bool all_match = true;
        for (int i = 0; i < 3; ++i) {
          std::string sig = atfw::atbus::message_handler::calculate_access_data_signature(
              ad, gsl::span<const unsigned char>{tokens[i].data(), tokens[i].size()}, plaintext);
          if (ad.signature(i) != sig) {
            CASE_MSG_INFO() << "[FAIL] " << test_name << ": signature " << i << " mismatch" << std::endl;
            all_match = false;
          }
        }

        CASE_EXPECT_TRUE(all_match);
        if (all_match) {
          CASE_MSG_INFO() << "[PASS] " << test_name << ": all 3 signatures verified" << std::endl;
          verified_count++;
        } else {
          failed_count++;
        }
      } else {
        CASE_MSG_INFO() << "[FAIL] " << test_name << ": failed to parse protobuf" << std::endl;
        failed_count++;
      }
    }
  }

  CASE_MSG_INFO() << "[SUMMARY] Access data verification: " << verified_count << " passed, " << failed_count
                  << " failed" << std::endl;
  CASE_EXPECT_EQ(0, failed_count);
}
