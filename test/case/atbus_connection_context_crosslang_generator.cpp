// Copyright 2026 atframework
// This file generates binary test data files for cross-language pack/unpack verification.

#include <atbus_connection_context.h>
#include <libatbus_protocol.h>

#include <detail/buffer.h>
#include <detail/libatbus_error.h>

#include <algorithm/compression.h>
#include <algorithm/crypto_cipher.h>
#include <algorithm/crypto_dh.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
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

#ifdef CRYPTO_DH_ENABLED
struct openssl_test_init_wrapper_for_crosslang_generator {
  openssl_test_init_wrapper_for_crosslang_generator() { atfw::util::crypto::cipher::init_global_algorithm(); }
  ~openssl_test_init_wrapper_for_crosslang_generator() { atfw::util::crypto::cipher::cleanup_global_algorithm(); }
};

static std::shared_ptr<openssl_test_init_wrapper_for_crosslang_generator> openssl_test_inited_for_crosslang_generator;

static void ensure_openssl_initialized_for_generator() {
  if (!openssl_test_inited_for_crosslang_generator) {
    openssl_test_inited_for_crosslang_generator = std::make_shared<openssl_test_init_wrapper_for_crosslang_generator>();
  }
}
#endif

// 测试数据输出子目录
static const char* kTestOutputSubDir = "atbus_connection_context_enc_dec";

// 获取源码目录路径（基于 __FILE__ 宏）
static std::string get_source_dir() {
  std::string file_path = __FILE__;
  // 处理 Windows 和 Unix 路径分隔符
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

// 写入二进制文件 (.bytes)
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

// 写入JSON元数据文件
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

// 读取二进制文件 (.bytes)
static bool read_binary_file(const std::string& filename, std::vector<unsigned char>& out_data) {
  std::string path = get_output_dir() + "/" + filename;
  std::ifstream file(path, std::ios::binary | std::ios::ate);
  if (!file.is_open()) {
    CASE_MSG_INFO() << "File not found: " << path << std::endl;
    return false;
  }
  std::streamsize size = file.tellg();
  file.seekg(0, std::ios::beg);
  out_data.resize(static_cast<size_t>(size));
  if (!file.read(reinterpret_cast<char*>(out_data.data()), size)) {
    CASE_MSG_INFO() << "Failed to read file: " << path << std::endl;
    return false;
  }
  file.close();
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

// 生成JSON数组
static std::string string_vector_to_json_array(const std::vector<std::string>& vec) {
  std::ostringstream oss;
  oss << "[";
  for (size_t i = 0; i < vec.size(); ++i) {
    if (i > 0) oss << ", ";
    oss << "\"" << escape_json_string(vec[i]) << "\"";
  }
  oss << "]";
  return oss.str();
}

static bool parse_message_head_from_buffer(const unsigned char* data, size_t size,
                                           ::atframework::atbus::protocol::message_head& out_head,
                                           size_t& out_head_size, size_t& out_head_vint_size) {
  if (data == nullptr || size == 0) {
    return false;
  }

  uint64_t head_size = 0;
  out_head_vint_size = ::atframework::atbus::detail::fn::read_vint(head_size, data, size);
  if (out_head_vint_size == 0 || head_size == 0) {
    return false;
  }
  if (out_head_vint_size + static_cast<size_t>(head_size) > size) {
    return false;
  }
  if (!out_head.ParseFromArray(data + out_head_vint_size, static_cast<int>(head_size))) {
    return false;
  }

  out_head_size = static_cast<size_t>(head_size);
  return true;
}

#ifdef ATFW_UTIL_MACRO_COMPRESSION_ENABLED
struct compression_algorithm_info {
  atframework::atbus::protocol::ATBUS_COMPRESSION_ALGORITHM_TYPE type;
  std::string name;
};

static std::vector<compression_algorithm_info> build_supported_compression_algorithms() {
  std::vector<compression_algorithm_info> ret;
  auto supported = ::atfw::util::compression::get_supported_algorithms();
  for (const auto& alg : supported) {
    switch (alg) {
      case ::atfw::util::compression::algorithm_t::kZstd:
        ret.push_back({atframework::atbus::protocol::ATBUS_COMPRESSION_ALGORITHM_ZSTD, "zstd"});
        break;
      case ::atfw::util::compression::algorithm_t::kLz4:
        ret.push_back({atframework::atbus::protocol::ATBUS_COMPRESSION_ALGORITHM_LZ4, "lz4"});
        break;
      case ::atfw::util::compression::algorithm_t::kSnappy:
        ret.push_back({atframework::atbus::protocol::ATBUS_COMPRESSION_ALGORITHM_SNAPPY, "snappy"});
        break;
      case ::atfw::util::compression::algorithm_t::kZlib:
        ret.push_back({atframework::atbus::protocol::ATBUS_COMPRESSION_ALGORITHM_ZLIB, "zlib"});
        break;
      default:
        break;
    }
  }
  return ret;
}
#endif

}  // namespace

// ============================================================================
// 生成无加密的测试数据文件
// ============================================================================

CASE_TEST(atbus_connection_context_crosslang, generate_no_encryption_test_files) {
  CASE_EXPECT_TRUE(ensure_output_dir());

  auto ctx =
      atfw::atbus::connection_context::create(atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_NONE, nullptr);
  CASE_EXPECT_NE(nullptr, ctx.get());

  atfw::atbus::random_engine_t random_engine;
  random_engine.init_seed(12345);  // 固定种子保证可复现

  int32_t protocol_version = atframework::atbus::protocol::ATBUS_PROTOCOL_VERSION;
  ::google::protobuf::ArenaOptions arena_options;

  int generated_count = 0;

  // ============================================================================
  // Test Case 1: node_ping_req
  // ============================================================================
  {
    const char* test_name = "no_enc_ping_req";
    int64_t time_point = 1735689600000;  // 2025-01-01 00:00:00 UTC in ms

    atfw::atbus::message msg(arena_options);
    auto* ping = msg.mutable_body().mutable_node_ping_req();
    ping->set_time_point(time_point);

    auto pack_result = ctx->pack_message(msg, protocol_version, random_engine, 1024 * 1024);
    if (pack_result.is_success()) {
      auto* buffer = pack_result.get_success();
      write_binary_file(std::string(test_name) + ".bytes", buffer->data(), buffer->used());

      std::ostringstream json;
      json << "{\n";
      json << "  \"name\": \"" << test_name << "\",\n";
      json << "  \"description\": \"Ping request message without encryption\",\n";
      json << "  \"protocol_version\": " << protocol_version << ",\n";
      json << "  \"body_type\": \"node_ping_req\",\n";
      json << "  \"body_type_case\": 21,\n";
      json << "  \"crypto_algorithm\": \"NONE\",\n";
      json << "  \"packed_size\": " << buffer->used() << ",\n";
      json << "  \"packed_hex\": \"" << bytes_to_hex(buffer->data(), buffer->used()) << "\",\n";
      json << "  \"expected\": {\n";
      json << "    \"time_point\": " << time_point << "\n";
      json << "  }\n";
      json << "}\n";
      write_json_file(std::string(test_name) + ".json", json.str());
      generated_count++;
    }
  }

  // ============================================================================
  // Test Case 2: node_pong_rsp
  // ============================================================================
  {
    const char* test_name = "no_enc_pong_rsp";
    int64_t time_point = 1735689600123;

    atfw::atbus::message msg(arena_options);
    auto* pong = msg.mutable_body().mutable_node_pong_rsp();
    pong->set_time_point(time_point);

    auto pack_result = ctx->pack_message(msg, protocol_version, random_engine, 1024 * 1024);
    if (pack_result.is_success()) {
      auto* buffer = pack_result.get_success();
      write_binary_file(std::string(test_name) + ".bytes", buffer->data(), buffer->used());

      std::ostringstream json;
      json << "{\n";
      json << "  \"name\": \"" << test_name << "\",\n";
      json << "  \"description\": \"Pong response message without encryption\",\n";
      json << "  \"protocol_version\": " << protocol_version << ",\n";
      json << "  \"body_type\": \"node_pong_rsp\",\n";
      json << "  \"body_type_case\": 22,\n";
      json << "  \"crypto_algorithm\": \"NONE\",\n";
      json << "  \"packed_size\": " << buffer->used() << ",\n";
      json << "  \"packed_hex\": \"" << bytes_to_hex(buffer->data(), buffer->used()) << "\",\n";
      json << "  \"expected\": {\n";
      json << "    \"time_point\": " << time_point << "\n";
      json << "  }\n";
      json << "}\n";
      write_json_file(std::string(test_name) + ".json", json.str());
      generated_count++;
    }
  }

  // ============================================================================
  // Test Case 3: data_transform_req (simple)
  // ============================================================================
  {
    const char* test_name = "no_enc_data_transform_req_simple";
    uint64_t from = 0x10001;
    uint64_t to = 0x10002;
    std::string content = "Hello, atbus!";
    uint32_t flags = 0;

    atfw::atbus::message msg(arena_options);
    auto* fwd = msg.mutable_body().mutable_data_transform_req();
    fwd->set_from(from);
    fwd->set_to(to);
    fwd->set_content(content);
    fwd->set_flags(flags);

    auto pack_result = ctx->pack_message(msg, protocol_version, random_engine, 1024 * 1024);
    if (pack_result.is_success()) {
      auto* buffer = pack_result.get_success();
      write_binary_file(std::string(test_name) + ".bytes", buffer->data(), buffer->used());

      std::ostringstream json;
      json << "{\n";
      json << "  \"name\": \"" << test_name << "\",\n";
      json << "  \"description\": \"Data transform request with simple content\",\n";
      json << "  \"protocol_version\": " << protocol_version << ",\n";
      json << "  \"body_type\": \"data_transform_req\",\n";
      json << "  \"body_type_case\": 13,\n";
      json << "  \"crypto_algorithm\": \"NONE\",\n";
      json << "  \"packed_size\": " << buffer->used() << ",\n";
      json << "  \"packed_hex\": \"" << bytes_to_hex(buffer->data(), buffer->used()) << "\",\n";
      json << "  \"expected\": {\n";
      json << "    \"from\": " << from << ",\n";
      json << "    \"to\": " << to << ",\n";
      json << "    \"content\": \"" << escape_json_string(content) << "\",\n";
      json << "    \"content_hex\": \""
           << bytes_to_hex(reinterpret_cast<const unsigned char*>(content.data()), content.size()) << "\",\n";
      json << "    \"flags\": " << flags << "\n";
      json << "  }\n";
      json << "}\n";
      write_json_file(std::string(test_name) + ".json", json.str());
      generated_count++;
    }
  }

  // ============================================================================
  // Test Case 4: data_transform_req with require response flag
  // ============================================================================
  {
    const char* test_name = "no_enc_data_transform_req_with_rsp_flag";
    uint64_t from = 0x20001;
    uint64_t to = 0x20002;
    std::string content = "Request with response flag";
    uint32_t flags = atframework::atbus::protocol::FORWARD_DATA_FLAG_REQUIRE_RSP;

    atfw::atbus::message msg(arena_options);
    auto* fwd = msg.mutable_body().mutable_data_transform_req();
    fwd->set_from(from);
    fwd->set_to(to);
    fwd->set_content(content);
    fwd->set_flags(flags);

    auto pack_result = ctx->pack_message(msg, protocol_version, random_engine, 1024 * 1024);
    if (pack_result.is_success()) {
      auto* buffer = pack_result.get_success();
      write_binary_file(std::string(test_name) + ".bytes", buffer->data(), buffer->used());

      std::ostringstream json;
      json << "{\n";
      json << "  \"name\": \"" << test_name << "\",\n";
      json << "  \"description\": \"Data transform request requiring response\",\n";
      json << "  \"protocol_version\": " << protocol_version << ",\n";
      json << "  \"body_type\": \"data_transform_req\",\n";
      json << "  \"body_type_case\": 13,\n";
      json << "  \"crypto_algorithm\": \"NONE\",\n";
      json << "  \"packed_size\": " << buffer->used() << ",\n";
      json << "  \"packed_hex\": \"" << bytes_to_hex(buffer->data(), buffer->used()) << "\",\n";
      json << "  \"expected\": {\n";
      json << "    \"from\": " << from << ",\n";
      json << "    \"to\": " << to << ",\n";
      json << "    \"content\": \"" << escape_json_string(content) << "\",\n";
      json << "    \"content_hex\": \""
           << bytes_to_hex(reinterpret_cast<const unsigned char*>(content.data()), content.size()) << "\",\n";
      json << "    \"flags\": " << flags << "\n";
      json << "  }\n";
      json << "}\n";
      write_json_file(std::string(test_name) + ".json", json.str());
      generated_count++;
    }
  }

  // ============================================================================
  // Test Case 5: data_transform_rsp
  // ============================================================================
  {
    const char* test_name = "no_enc_data_transform_rsp";
    uint64_t from = 0x10002;
    uint64_t to = 0x10001;
    std::string content = "Response content";
    uint32_t flags = 0;

    atfw::atbus::message msg(arena_options);
    auto* fwd = msg.mutable_body().mutable_data_transform_rsp();
    fwd->set_from(from);
    fwd->set_to(to);
    fwd->set_content(content);
    fwd->set_flags(flags);

    auto pack_result = ctx->pack_message(msg, protocol_version, random_engine, 1024 * 1024);
    if (pack_result.is_success()) {
      auto* buffer = pack_result.get_success();
      write_binary_file(std::string(test_name) + ".bytes", buffer->data(), buffer->used());

      std::ostringstream json;
      json << "{\n";
      json << "  \"name\": \"" << test_name << "\",\n";
      json << "  \"description\": \"Data transform response message\",\n";
      json << "  \"protocol_version\": " << protocol_version << ",\n";
      json << "  \"body_type\": \"data_transform_rsp\",\n";
      json << "  \"body_type_case\": 14,\n";
      json << "  \"crypto_algorithm\": \"NONE\",\n";
      json << "  \"packed_size\": " << buffer->used() << ",\n";
      json << "  \"packed_hex\": \"" << bytes_to_hex(buffer->data(), buffer->used()) << "\",\n";
      json << "  \"expected\": {\n";
      json << "    \"from\": " << from << ",\n";
      json << "    \"to\": " << to << ",\n";
      json << "    \"content\": \"" << escape_json_string(content) << "\",\n";
      json << "    \"content_hex\": \""
           << bytes_to_hex(reinterpret_cast<const unsigned char*>(content.data()), content.size()) << "\",\n";
      json << "    \"flags\": " << flags << "\n";
      json << "  }\n";
      json << "}\n";
      write_json_file(std::string(test_name) + ".json", json.str());
      generated_count++;
    }
  }

  // ============================================================================
  // Test Case 6: custom_command_req
  // ============================================================================
  {
    const char* test_name = "no_enc_custom_command_req";
    uint64_t from = 0x30001;
    std::vector<std::string> commands = {"cmd1", "arg1", "arg2"};

    atfw::atbus::message msg(arena_options);
    auto* custom = msg.mutable_body().mutable_custom_command_req();
    custom->set_from(from);
    for (const auto& cmd : commands) {
      auto* argv = custom->add_commands();
      argv->set_arg(cmd);
    }

    auto pack_result = ctx->pack_message(msg, protocol_version, random_engine, 1024 * 1024);
    if (pack_result.is_success()) {
      auto* buffer = pack_result.get_success();
      write_binary_file(std::string(test_name) + ".bytes", buffer->data(), buffer->used());

      std::ostringstream json;
      json << "{\n";
      json << "  \"name\": \"" << test_name << "\",\n";
      json << "  \"description\": \"Custom command request with multiple arguments\",\n";
      json << "  \"protocol_version\": " << protocol_version << ",\n";
      json << "  \"body_type\": \"custom_command_req\",\n";
      json << "  \"body_type_case\": 11,\n";
      json << "  \"crypto_algorithm\": \"NONE\",\n";
      json << "  \"packed_size\": " << buffer->used() << ",\n";
      json << "  \"packed_hex\": \"" << bytes_to_hex(buffer->data(), buffer->used()) << "\",\n";
      json << "  \"expected\": {\n";
      json << "    \"from\": " << from << ",\n";
      json << "    \"commands\": " << string_vector_to_json_array(commands) << "\n";
      json << "  }\n";
      json << "}\n";
      write_json_file(std::string(test_name) + ".json", json.str());
      generated_count++;
    }
  }

  // ============================================================================
  // Test Case 7: custom_command_rsp
  // ============================================================================
  {
    const char* test_name = "no_enc_custom_command_rsp";
    uint64_t from = 0x30002;
    std::vector<std::string> commands = {"result", "success"};

    atfw::atbus::message msg(arena_options);
    auto* custom = msg.mutable_body().mutable_custom_command_rsp();
    custom->set_from(from);
    for (const auto& cmd : commands) {
      auto* argv = custom->add_commands();
      argv->set_arg(cmd);
    }

    auto pack_result = ctx->pack_message(msg, protocol_version, random_engine, 1024 * 1024);
    if (pack_result.is_success()) {
      auto* buffer = pack_result.get_success();
      write_binary_file(std::string(test_name) + ".bytes", buffer->data(), buffer->used());

      std::ostringstream json;
      json << "{\n";
      json << "  \"name\": \"" << test_name << "\",\n";
      json << "  \"description\": \"Custom command response message\",\n";
      json << "  \"protocol_version\": " << protocol_version << ",\n";
      json << "  \"body_type\": \"custom_command_rsp\",\n";
      json << "  \"body_type_case\": 12,\n";
      json << "  \"crypto_algorithm\": \"NONE\",\n";
      json << "  \"packed_size\": " << buffer->used() << ",\n";
      json << "  \"packed_hex\": \"" << bytes_to_hex(buffer->data(), buffer->used()) << "\",\n";
      json << "  \"expected\": {\n";
      json << "    \"from\": " << from << ",\n";
      json << "    \"commands\": " << string_vector_to_json_array(commands) << "\n";
      json << "  }\n";
      json << "}\n";
      write_json_file(std::string(test_name) + ".json", json.str());
      generated_count++;
    }
  }

  // ============================================================================
  // Test Case 8: node_register_req
  // ============================================================================
  {
    const char* test_name = "no_enc_node_register_req";
    uint64_t bus_id = 0x40001;
    int32_t pid = 12345;
    std::string hostname = "test-host";
    std::vector<std::string> channels = {"ipv4://127.0.0.1:8800", "unix:///tmp/atbus.sock"};

    atfw::atbus::message msg(arena_options);
    auto* reg = msg.mutable_body().mutable_node_register_req();
    reg->set_bus_id(bus_id);
    reg->set_pid(pid);
    reg->set_hostname(hostname);
    for (const auto& ch : channels) {
      auto* channel = reg->add_channels();
      channel->set_address(ch);
    }

    auto pack_result = ctx->pack_message(msg, protocol_version, random_engine, 1024 * 1024);
    if (pack_result.is_success()) {
      auto* buffer = pack_result.get_success();
      write_binary_file(std::string(test_name) + ".bytes", buffer->data(), buffer->used());

      std::ostringstream json;
      json << "{\n";
      json << "  \"name\": \"" << test_name << "\",\n";
      json << "  \"description\": \"Node registration request message\",\n";
      json << "  \"protocol_version\": " << protocol_version << ",\n";
      json << "  \"body_type\": \"node_register_req\",\n";
      json << "  \"body_type_case\": 17,\n";
      json << "  \"crypto_algorithm\": \"NONE\",\n";
      json << "  \"packed_size\": " << buffer->used() << ",\n";
      json << "  \"packed_hex\": \"" << bytes_to_hex(buffer->data(), buffer->used()) << "\",\n";
      json << "  \"expected\": {\n";
      json << "    \"bus_id\": " << bus_id << ",\n";
      json << "    \"pid\": " << pid << ",\n";
      json << "    \"hostname\": \"" << escape_json_string(hostname) << "\",\n";
      json << "    \"channels\": " << string_vector_to_json_array(channels) << "\n";
      json << "  }\n";
      json << "}\n";
      write_json_file(std::string(test_name) + ".json", json.str());
      generated_count++;
    }
  }

  // ============================================================================
  // Test Case 9: node_register_rsp
  // ============================================================================
  {
    const char* test_name = "no_enc_node_register_rsp";
    uint64_t bus_id = 0x40002;
    int32_t pid = 12346;
    std::string hostname = "peer-host";
    std::vector<std::string> channels = {"ipv4://192.168.1.1:8800"};

    atfw::atbus::message msg(arena_options);
    auto* reg = msg.mutable_body().mutable_node_register_rsp();
    reg->set_bus_id(bus_id);
    reg->set_pid(pid);
    reg->set_hostname(hostname);
    for (const auto& ch : channels) {
      auto* channel = reg->add_channels();
      channel->set_address(ch);
    }

    auto pack_result = ctx->pack_message(msg, protocol_version, random_engine, 1024 * 1024);
    if (pack_result.is_success()) {
      auto* buffer = pack_result.get_success();
      write_binary_file(std::string(test_name) + ".bytes", buffer->data(), buffer->used());

      std::ostringstream json;
      json << "{\n";
      json << "  \"name\": \"" << test_name << "\",\n";
      json << "  \"description\": \"Node registration response message\",\n";
      json << "  \"protocol_version\": " << protocol_version << ",\n";
      json << "  \"body_type\": \"node_register_rsp\",\n";
      json << "  \"body_type_case\": 18,\n";
      json << "  \"crypto_algorithm\": \"NONE\",\n";
      json << "  \"packed_size\": " << buffer->used() << ",\n";
      json << "  \"packed_hex\": \"" << bytes_to_hex(buffer->data(), buffer->used()) << "\",\n";
      json << "  \"expected\": {\n";
      json << "    \"bus_id\": " << bus_id << ",\n";
      json << "    \"pid\": " << pid << ",\n";
      json << "    \"hostname\": \"" << escape_json_string(hostname) << "\",\n";
      json << "    \"channels\": " << string_vector_to_json_array(channels) << "\n";
      json << "  }\n";
      json << "}\n";
      write_json_file(std::string(test_name) + ".json", json.str());
      generated_count++;
    }
  }

  // ============================================================================
  // Test Case 13: data_transform_req with binary content (all byte values 0-255)
  // ============================================================================
  {
    const char* test_name = "no_enc_data_transform_binary_content";
    uint64_t from = 0x80001;
    uint64_t to = 0x80002;
    std::string content;
    content.reserve(256);
    for (int i = 0; i < 256; ++i) {
      content.push_back(static_cast<char>(i));
    }
    uint32_t flags = 0;

    atfw::atbus::message msg(arena_options);
    auto* fwd = msg.mutable_body().mutable_data_transform_req();
    fwd->set_from(from);
    fwd->set_to(to);
    fwd->set_content(content);
    fwd->set_flags(flags);

    auto pack_result = ctx->pack_message(msg, protocol_version, random_engine, 1024 * 1024);
    if (pack_result.is_success()) {
      auto* buffer = pack_result.get_success();
      write_binary_file(std::string(test_name) + ".bytes", buffer->data(), buffer->used());

      std::ostringstream json;
      json << "{\n";
      json << "  \"name\": \"" << test_name << "\",\n";
      json << "  \"description\": \"Data transform with binary content (all 256 byte values)\",\n";
      json << "  \"protocol_version\": " << protocol_version << ",\n";
      json << "  \"body_type\": \"data_transform_req\",\n";
      json << "  \"body_type_case\": 13,\n";
      json << "  \"crypto_algorithm\": \"NONE\",\n";
      json << "  \"packed_size\": " << buffer->used() << ",\n";
      json << "  \"packed_hex\": \"" << bytes_to_hex(buffer->data(), buffer->used()) << "\",\n";
      json << "  \"expected\": {\n";
      json << "    \"from\": " << from << ",\n";
      json << "    \"to\": " << to << ",\n";
      json << "    \"content_hex\": \""
           << bytes_to_hex(reinterpret_cast<const unsigned char*>(content.data()), content.size()) << "\",\n";
      json << "    \"content_size\": " << content.size() << ",\n";
      json << "    \"flags\": " << flags << "\n";
      json << "  }\n";
      json << "}\n";
      write_json_file(std::string(test_name) + ".json", json.str());
      generated_count++;
    }
  }

  // ============================================================================
  // Test Case 14: data_transform_req with large content (1KB)
  // ============================================================================
  {
    const char* test_name = "no_enc_data_transform_large_content";
    uint64_t from = 0x70001;
    uint64_t to = 0x70002;
    std::string content(1024, 'X');  // 1KB of 'X'
    uint32_t flags = 0;

    atfw::atbus::message msg(arena_options);
    auto* fwd = msg.mutable_body().mutable_data_transform_req();
    fwd->set_from(from);
    fwd->set_to(to);
    fwd->set_content(content);
    fwd->set_flags(flags);

    auto pack_result = ctx->pack_message(msg, protocol_version, random_engine, 1024 * 1024);
    if (pack_result.is_success()) {
      auto* buffer = pack_result.get_success();
      write_binary_file(std::string(test_name) + ".bytes", buffer->data(), buffer->used());

      std::ostringstream json;
      json << "{\n";
      json << "  \"name\": \"" << test_name << "\",\n";
      json << "  \"description\": \"Data transform with large content (1KB)\",\n";
      json << "  \"protocol_version\": " << protocol_version << ",\n";
      json << "  \"body_type\": \"data_transform_req\",\n";
      json << "  \"body_type_case\": 13,\n";
      json << "  \"crypto_algorithm\": \"NONE\",\n";
      json << "  \"packed_size\": " << buffer->used() << ",\n";
      json << "  \"packed_hex\": \"" << bytes_to_hex(buffer->data(), buffer->used()) << "\",\n";
      json << "  \"expected\": {\n";
      json << "    \"from\": " << from << ",\n";
      json << "    \"to\": " << to << ",\n";
      json << "    \"content_pattern\": \"X\",\n";
      json << "    \"content_size\": " << content.size() << ",\n";
      json << "    \"flags\": " << flags << "\n";
      json << "  }\n";
      json << "}\n";
      write_json_file(std::string(test_name) + ".json", json.str());
      generated_count++;
    }
  }

  // ============================================================================
  // Test Case 15: data_transform_req with UTF-8 content
  // ============================================================================
  {
    const char* test_name = "no_enc_data_transform_utf8_content";
    uint64_t from = 0x90001;
    uint64_t to = 0x90002;
    // UTF-8多语言内容 (C++14兼容的UTF-8字符串)
    // "Hello, 世界! Привет мир! مرحبا! 🌍🌎🌏"
    const unsigned char utf8_content[] = {
        0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20,                                      // "Hello, "
        0xe4, 0xb8, 0x96, 0xe7, 0x95, 0x8c, 0x21, 0x20,                                // "世界! "
        0xd0, 0x9f, 0xd1, 0x80, 0xd0, 0xb8, 0xd0, 0xb2, 0xd0, 0xb5, 0xd1, 0x82, 0x20,  // "Привет "
        0xd0, 0xbc, 0xd0, 0xb8, 0xd1, 0x80, 0x21, 0x20,                                // "мир! "
        0xd9, 0x85, 0xd8, 0xb1, 0xd8, 0xad, 0xd8, 0xa8, 0xd8, 0xa7, 0x21, 0x20,        // "مرحبا! "
        0xf0, 0x9f, 0x8c, 0x8d, 0xf0, 0x9f, 0x8c, 0x8e, 0xf0, 0x9f, 0x8c, 0x8f         // "🌍🌎🌏"
    };
    std::string content(reinterpret_cast<const char*>(utf8_content), sizeof(utf8_content));
    uint32_t flags = 0;

    atfw::atbus::message msg(arena_options);
    auto* fwd = msg.mutable_body().mutable_data_transform_req();
    fwd->set_from(from);
    fwd->set_to(to);
    fwd->set_content(content);
    fwd->set_flags(flags);

    auto pack_result = ctx->pack_message(msg, protocol_version, random_engine, 1024 * 1024);
    if (pack_result.is_success()) {
      auto* buffer = pack_result.get_success();
      write_binary_file(std::string(test_name) + ".bytes", buffer->data(), buffer->used());

      std::ostringstream json;
      json << "{\n";
      json << "  \"name\": \"" << test_name << "\",\n";
      json << "  \"description\": \"Data transform with UTF-8 multilingual content\",\n";
      json << "  \"protocol_version\": " << protocol_version << ",\n";
      json << "  \"body_type\": \"data_transform_req\",\n";
      json << "  \"body_type_case\": 13,\n";
      json << "  \"crypto_algorithm\": \"NONE\",\n";
      json << "  \"packed_size\": " << buffer->used() << ",\n";
      json << "  \"packed_hex\": \"" << bytes_to_hex(buffer->data(), buffer->used()) << "\",\n";
      json << "  \"expected\": {\n";
      json << "    \"from\": " << from << ",\n";
      json << "    \"to\": " << to << ",\n";
      json << "    \"content_hex\": \""
           << bytes_to_hex(reinterpret_cast<const unsigned char*>(content.data()), content.size()) << "\",\n";
      json << "    \"content_size\": " << content.size() << ",\n";
      json << "    \"flags\": " << flags << "\n";
      json << "  }\n";
      json << "}\n";
      write_json_file(std::string(test_name) + ".json", json.str());
      generated_count++;
    }
  }

  CASE_MSG_INFO() << "Generated " << generated_count << " no-encryption test files in " << get_output_dir()
                  << std::endl;
  CASE_EXPECT_EQ(12, generated_count);
}

// ============================================================================
// 验证生成的文件可以正确解包
// ============================================================================

CASE_TEST(atbus_connection_context_crosslang, verify_generated_no_encryption_files) {
  auto ctx =
      atfw::atbus::connection_context::create(atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_NONE, nullptr);
  CASE_EXPECT_NE(nullptr, ctx.get());

  // 读取并验证所有生成的bin文件
  std::vector<std::string> test_files = {
      "no_enc_ping_req",
      "no_enc_pong_rsp",
      "no_enc_data_transform_req_simple",
      "no_enc_data_transform_req_with_rsp_flag",
      "no_enc_data_transform_rsp",
      "no_enc_custom_command_req",
      "no_enc_custom_command_rsp",
      "no_enc_node_register_req",
      "no_enc_node_register_rsp",
      "no_enc_data_transform_binary_content",
      "no_enc_data_transform_large_content",
      "no_enc_data_transform_utf8_content",
  };

  ::google::protobuf::ArenaOptions arena_options;
  int verified_count = 0;

  for (const auto& test_name : test_files) {
    std::vector<unsigned char> buffer;
    if (!read_binary_file(test_name + ".bytes", buffer)) {
      CASE_MSG_INFO() << "File not found (run generate test first): " << test_name << std::endl;
      continue;
    }

    // 解包验证
    atfw::atbus::message msg(arena_options);
    gsl::span<const unsigned char> input_span(buffer.data(), buffer.size());
    int result = ctx->unpack_message(msg, input_span, 1024 * 1024);
    if (result != EN_ATBUS_ERR_SUCCESS) {
      CASE_MSG_INFO() << "Failed to unpack " << test_name << ": error " << result << std::endl;
      CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, result);
      continue;
    }

    // 验证body不为空
    auto* body = msg.get_body();
    CASE_EXPECT_NE(nullptr, body);
    if (body != nullptr) {
      CASE_MSG_INFO() << "Verified: " << test_name << " (body_type_case=" << body->message_type_case() << ")"
                      << std::endl;
      verified_count++;
    }
  }

  CASE_MSG_INFO() << "Verified " << verified_count << " files" << std::endl;
}

#ifdef ATFW_UTIL_MACRO_COMPRESSION_ENABLED
// ============================================================================
// 生成仅压缩的测试数据文件
// ============================================================================

CASE_TEST(atbus_connection_context_crosslang, generate_compressed_test_files) {
  CASE_EXPECT_TRUE(ensure_output_dir());

  auto compression_algorithms = build_supported_compression_algorithms();
  if (compression_algorithms.empty()) {
    CASE_MSG_INFO() << "No compression algorithm available, skipping generation" << std::endl;
    return;
  }

  atfw::atbus::random_engine_t random_engine;
  random_engine.init_seed(12345);

  int32_t protocol_version = atframework::atbus::protocol::ATBUS_PROTOCOL_VERSION;
  ::google::protobuf::ArenaOptions arena_options;

  int generated_count = 0;

  for (const auto& alg : compression_algorithms) {
    auto ctx =
        atfw::atbus::connection_context::create(atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_NONE, nullptr);
    CASE_EXPECT_NE(nullptr, ctx.get());

    std::vector<atframework::atbus::protocol::ATBUS_COMPRESSION_ALGORITHM_TYPE> algorithms = {alg.type};
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, ctx->update_compression_algorithm(algorithms));

    // Test Case 1: data_transform_req with large content (compressible)
    {
      std::string test_name = std::string("compress_") + alg.name + "_data_transform_req";
      uint64_t from = 0xABCDEF01ULL;
      uint64_t to = 0x12345678ULL;
      std::string content(4096, 'A');

      atfw::atbus::message msg(arena_options);
      auto* req = msg.mutable_body().mutable_data_transform_req();
      req->set_from(from);
      req->set_to(to);
      req->set_content(content);
      req->set_flags(0);

      auto pack_result = ctx->pack_message(msg, protocol_version, random_engine, 1024 * 1024);
      if (pack_result.is_success()) {
        auto* buffer = pack_result.get_success();
        write_binary_file(test_name + ".bytes", buffer->data(), buffer->used());

        ::atframework::atbus::protocol::message_head head;
        size_t head_size = 0;
        size_t head_vint_size = 0;
        bool parsed = parse_message_head_from_buffer(buffer->data(), buffer->used(), head, head_size, head_vint_size);
        CASE_EXPECT_TRUE(parsed);

        std::ostringstream json;
        json << "{\n";
        json << "  \"name\": \"" << test_name << "\",\n";
        json << "  \"description\": \"Data transform request with compression\",\n";
        json << "  \"protocol_version\": " << protocol_version << ",\n";
        json << "  \"body_type\": \"data_transform_req\",\n";
        json << "  \"body_type_case\": 13,\n";
        json << "  \"compression_algorithm\": \"" << alg.name << "\",\n";
        json << "  \"compression_algorithm_type\": " << static_cast<int>(alg.type) << ",\n";
        if (parsed) {
          json << "  \"compression_original_size\": " << head.compression().original_size() << ",\n";
        }
        json << "  \"packed_size\": " << buffer->used() << ",\n";
        json << "  \"packed_hex\": \"" << bytes_to_hex(buffer->data(), buffer->used()) << "\",\n";
        json << "  \"expected\": {\n";
        json << "    \"from\": " << from << ",\n";
        json << "    \"to\": " << to << ",\n";
        json << "    \"content_size\": " << content.size() << "\n";
        json << "  }\n";
        json << "}\n";
        write_json_file(test_name + ".json", json.str());
        generated_count++;
      }
    }

    // Test Case 2: custom_command_req with large arguments (compressible)
    {
      std::string test_name = std::string("compress_") + alg.name + "_custom_cmd";
      uint64_t from = 0x5555AAAAULL;
      std::string large_arg(2048, 'B');
      std::vector<std::string> commands = {"cmd", large_arg, large_arg};

      atfw::atbus::message msg(arena_options);
      auto* req = msg.mutable_body().mutable_custom_command_req();
      req->set_from(from);
      for (const auto& cmd : commands) {
        auto* command = req->add_commands();
        command->set_arg(cmd);
      }

      auto pack_result = ctx->pack_message(msg, protocol_version, random_engine, 1024 * 1024);
      if (pack_result.is_success()) {
        auto* buffer = pack_result.get_success();
        write_binary_file(test_name + ".bytes", buffer->data(), buffer->used());

        ::atframework::atbus::protocol::message_head head;
        size_t head_size = 0;
        size_t head_vint_size = 0;
        bool parsed = parse_message_head_from_buffer(buffer->data(), buffer->used(), head, head_size, head_vint_size);
        CASE_EXPECT_TRUE(parsed);

        std::ostringstream json;
        json << "{\n";
        json << "  \"name\": \"" << test_name << "\",\n";
        json << "  \"description\": \"Custom command request with compression\",\n";
        json << "  \"protocol_version\": " << protocol_version << ",\n";
        json << "  \"body_type\": \"custom_command_req\",\n";
        json << "  \"body_type_case\": 11,\n";
        json << "  \"compression_algorithm\": \"" << alg.name << "\",\n";
        json << "  \"compression_algorithm_type\": " << static_cast<int>(alg.type) << ",\n";
        if (parsed) {
          json << "  \"compression_original_size\": " << head.compression().original_size() << ",\n";
        }
        json << "  \"packed_size\": " << buffer->used() << ",\n";
        json << "  \"packed_hex\": \"" << bytes_to_hex(buffer->data(), buffer->used()) << "\",\n";
        json << "  \"expected\": {\n";
        json << "    \"from\": " << from << "\n";
        json << "  }\n";
        json << "}\n";
        write_json_file(test_name + ".json", json.str());
        generated_count++;
      }
    }
  }

  CASE_MSG_INFO() << "Generated " << generated_count << " compressed test files in " << get_output_dir() << std::endl;
  CASE_EXPECT_GE(generated_count, 1);
}

// ============================================================================
// 验证生成的压缩文件可以正确解包
// ============================================================================

CASE_TEST(atbus_connection_context_crosslang, verify_generated_compressed_files) {
  auto compression_algorithms = build_supported_compression_algorithms();
  if (compression_algorithms.empty()) {
    CASE_MSG_INFO() << "No compression algorithm available, skipping verification" << std::endl;
    return;
  }

  ::google::protobuf::ArenaOptions arena_options;
  int verified_count = 0;

  for (const auto& alg : compression_algorithms) {
    std::vector<std::string> test_files = {
        std::string("compress_") + alg.name + "_data_transform_req",
        std::string("compress_") + alg.name + "_custom_cmd",
    };

    auto ctx =
        atfw::atbus::connection_context::create(atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_NONE, nullptr);
    CASE_EXPECT_NE(nullptr, ctx.get());

    for (const auto& test_name : test_files) {
      std::vector<unsigned char> buffer;
      if (!read_binary_file(test_name + ".bytes", buffer)) {
        CASE_MSG_INFO() << "File not found (run generate test first): " << test_name << std::endl;
        continue;
      }

      atfw::atbus::message msg(arena_options);
      gsl::span<const unsigned char> input_span(buffer.data(), buffer.size());
      int result = ctx->unpack_message(msg, input_span, 1024 * 1024);
      if (result != EN_ATBUS_ERR_SUCCESS) {
        CASE_MSG_INFO() << "Failed to unpack " << test_name << ": error " << result << std::endl;
        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, result);
        continue;
      }

      auto* body = msg.get_body();
      CASE_EXPECT_NE(nullptr, body);
      if (body != nullptr) {
        CASE_MSG_INFO() << "Verified: " << test_name << " (body_type_case=" << body->message_type_case() << ")"
                        << std::endl;
        verified_count++;
      }
    }
  }

  CASE_MSG_INFO() << "Verified " << verified_count << " compressed files" << std::endl;
}
#endif  // ATFW_UTIL_MACRO_COMPRESSION_ENABLED

// ============================================================================
// 生成综合索引文件
// ============================================================================

CASE_TEST(atbus_connection_context_crosslang, generate_index_file) {
  CASE_EXPECT_TRUE(ensure_output_dir());

  std::vector<std::string> test_files = {
      "no_enc_ping_req",
      "no_enc_pong_rsp",
      "no_enc_data_transform_req_simple",
      "no_enc_data_transform_req_with_rsp_flag",
      "no_enc_data_transform_rsp",
      "no_enc_custom_command_req",
      "no_enc_custom_command_rsp",
      "no_enc_node_register_req",
      "no_enc_node_register_rsp",
      "no_enc_data_transform_binary_content",
      "no_enc_data_transform_large_content",
      "no_enc_data_transform_utf8_content",
  };

#ifdef ATFW_UTIL_MACRO_COMPRESSION_ENABLED
  auto compression_algorithms = build_supported_compression_algorithms();
  for (const auto& alg : compression_algorithms) {
    test_files.push_back(std::string("compress_") + alg.name + "_data_transform_req");
    test_files.push_back(std::string("compress_") + alg.name + "_custom_cmd");
  }
#endif

  std::ostringstream json;
  json << "{\n";
  json << "  \"description\": \"libatbus cross-language pack/unpack test data\",\n";
  json << "  \"protocol_version\": " << atframework::atbus::protocol::ATBUS_PROTOCOL_VERSION << ",\n";
  json << "  \"output_dir\": \"" << kTestOutputSubDir << "\",\n";
  json << "  \"generated_at\": \"2026-01-05\",\n";
  json << "  \"test_files\": [\n";

  for (size_t i = 0; i < test_files.size(); ++i) {
    if (i > 0) json << ",\n";
    json << "    {\n";
    json << "      \"name\": \"" << test_files[i] << "\",\n";
    json << "      \"binary\": \"" << test_files[i] << ".bytes\",\n";
    json << "      \"metadata\": \"" << test_files[i] << ".json\"\n";
    json << "    }";
  }

  json << "\n  ],\n";
  json << "  \"usage\": {\n";
  json << "    \"step1\": \"Read the .bytes file as raw bytes\",\n";
  json << "    \"step2\": \"Use your language's unpack implementation to decode\",\n";
  json << "    \"step3\": \"Compare decoded values with expected values in .json\",\n";
  json << "    \"step4\": \"Pack the same message and compare with original .bytes\"\n";
  json << "  }\n";
  json << "}\n";

  write_json_file("index.json", json.str());
}

#ifdef CRYPTO_DH_ENABLED
// ============================================================================
// 生成加密测试数据文件（使用固定密钥）
// ============================================================================

CASE_TEST(atbus_connection_context_crosslang, generate_encrypted_test_files) {
  ensure_openssl_initialized_for_generator();
  CASE_EXPECT_TRUE(ensure_output_dir());

  atfw::atbus::random_engine_t random_engine;
  random_engine.init_seed(12345);  // 固定种子保证可复现

  int32_t protocol_version = atframework::atbus::protocol::ATBUS_PROTOCOL_VERSION;
  ::google::protobuf::ArenaOptions arena_options;

  int generated_count = 0;

  // 定义固定的测试密钥（用于跨语言测试，非生产环境）
  // 32字节密钥（AES-256）
  static const unsigned char test_key_256[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                                                 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                                                 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
  // 24字节密钥（AES-192）
  static const unsigned char test_key_192[24] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                                 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                                 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
  // 16字节密钥（AES-128 / XXTEA）
  static const unsigned char test_key_128[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                                 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
  // 16字节IV（用于CBC模式）
  static const unsigned char test_iv_16[16] = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
                                               0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf};
  // 12字节IV（用于GCM模式）
  static const unsigned char test_iv_12[12] = {0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb};
  // 24字节IV（用于XChaCha20-Poly1305）
  static const unsigned char test_iv_24[24] = {0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb,
                                               0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7};

  // 加密算法测试配置
  struct crypto_test_config {
    const char* name;
    atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_TYPE algorithm;
    const unsigned char* key;
    size_t key_size;
    const unsigned char* iv;
    size_t iv_size;
    const char* cipher_name;
  };

  std::vector<crypto_test_config> crypto_configs = {
      // XXTEA - 使用16字节密钥，无IV
      {"xxtea", atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_XXTEA, test_key_128, 16, nullptr, 0, "xxtea"},
      // AES-128-CBC
      {"aes_128_cbc", atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_128_CBC, test_key_128, 16, test_iv_16,
       16, "aes-128-cbc"},
      // AES-192-CBC
      {"aes_192_cbc", atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_192_CBC, test_key_192, 24, test_iv_16,
       16, "aes-192-cbc"},
      // AES-256-CBC
      {"aes_256_cbc", atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_CBC, test_key_256, 32, test_iv_16,
       16, "aes-256-cbc"},
      // AES-128-GCM
      {"aes_128_gcm", atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_128_GCM, test_key_128, 16, test_iv_12,
       12, "aes-128-gcm"},
      // AES-192-GCM
      {"aes_192_gcm", atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_192_GCM, test_key_192, 24, test_iv_12,
       12, "aes-192-gcm"},
      // AES-256-GCM
      {"aes_256_gcm", atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_GCM, test_key_256, 32, test_iv_12,
       12, "aes-256-gcm"},
      // ChaCha20
      {"chacha20", atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_CHACHA20, test_key_256, 32, test_iv_12, 12,
       "chacha20"},
      // ChaCha20-Poly1305-IETF
      {"chacha20_poly1305", atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_CHACHA20_POLY1305_IETF, test_key_256,
       32, test_iv_12, 12, "chacha20-poly1305-ietf"},
      // XChaCha20-Poly1305-IETF
      {"xchacha20_poly1305", atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_XCHACHA20_POLY1305_IETF, test_key_256,
       32, test_iv_24, 24, "xchacha20-poly1305-ietf"},
  };

  // 为每种加密算法生成测试数据
  for (const auto& crypto_config : crypto_configs) {
    // 检查算法是否可用
    auto test_cipher = atfw::util::memory::make_strong_rc<atfw::util::crypto::cipher>();
    if (test_cipher->init(crypto_config.cipher_name, atfw::util::crypto::cipher::mode_t::EN_CMODE_ENCRYPT) !=
        atfw::util::crypto::cipher::error_code_t::OK) {
      CASE_MSG_INFO() << "Cipher " << crypto_config.cipher_name << " not available, skipping" << std::endl;
      continue;
    }
    const bool is_aead = test_cipher->is_aead();

    // 生成 data_transform_req 测试用例
    {
      auto ctx = atfw::atbus::connection_context::create(atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_NONE,
                                                         nullptr);
      CASE_EXPECT_NE(nullptr, ctx.get());

      int setup_result = ctx->setup_crypto_with_key(crypto_config.algorithm, crypto_config.key, crypto_config.key_size,
                                                    crypto_config.iv, crypto_config.iv_size);
      if (setup_result != EN_ATBUS_ERR_SUCCESS) {
        CASE_MSG_INFO() << "Failed to setup crypto " << crypto_config.name << ": " << setup_result << std::endl;
        continue;
      }

      std::string test_name = std::string("enc_") + crypto_config.name + "_data_transform_req";
      uint64_t from = 0x123456789ABCDEF0ULL;
      uint64_t to = 0x0FEDCBA987654321ULL;
      std::string content = "Hello, encrypted atbus!";
      uint32_t flags = 0x0001;

      atfw::atbus::message msg(arena_options);
      auto* req = msg.mutable_body().mutable_data_transform_req();
      req->set_from(from);
      req->set_to(to);
      req->set_content(content);
      req->set_flags(flags);

      auto pack_result = ctx->pack_message(msg, protocol_version, random_engine, 1024 * 1024);
      if (pack_result.is_success()) {
        auto* buffer = pack_result.get_success();
        write_binary_file(test_name + ".bytes", buffer->data(), buffer->used());

        std::string aad_hex;
        size_t aad_size = 0;
        if (is_aead) {
          ::atframework::atbus::protocol::message_head head;
          size_t head_size = 0;
          size_t head_vint_size = 0;
          bool parsed = parse_message_head_from_buffer(buffer->data(), buffer->used(), head, head_size, head_vint_size);
          CASE_EXPECT_TRUE(parsed);
          if (parsed) {
            const auto& crypt = head.crypto();
            aad_size = crypt.aad().size();
            if (aad_size > 0) {
              aad_hex = bytes_to_hex(reinterpret_cast<const unsigned char*>(crypt.aad().data()), aad_size);
            }
          }
        }

        std::ostringstream json;
        json << "{\n";
        json << "  \"name\": \"" << test_name << "\",\n";
        json << "  \"description\": \"Data transform request with " << crypto_config.name << " encryption\",\n";
        json << "  \"protocol_version\": " << protocol_version << ",\n";
        json << "  \"body_type\": \"data_transform_req\",\n";
        json << "  \"body_type_case\": 13,\n";
        json << "  \"crypto_algorithm\": \"" << crypto_config.name << "\",\n";
        json << "  \"crypto_algorithm_type\": " << static_cast<int>(crypto_config.algorithm) << ",\n";
        json << "  \"key_hex\": \"" << bytes_to_hex(crypto_config.key, crypto_config.key_size) << "\",\n";
        json << "  \"key_size\": " << crypto_config.key_size << ",\n";
        if (crypto_config.iv != nullptr && crypto_config.iv_size > 0) {
          json << "  \"iv_hex\": \"" << bytes_to_hex(crypto_config.iv, crypto_config.iv_size) << "\",\n";
          json << "  \"iv_size\": " << crypto_config.iv_size << ",\n";
        }
        if (is_aead) {
          json << "  \"aad_hex\": \"" << aad_hex << "\",\n";
          json << "  \"aad_size\": " << aad_size << ",\n";
        }
        json << "  \"packed_size\": " << buffer->used() << ",\n";
        json << "  \"packed_hex\": \"" << bytes_to_hex(buffer->data(), buffer->used()) << "\",\n";
        json << "  \"expected\": {\n";
        json << "    \"from\": " << from << ",\n";
        json << "    \"to\": " << to << ",\n";
        json << "    \"content\": \"" << escape_json_string(content) << "\",\n";
        json << "    \"flags\": " << flags << "\n";
        json << "  }\n";
        json << "}\n";
        write_json_file(test_name + ".json", json.str());
        generated_count++;
      } else {
        CASE_MSG_INFO() << "Failed to pack " << test_name << std::endl;
      }
    }

    // 生成 custom_command_req 测试用例
    {
      auto ctx = atfw::atbus::connection_context::create(atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_NONE,
                                                         nullptr);
      CASE_EXPECT_NE(nullptr, ctx.get());

      int setup_result = ctx->setup_crypto_with_key(crypto_config.algorithm, crypto_config.key, crypto_config.key_size,
                                                    crypto_config.iv, crypto_config.iv_size);
      if (setup_result != EN_ATBUS_ERR_SUCCESS) {
        CASE_MSG_INFO() << "Failed to setup crypto " << crypto_config.name << ": " << setup_result << std::endl;
        continue;
      }

      std::string test_name = std::string("enc_") + crypto_config.name + "_custom_cmd";
      uint64_t from = 0xABCDEF0123456789ULL;
      std::vector<std::string> commands = {"cmd1", "arg1", "arg2"};

      atfw::atbus::message msg(arena_options);
      auto* req = msg.mutable_body().mutable_custom_command_req();
      req->set_from(from);
      for (const auto& cmd : commands) {
        auto* command = req->add_commands();
        command->set_arg(cmd);
      }

      auto pack_result = ctx->pack_message(msg, protocol_version, random_engine, 1024 * 1024);
      if (pack_result.is_success()) {
        auto* buffer = pack_result.get_success();
        write_binary_file(test_name + ".bytes", buffer->data(), buffer->used());

        std::string aad_hex;
        size_t aad_size = 0;
        if (is_aead) {
          ::atframework::atbus::protocol::message_head head;
          size_t head_size = 0;
          size_t head_vint_size = 0;
          bool parsed = parse_message_head_from_buffer(buffer->data(), buffer->used(), head, head_size, head_vint_size);
          CASE_EXPECT_TRUE(parsed);
          if (parsed) {
            const auto& crypt = head.crypto();
            aad_size = crypt.aad().size();
            if (aad_size > 0) {
              aad_hex = bytes_to_hex(reinterpret_cast<const unsigned char*>(crypt.aad().data()), aad_size);
            }
          }
        }

        std::ostringstream json;
        json << "{\n";
        json << "  \"name\": \"" << test_name << "\",\n";
        json << "  \"description\": \"Custom command request with " << crypto_config.name << " encryption\",\n";
        json << "  \"protocol_version\": " << protocol_version << ",\n";
        json << "  \"body_type\": \"custom_command_req\",\n";
        json << "  \"body_type_case\": 11,\n";
        json << "  \"crypto_algorithm\": \"" << crypto_config.name << "\",\n";
        json << "  \"crypto_algorithm_type\": " << static_cast<int>(crypto_config.algorithm) << ",\n";
        json << "  \"key_hex\": \"" << bytes_to_hex(crypto_config.key, crypto_config.key_size) << "\",\n";
        json << "  \"key_size\": " << crypto_config.key_size << ",\n";
        if (crypto_config.iv != nullptr && crypto_config.iv_size > 0) {
          json << "  \"iv_hex\": \"" << bytes_to_hex(crypto_config.iv, crypto_config.iv_size) << "\",\n";
          json << "  \"iv_size\": " << crypto_config.iv_size << ",\n";
        }
        if (is_aead) {
          json << "  \"aad_hex\": \"" << aad_hex << "\",\n";
          json << "  \"aad_size\": " << aad_size << ",\n";
        }
        json << "  \"packed_size\": " << buffer->used() << ",\n";
        json << "  \"packed_hex\": \"" << bytes_to_hex(buffer->data(), buffer->used()) << "\",\n";
        json << "  \"expected\": {\n";
        json << "    \"from\": " << from << ",\n";
        json << "    \"commands\": " << string_vector_to_json_array(commands) << "\n";
        json << "  }\n";
        json << "}\n";
        write_json_file(test_name + ".json", json.str());
        generated_count++;
      }
    }
  }

  CASE_MSG_INFO() << "Generated " << generated_count << " encrypted test files" << std::endl;
  CASE_EXPECT_GT(generated_count, 0);
}

#  ifdef ATFW_UTIL_MACRO_COMPRESSION_ENABLED
// ============================================================================
// 生成同时压缩+加密的测试数据文件
// ============================================================================

CASE_TEST(atbus_connection_context_crosslang, generate_compressed_encrypted_test_files) {
  ensure_openssl_initialized_for_generator();
  CASE_EXPECT_TRUE(ensure_output_dir());

  auto compression_algorithms = build_supported_compression_algorithms();
  if (compression_algorithms.empty()) {
    CASE_MSG_INFO() << "No compression algorithm available, skipping generation" << std::endl;
    return;
  }

  atfw::atbus::random_engine_t random_engine;
  random_engine.init_seed(12345);

  int32_t protocol_version = atframework::atbus::protocol::ATBUS_PROTOCOL_VERSION;
  ::google::protobuf::ArenaOptions arena_options;

  // Fixed test key/iv (AES-256-CBC/GCM)
  static const unsigned char test_key_256[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                                                 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                                                 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
  static const unsigned char test_iv_16[16] = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
                                               0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf};
  static const unsigned char test_iv_12[12] = {0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb};

  int generated_count = 0;

  for (const auto& alg : compression_algorithms) {
    // data_transform_req (CBC)
    {
      std::string test_name = std::string("enc_compress_") + alg.name + "_aes_256_cbc_data_transform_req";
      auto ctx = atfw::atbus::connection_context::create(atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_NONE,
                                                         nullptr);
      CASE_EXPECT_NE(nullptr, ctx.get());

      int setup_result = ctx->setup_crypto_with_key(atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_CBC,
                                                    test_key_256, sizeof(test_key_256), test_iv_16, sizeof(test_iv_16));
      CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, setup_result);

      std::vector<atframework::atbus::protocol::ATBUS_COMPRESSION_ALGORITHM_TYPE> algorithms = {alg.type};
      CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, ctx->update_compression_algorithm(algorithms));

      atfw::atbus::message msg(arena_options);
      auto* req = msg.mutable_body().mutable_data_transform_req();
      req->set_from(0x13579BDFULL);
      req->set_to(0x2468ACE0ULL);
      req->set_content(std::string(4096, 'C'));
      req->set_flags(0);

      auto pack_result = ctx->pack_message(msg, protocol_version, random_engine, 1024 * 1024);
      if (pack_result.is_success()) {
        auto* buffer = pack_result.get_success();
        write_binary_file(test_name + ".bytes", buffer->data(), buffer->used());

        ::atframework::atbus::protocol::message_head head;
        size_t head_size = 0;
        size_t head_vint_size = 0;
        bool parsed = parse_message_head_from_buffer(buffer->data(), buffer->used(), head, head_size, head_vint_size);
        CASE_EXPECT_TRUE(parsed);

        std::ostringstream json;
        json << "{\n";
        json << "  \"name\": \"" << test_name << "\",\n";
        json << "  \"description\": \"Data transform request with compression + AES-256-CBC\",\n";
        json << "  \"protocol_version\": " << protocol_version << ",\n";
        json << "  \"body_type\": \"data_transform_req\",\n";
        json << "  \"body_type_case\": 13,\n";
        json << "  \"compression_algorithm\": \"" << alg.name << "\",\n";
        json << "  \"compression_algorithm_type\": " << static_cast<int>(alg.type) << ",\n";
        if (parsed) {
          json << "  \"compression_original_size\": " << head.compression().original_size() << ",\n";
        }
        json << "  \"crypto_algorithm\": \"aes_256_cbc\",\n";
        json << "  \"crypto_algorithm_type\": "
             << static_cast<int>(atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_CBC) << ",\n";
        json << "  \"key_hex\": \"" << bytes_to_hex(test_key_256, sizeof(test_key_256)) << "\",\n";
        json << "  \"iv_hex\": \"" << bytes_to_hex(test_iv_16, sizeof(test_iv_16)) << "\",\n";
        json << "  \"packed_size\": " << buffer->used() << ",\n";
        json << "  \"packed_hex\": \"" << bytes_to_hex(buffer->data(), buffer->used()) << "\",\n";
        json << "  \"expected\": {\n";
        json << "    \"from\": " << 0x13579BDFULL << ",\n";
        json << "    \"to\": " << 0x2468ACE0ULL << "\n";
        json << "  }\n";
        json << "}\n";
        write_json_file(test_name + ".json", json.str());
        generated_count++;
      }
    }

    // custom_command_req (CBC)
    {
      std::string test_name = std::string("enc_compress_") + alg.name + "_aes_256_cbc_custom_cmd";
      auto ctx = atfw::atbus::connection_context::create(atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_NONE,
                                                         nullptr);
      CASE_EXPECT_NE(nullptr, ctx.get());

      int setup_result = ctx->setup_crypto_with_key(atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_CBC,
                                                    test_key_256, sizeof(test_key_256), test_iv_16, sizeof(test_iv_16));
      CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, setup_result);

      std::vector<atframework::atbus::protocol::ATBUS_COMPRESSION_ALGORITHM_TYPE> algorithms = {alg.type};
      CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, ctx->update_compression_algorithm(algorithms));

      atfw::atbus::message msg(arena_options);
      auto* req = msg.mutable_body().mutable_custom_command_req();
      req->set_from(0x11112222ULL);
      std::string large_arg(2048, 'D');
      std::vector<std::string> commands = {"cmd", large_arg, large_arg};
      for (const auto& cmd : commands) {
        auto* command = req->add_commands();
        command->set_arg(cmd);
      }

      auto pack_result = ctx->pack_message(msg, protocol_version, random_engine, 1024 * 1024);
      if (pack_result.is_success()) {
        auto* buffer = pack_result.get_success();
        write_binary_file(test_name + ".bytes", buffer->data(), buffer->used());

        ::atframework::atbus::protocol::message_head head;
        size_t head_size = 0;
        size_t head_vint_size = 0;
        bool parsed = parse_message_head_from_buffer(buffer->data(), buffer->used(), head, head_size, head_vint_size);
        CASE_EXPECT_TRUE(parsed);

        std::ostringstream json;
        json << "{\n";
        json << "  \"name\": \"" << test_name << "\",\n";
        json << "  \"description\": \"Custom command request with compression + AES-256-CBC\",\n";
        json << "  \"protocol_version\": " << protocol_version << ",\n";
        json << "  \"body_type\": \"custom_command_req\",\n";
        json << "  \"body_type_case\": 11,\n";
        json << "  \"compression_algorithm\": \"" << alg.name << "\",\n";
        json << "  \"compression_algorithm_type\": " << static_cast<int>(alg.type) << ",\n";
        if (parsed) {
          json << "  \"compression_original_size\": " << head.compression().original_size() << ",\n";
        }
        json << "  \"crypto_algorithm\": \"aes_256_cbc\",\n";
        json << "  \"crypto_algorithm_type\": "
             << static_cast<int>(atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_CBC) << ",\n";
        json << "  \"key_hex\": \"" << bytes_to_hex(test_key_256, sizeof(test_key_256)) << "\",\n";
        json << "  \"iv_hex\": \"" << bytes_to_hex(test_iv_16, sizeof(test_iv_16)) << "\",\n";
        json << "  \"packed_size\": " << buffer->used() << ",\n";
        json << "  \"packed_hex\": \"" << bytes_to_hex(buffer->data(), buffer->used()) << "\",\n";
        json << "  \"expected\": {\n";
        json << "    \"from\": " << 0x11112222ULL << "\n";
        json << "  }\n";
        json << "}\n";
        write_json_file(test_name + ".json", json.str());
        generated_count++;
      }
    }

    // data_transform_req (GCM)
    {
      std::string test_name = std::string("enc_compress_") + alg.name + "_aes_256_gcm_data_transform_req";
      auto ctx = atfw::atbus::connection_context::create(atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_NONE,
                                                         nullptr);
      CASE_EXPECT_NE(nullptr, ctx.get());

      int setup_result = ctx->setup_crypto_with_key(atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_GCM,
                                                    test_key_256, sizeof(test_key_256), test_iv_12, sizeof(test_iv_12));
      CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, setup_result);

      std::vector<atframework::atbus::protocol::ATBUS_COMPRESSION_ALGORITHM_TYPE> algorithms = {alg.type};
      CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, ctx->update_compression_algorithm(algorithms));

      atfw::atbus::message msg(arena_options);
      auto* req = msg.mutable_body().mutable_data_transform_req();
      req->set_from(0x13579BDFULL);
      req->set_to(0x2468ACE0ULL);
      req->set_content(std::string(4096, 'C'));
      req->set_flags(0);

      auto pack_result = ctx->pack_message(msg, protocol_version, random_engine, 1024 * 1024);
      if (pack_result.is_success()) {
        auto* buffer = pack_result.get_success();
        write_binary_file(test_name + ".bytes", buffer->data(), buffer->used());

        ::atframework::atbus::protocol::message_head head;
        size_t head_size = 0;
        size_t head_vint_size = 0;
        bool parsed = parse_message_head_from_buffer(buffer->data(), buffer->used(), head, head_size, head_vint_size);
        CASE_EXPECT_TRUE(parsed);

        std::string aad_hex;
        size_t aad_size = 0;
        if (parsed) {
          const auto& crypt = head.crypto();
          aad_size = crypt.aad().size();
          if (aad_size > 0) {
            aad_hex = bytes_to_hex(reinterpret_cast<const unsigned char*>(crypt.aad().data()), aad_size);
          }
        }

        std::ostringstream json;
        json << "{\n";
        json << "  \"name\": \"" << test_name << "\",\n";
        json << "  \"description\": \"Data transform request with compression + AES-256-GCM\",\n";
        json << "  \"protocol_version\": " << protocol_version << ",\n";
        json << "  \"body_type\": \"data_transform_req\",\n";
        json << "  \"body_type_case\": 13,\n";
        json << "  \"compression_algorithm\": \"" << alg.name << "\",\n";
        json << "  \"compression_algorithm_type\": " << static_cast<int>(alg.type) << ",\n";
        if (parsed) {
          json << "  \"compression_original_size\": " << head.compression().original_size() << ",\n";
        }
        json << "  \"crypto_algorithm\": \"aes_256_gcm\",\n";
        json << "  \"crypto_algorithm_type\": "
             << static_cast<int>(atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_GCM) << ",\n";
        json << "  \"key_hex\": \"" << bytes_to_hex(test_key_256, sizeof(test_key_256)) << "\",\n";
        json << "  \"iv_hex\": \"" << bytes_to_hex(test_iv_12, sizeof(test_iv_12)) << "\",\n";
        if (!aad_hex.empty()) {
          json << "  \"aad_hex\": \"" << aad_hex << "\",\n";
          json << "  \"aad_size\": " << aad_size << ",\n";
        }
        json << "  \"packed_size\": " << buffer->used() << ",\n";
        json << "  \"packed_hex\": \"" << bytes_to_hex(buffer->data(), buffer->used()) << "\",\n";
        json << "  \"expected\": {\n";
        json << "    \"from\": " << 0x13579BDFULL << ",\n";
        json << "    \"to\": " << 0x2468ACE0ULL << "\n";
        json << "  }\n";
        json << "}\n";
        write_json_file(test_name + ".json", json.str());
        generated_count++;
      }
    }

    // custom_command_req (GCM)
    {
      std::string test_name = std::string("enc_compress_") + alg.name + "_aes_256_gcm_custom_cmd";
      auto ctx = atfw::atbus::connection_context::create(atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_NONE,
                                                         nullptr);
      CASE_EXPECT_NE(nullptr, ctx.get());

      int setup_result = ctx->setup_crypto_with_key(atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_GCM,
                                                    test_key_256, sizeof(test_key_256), test_iv_12, sizeof(test_iv_12));
      CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, setup_result);

      std::vector<atframework::atbus::protocol::ATBUS_COMPRESSION_ALGORITHM_TYPE> algorithms = {alg.type};
      CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, ctx->update_compression_algorithm(algorithms));

      atfw::atbus::message msg(arena_options);
      auto* req = msg.mutable_body().mutable_custom_command_req();
      req->set_from(0x11112222ULL);
      std::string large_arg(2048, 'D');
      std::vector<std::string> commands = {"cmd", large_arg, large_arg};
      for (const auto& cmd : commands) {
        auto* command = req->add_commands();
        command->set_arg(cmd);
      }

      auto pack_result = ctx->pack_message(msg, protocol_version, random_engine, 1024 * 1024);
      if (pack_result.is_success()) {
        auto* buffer = pack_result.get_success();
        write_binary_file(test_name + ".bytes", buffer->data(), buffer->used());

        ::atframework::atbus::protocol::message_head head;
        size_t head_size = 0;
        size_t head_vint_size = 0;
        bool parsed = parse_message_head_from_buffer(buffer->data(), buffer->used(), head, head_size, head_vint_size);
        CASE_EXPECT_TRUE(parsed);

        std::string aad_hex;
        size_t aad_size = 0;
        if (parsed) {
          const auto& crypt = head.crypto();
          aad_size = crypt.aad().size();
          if (aad_size > 0) {
            aad_hex = bytes_to_hex(reinterpret_cast<const unsigned char*>(crypt.aad().data()), aad_size);
          }
        }

        std::ostringstream json;
        json << "{\n";
        json << "  \"name\": \"" << test_name << "\",\n";
        json << "  \"description\": \"Custom command request with compression + AES-256-GCM\",\n";
        json << "  \"protocol_version\": " << protocol_version << ",\n";
        json << "  \"body_type\": \"custom_command_req\",\n";
        json << "  \"body_type_case\": 11,\n";
        json << "  \"compression_algorithm\": \"" << alg.name << "\",\n";
        json << "  \"compression_algorithm_type\": " << static_cast<int>(alg.type) << ",\n";
        if (parsed) {
          json << "  \"compression_original_size\": " << head.compression().original_size() << ",\n";
        }
        json << "  \"crypto_algorithm\": \"aes_256_gcm\",\n";
        json << "  \"crypto_algorithm_type\": "
             << static_cast<int>(atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_GCM) << ",\n";
        json << "  \"key_hex\": \"" << bytes_to_hex(test_key_256, sizeof(test_key_256)) << "\",\n";
        json << "  \"iv_hex\": \"" << bytes_to_hex(test_iv_12, sizeof(test_iv_12)) << "\",\n";
        if (!aad_hex.empty()) {
          json << "  \"aad_hex\": \"" << aad_hex << "\",\n";
          json << "  \"aad_size\": " << aad_size << ",\n";
        }
        json << "  \"packed_size\": " << buffer->used() << ",\n";
        json << "  \"packed_hex\": \"" << bytes_to_hex(buffer->data(), buffer->used()) << "\",\n";
        json << "  \"expected\": {\n";
        json << "    \"from\": " << 0x11112222ULL << "\n";
        json << "  }\n";
        json << "}\n";
        write_json_file(test_name + ".json", json.str());
        generated_count++;
      }
    }
  }

  CASE_MSG_INFO() << "Generated " << generated_count << " compressed+encrypted test files" << std::endl;
  CASE_EXPECT_GE(generated_count, 1);
}

// ============================================================================
// 验证压缩+加密测试文件可以正确解包
// ============================================================================

CASE_TEST(atbus_connection_context_crosslang, verify_compressed_encrypted_test_files) {
  ensure_openssl_initialized_for_generator();

  auto compression_algorithms = build_supported_compression_algorithms();
  if (compression_algorithms.empty()) {
    CASE_MSG_INFO() << "No compression algorithm available, skipping verification" << std::endl;
    return;
  }

  static const unsigned char test_key_256[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                                                 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                                                 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
  static const unsigned char test_iv_16[16] = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
                                               0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf};
  static const unsigned char test_iv_12[12] = {0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb};

  ::google::protobuf::ArenaOptions arena_options;
  int verified_count = 0;

  for (const auto& alg : compression_algorithms) {
    std::vector<std::string> test_files = {
        std::string("enc_compress_") + alg.name + "_aes_256_cbc_data_transform_req",
        std::string("enc_compress_") + alg.name + "_aes_256_cbc_custom_cmd",
        std::string("enc_compress_") + alg.name + "_aes_256_gcm_data_transform_req",
        std::string("enc_compress_") + alg.name + "_aes_256_gcm_custom_cmd",
    };

    for (const auto& test_name : test_files) {
      std::vector<unsigned char> buffer;
      if (!read_binary_file(test_name + ".bytes", buffer)) {
        CASE_MSG_INFO() << "File not found: " << test_name << std::endl;
        continue;
      }

      auto ctx = atfw::atbus::connection_context::create(atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_NONE,
                                                         nullptr);
      bool is_gcm = (test_name.find("_aes_256_gcm_") != std::string::npos);
      int setup_result =
          ctx->setup_crypto_with_key(is_gcm ? atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_GCM
                                            : atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_CBC,
                                     test_key_256, sizeof(test_key_256), is_gcm ? test_iv_12 : test_iv_16,
                                     is_gcm ? sizeof(test_iv_12) : sizeof(test_iv_16));
      CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, setup_result);

      atfw::atbus::message msg(arena_options);
      gsl::span<const unsigned char> input_span(buffer.data(), buffer.size());
      int result = ctx->unpack_message(msg, input_span, 1024 * 1024);
      if (result != EN_ATBUS_ERR_SUCCESS) {
        CASE_MSG_INFO() << "Failed to unpack " << test_name << ": error " << result << std::endl;
        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, result);
        continue;
      }

      auto* body = msg.get_body();
      CASE_EXPECT_NE(nullptr, body);
      if (body != nullptr) {
        CASE_MSG_INFO() << "Verified: " << test_name << " (body_type_case=" << body->message_type_case() << ")"
                        << std::endl;
        verified_count++;
      }
    }
  }

  CASE_MSG_INFO() << "Verified " << verified_count << " compressed+encrypted files" << std::endl;
}
#  endif  // ATFW_UTIL_MACRO_COMPRESSION_ENABLED

// 验证加密测试文件可以正确解包
CASE_TEST(atbus_connection_context_crosslang, verify_encrypted_test_files) {
  ensure_openssl_initialized_for_generator();

  ::google::protobuf::ArenaOptions arena_options;
  int verified_count = 0;

  // 定义固定的测试密钥
  static const unsigned char test_key_256[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                                                 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                                                 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
  static const unsigned char test_key_192[24] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                                 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                                 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
  static const unsigned char test_key_128[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                                 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
  static const unsigned char test_iv_16[16] = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
                                               0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf};
  static const unsigned char test_iv_12[12] = {0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb};
  static const unsigned char test_iv_24[24] = {0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb,
                                               0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7};

  struct verify_config {
    const char* name;
    atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_TYPE algorithm;
    const unsigned char* key;
    size_t key_size;
    const unsigned char* iv;
    size_t iv_size;
    const char* cipher_name;
  };

  std::vector<verify_config> verify_configs = {
      {"xxtea", atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_XXTEA, test_key_128, 16, nullptr, 0, "xxtea"},
      {"aes_128_cbc", atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_128_CBC, test_key_128, 16, test_iv_16,
       16, "aes-128-cbc"},
      {"aes_192_cbc", atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_192_CBC, test_key_192, 24, test_iv_16,
       16, "aes-192-cbc"},
      {"aes_256_cbc", atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_CBC, test_key_256, 32, test_iv_16,
       16, "aes-256-cbc"},
      {"aes_128_gcm", atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_128_GCM, test_key_128, 16, test_iv_12,
       12, "aes-128-gcm"},
      {"aes_192_gcm", atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_192_GCM, test_key_192, 24, test_iv_12,
       12, "aes-192-gcm"},
      {"aes_256_gcm", atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_GCM, test_key_256, 32, test_iv_12,
       12, "aes-256-gcm"},
      {"chacha20", atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_CHACHA20, test_key_256, 32, test_iv_12, 12,
       "chacha20"},
      {"chacha20_poly1305", atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_CHACHA20_POLY1305_IETF, test_key_256,
       32, test_iv_12, 12, "chacha20-poly1305-ietf"},
      {"xchacha20_poly1305", atframework::atbus::protocol::ATBUS_CRYPTO_ALGORITHM_XCHACHA20_POLY1305_IETF, test_key_256,
       32, test_iv_24, 24, "xchacha20-poly1305-ietf"},
  };

  std::vector<std::string> test_suffixes = {"_data_transform_req", "_custom_cmd"};

  for (const auto& config : verify_configs) {
    // 检查算法是否可用
    auto test_cipher = atfw::util::memory::make_strong_rc<atfw::util::crypto::cipher>();
    if (test_cipher->init(config.cipher_name, atfw::util::crypto::cipher::mode_t::EN_CMODE_DECRYPT) !=
        atfw::util::crypto::cipher::error_code_t::OK) {
      CASE_MSG_INFO() << "Cipher " << config.cipher_name << " not available, skipping verification" << std::endl;
      continue;
    }
    const bool is_aead = test_cipher->is_aead();

    for (const auto& suffix : test_suffixes) {
      std::string test_name = std::string("enc_") + config.name + suffix;
      std::vector<unsigned char> buffer;
      if (!read_binary_file(test_name + ".bytes", buffer)) {
        CASE_MSG_INFO() << "File not found: " << test_name << std::endl;
        continue;
      }

      ::atframework::atbus::protocol::message_head head;
      size_t head_size = 0;
      size_t head_vint_size = 0;
      bool parsed = parse_message_head_from_buffer(buffer.data(), buffer.size(), head, head_size, head_vint_size);
      CASE_EXPECT_TRUE(parsed);

      std::string aad_value;
      std::string iv_value;
      if (parsed && is_aead) {
        const auto& crypt = head.crypto();
        aad_value = crypt.aad();
        iv_value = crypt.iv();
        CASE_EXPECT_FALSE(aad_value.empty());
      }

      // 创建context并设置相同的密钥
      auto ctx = atfw::atbus::connection_context::create(atframework::atbus::protocol::ATBUS_CRYPTO_KEY_EXCHANGE_NONE,
                                                         nullptr);
      int setup_result =
          ctx->setup_crypto_with_key(config.algorithm, config.key, config.key_size, config.iv, config.iv_size);
      if (setup_result != EN_ATBUS_ERR_SUCCESS) {
        CASE_MSG_INFO() << "Failed to setup crypto for verification: " << config.name << std::endl;
        continue;
      }

      if (parsed && is_aead && !aad_value.empty()) {
        gsl::span<const unsigned char> iv_span;
        if (!iv_value.empty()) {
          iv_span =
              gsl::span<const unsigned char>(reinterpret_cast<const unsigned char*>(iv_value.data()), iv_value.size());
        } else if (config.iv != nullptr && config.iv_size > 0) {
          iv_span = gsl::span<const unsigned char>(config.iv, config.iv_size);
        }

        auto decrypt_with_aad = [&](const std::string& aad) -> int {
          atfw::util::crypto::cipher verify_cipher;
          if (verify_cipher.init(config.cipher_name, atfw::util::crypto::cipher::mode_t::EN_CMODE_DECRYPT) !=
              atfw::util::crypto::cipher::error_code_t::OK) {
            return -1;
          }
          if (verify_cipher.set_key(gsl::span<const unsigned char>(config.key, config.key_size)) != 0) {
            return -2;
          }
          if (!iv_span.empty()) {
            if (verify_cipher.set_iv(iv_span.data(), iv_span.size()) != 0) {
              return -3;
            }
          }

          size_t body_offset = head_vint_size + head_size;
          gsl::span<const unsigned char> cipher_span(buffer.data() + body_offset, buffer.size() - body_offset);
          std::vector<unsigned char> plaintext(cipher_span.size() + verify_cipher.get_block_size());
          size_t out_size = plaintext.size();
          return verify_cipher.decrypt_aead(cipher_span.data(), cipher_span.size(), plaintext.data(), &out_size,
                                            reinterpret_cast<const unsigned char*>(aad.data()), aad.size());
        };

        int correct_aad_result = decrypt_with_aad(aad_value);
        CASE_EXPECT_EQ(0, correct_aad_result);

        std::string wrong_aad = "wrong-aad";
        int wrong_aad_result = decrypt_with_aad(wrong_aad);
        CASE_EXPECT_NE(0, wrong_aad_result);
      }

      // 解包验证
      atfw::atbus::message msg(arena_options);
      gsl::span<const unsigned char> input_span(buffer.data(), buffer.size());
      int result = ctx->unpack_message(msg, input_span, 1024 * 1024);
      if (result != EN_ATBUS_ERR_SUCCESS) {
        CASE_MSG_INFO() << "Failed to unpack " << test_name << ": error " << result << std::endl;
        CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, result);
        continue;
      }

      auto* body = msg.get_body();
      CASE_EXPECT_NE(nullptr, body);
      if (body != nullptr) {
        CASE_MSG_INFO() << "Verified: " << test_name << " (body_type_case=" << body->message_type_case() << ")"
                        << std::endl;
        verified_count++;
      }
    }
  }

  CASE_MSG_INFO() << "Verified " << verified_count << " encrypted files" << std::endl;
}

// 更新索引文件包含加密测试
CASE_TEST(atbus_connection_context_crosslang, generate_full_index_file) {
  ensure_openssl_initialized_for_generator();
  CASE_EXPECT_TRUE(ensure_output_dir());

  std::vector<std::string> no_enc_files = {
      "no_enc_ping_req",
      "no_enc_pong_rsp",
      "no_enc_data_transform_req_simple",
      "no_enc_data_transform_req_with_rsp_flag",
      "no_enc_data_transform_rsp",
      "no_enc_custom_command_req",
      "no_enc_custom_command_rsp",
      "no_enc_node_register_req",
      "no_enc_node_register_rsp",
      "no_enc_data_transform_binary_content",
      "no_enc_data_transform_large_content",
      "no_enc_data_transform_utf8_content",
  };

  std::vector<std::string> crypto_names = {
      "xxtea",       "aes_128_cbc", "aes_192_cbc", "aes_256_cbc",       "aes_128_gcm",
      "aes_192_gcm", "aes_256_gcm", "chacha20",    "chacha20_poly1305", "xchacha20_poly1305"};

  std::vector<std::string> all_files;
  all_files.insert(all_files.end(), no_enc_files.begin(), no_enc_files.end());

  for (const auto& crypto : crypto_names) {
    all_files.push_back(std::string("enc_") + crypto + "_data_transform_req");
    all_files.push_back(std::string("enc_") + crypto + "_custom_cmd");
  }

#  ifdef ATFW_UTIL_MACRO_COMPRESSION_ENABLED
  auto compression_algorithms = build_supported_compression_algorithms();
  for (const auto& alg : compression_algorithms) {
    all_files.push_back(std::string("compress_") + alg.name + "_data_transform_req");
    all_files.push_back(std::string("compress_") + alg.name + "_custom_cmd");
    all_files.push_back(std::string("enc_compress_") + alg.name + "_aes_256_cbc_data_transform_req");
    all_files.push_back(std::string("enc_compress_") + alg.name + "_aes_256_cbc_custom_cmd");
    all_files.push_back(std::string("enc_compress_") + alg.name + "_aes_256_gcm_data_transform_req");
    all_files.push_back(std::string("enc_compress_") + alg.name + "_aes_256_gcm_custom_cmd");
  }
#  endif

  // 过滤出实际存在的文件
  std::vector<std::string> existing_files;
  for (const auto& file : all_files) {
    std::vector<unsigned char> dummy;
    if (read_binary_file(file + ".bytes", dummy)) {
      existing_files.push_back(file);
    }
  }

  std::ostringstream json;
  json << "{\n";
  json << "  \"description\": \"libatbus cross-language pack/unpack test data (with encryption)\",\n";
  json << "  \"protocol_version\": " << atframework::atbus::protocol::ATBUS_PROTOCOL_VERSION << ",\n";
  json << "  \"output_dir\": \"" << kTestOutputSubDir << "\",\n";
  json << "  \"generated_at\": \"2026-01-05\",\n";
  json << "  \"encryption_note\": \"Encrypted test files use fixed test keys. See .json metadata for key/iv.\",\n";
  json << "  \"test_files\": [\n";

  for (size_t i = 0; i < existing_files.size(); ++i) {
    if (i > 0) json << ",\n";
    json << "    {\n";
    json << "      \"name\": \"" << existing_files[i] << "\",\n";
    json << "      \"binary\": \"" << existing_files[i] << ".bytes\",\n";
    json << "      \"metadata\": \"" << existing_files[i] << ".json\"\n";
    json << "    }";
  }

  json << "\n  ],\n";
  json << "  \"crypto_algorithms\": [\n";
  json << "    {\"name\": \"NONE\", \"type\": 0},\n";
  json << "    {\"name\": \"XXTEA\", \"type\": 1},\n";
  json << "    {\"name\": \"AES-128-CBC\", \"type\": 2},\n";
  json << "    {\"name\": \"AES-192-CBC\", \"type\": 3},\n";
  json << "    {\"name\": \"AES-256-CBC\", \"type\": 4},\n";
  json << "    {\"name\": \"AES-128-GCM\", \"type\": 5},\n";
  json << "    {\"name\": \"AES-192-GCM\", \"type\": 6},\n";
  json << "    {\"name\": \"AES-256-GCM\", \"type\": 7},\n";
  json << "    {\"name\": \"CHACHA20\", \"type\": 8},\n";
  json << "    {\"name\": \"CHACHA20-POLY1305-IETF\", \"type\": 9},\n";
  json << "    {\"name\": \"XCHACHA20-POLY1305-IETF\", \"type\": 10}\n";
  json << "  ],\n";
  json << "  \"usage\": {\n";
  json << "    \"step1\": \"Read the .bytes file as raw bytes\",\n";
  json << "    \"step2\": \"For encrypted files, setup cipher with key/iv from .json\",\n";
  json << "    \"step3\": \"Use your language's unpack implementation to decode\",\n";
  json << "    \"step4\": \"Compare decoded values with expected values in .json\",\n";
  json << "    \"step5\": \"Pack the same message and compare with original .bytes (for non-AEAD only)\"\n";
  json << "  }\n";
  json << "}\n";

  write_json_file("index.json", json.str());
}
#endif
