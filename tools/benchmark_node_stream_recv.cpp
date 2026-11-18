// Copyright 2026 atframework
// Node-level TCP stream benchmark receiver.
//
// Listens on an atbus node endpoint and counts data-transform messages sent by
// benchmark_node_stream_send. Writes per-second samples and final statistics as
// JSON so a runner script can collect QPS, throughput, CPU time and peak RSS.
//
// usage: benchmark_node_stream_recv <listen_addr> <bus_id> [options]
//   --crypto=<none|aes-128-gcm|aes-192-gcm|aes-256-gcm|chacha20|chacha20-poly1305-ietf>
//   --compression=<none|lz4|zstd>
//   --level=<fast|low-cpu|balanced|high-ratio|max-ratio>  (unified compression level, default balanced)
//   --payload-size=<bytes>                                (expected message size, integrity check only)
//   --json=<output file>                                  (default: stdout)

#include <chrono>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <vector>

#include <atbus_node.h>
#include <detail/libatbus_channel_export.h>  // IWYU pragma: keep (provides uv.h)

namespace {
struct run_config {
  std::string listen_addr;
  uint64_t bus_id = 0;
  std::string crypto = "none";
  std::string compression = "none";
  std::string level = "balanced";
  size_t payload_size = 0;
  std::string json_output;
  bool verbose = false;
};

struct sample_t {
  int sec;
  uint64_t msgs_delta;
  uint64_t bytes_delta;
  double cpu_percent;  // total (user+system) of the whole process in this interval
  long rss_kb;         // peak RSS of the whole process at sample time
};

struct stats_t {
  uint64_t msgs = 0;
  uint64_t bytes = 0;
  uint64_t errors = 0;
  uint64_t seq_gaps = 0;
  uint64_t last_seq = 0;
  bool has_seq = false;
  bool done = false;
  bool got_connection = false;
  size_t connections_seen = 0;
  std::set<const atbus::connection*> live_connections;
  std::map<const atbus::connection*, uint64_t> conn_msg_count;
  std::map<const atbus::connection*, uint64_t> conn_bytes_count;
  std::vector<sample_t> samples;
  std::string negotiated_crypto;
  std::string negotiated_compression;

  std::chrono::steady_clock::time_point start_time;
  double cpu_user_start = 0;
  double cpu_system_start = 0;
};

run_config conf;
stats_t bench_stat;
uv_loop_t* main_loop = nullptr;

double get_cpu_time() {
  uv_rusage_t usage;
  if (0 != uv_getrusage(&usage)) {
    return 0;
  }
  return static_cast<double>(usage.ru_utime.tv_sec) + static_cast<double>(usage.ru_utime.tv_usec) / 1e6 +
         static_cast<double>(usage.ru_stime.tv_sec) + static_cast<double>(usage.ru_stime.tv_usec) / 1e6;
}

long get_peak_rss_kb() {
  uv_rusage_t usage;
  if (0 != uv_getrusage(&usage)) {
    return 0;
  }
  return static_cast<long>(usage.ru_maxrss);
}

const char* crypto_algorithm_name(atbus::protocol::ATBUS_CRYPTO_ALGORITHM_TYPE algo) {
  using namespace atbus;
  switch (algo) {
    case protocol::ATBUS_CRYPTO_ALGORITHM_NONE:
      return "none";
    case protocol::ATBUS_CRYPTO_ALGORITHM_XXTEA:
      return "xxtea";
    case protocol::ATBUS_CRYPTO_ALGORITHM_AES_128_CBC:
      return "aes-128-cbc";
    case protocol::ATBUS_CRYPTO_ALGORITHM_AES_192_CBC:
      return "aes-192-cbc";
    case protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_CBC:
      return "aes-256-cbc";
    case protocol::ATBUS_CRYPTO_ALGORITHM_AES_128_GCM:
      return "aes-128-gcm";
    case protocol::ATBUS_CRYPTO_ALGORITHM_AES_192_GCM:
      return "aes-192-gcm";
    case protocol::ATBUS_CRYPTO_ALGORITHM_AES_256_GCM:
      return "aes-256-gcm";
    case protocol::ATBUS_CRYPTO_ALGORITHM_CHACHA20:
      return "chacha20";
    case protocol::ATBUS_CRYPTO_ALGORITHM_CHACHA20_POLY1305_IETF:
      return "chacha20-poly1305-ietf";
    case protocol::ATBUS_CRYPTO_ALGORITHM_XCHACHA20_POLY1305_IETF:
      return "xchacha20-poly1305-ietf";
    default:
      return "unknown";
  }
}

const char* compression_algorithm_name(atbus::protocol::ATBUS_COMPRESSION_ALGORITHM_TYPE algo) {
  using namespace atbus;
  switch (algo) {
    case protocol::ATBUS_COMPRESSION_ALGORITHM_NONE:
      return "none";
    case protocol::ATBUS_COMPRESSION_ALGORITHM_ZSTD:
      return "zstd";
    case protocol::ATBUS_COMPRESSION_ALGORITHM_LZ4:
      return "lz4";
    case protocol::ATBUS_COMPRESSION_ALGORITHM_SNAPPY:
      return "snappy";
    case protocol::ATBUS_COMPRESSION_ALGORITHM_ZLIB:
      return "zlib";
    default:
      return "unknown";
  }
}

void setup_crypto(atbus::node::conf_t& node_conf) {
  using namespace atbus;
  if (conf.crypto == "none") {
    node_conf.crypto_key_exchange_type = protocol::ATBUS_CRYPTO_KEY_EXCHANGE_NONE;
    node_conf.crypto_allow_algorithms.clear();
    return;
  }

  node_conf.crypto_key_exchange_type = protocol::ATBUS_CRYPTO_KEY_EXCHANGE_X25519;
  node_conf.crypto_allow_algorithms.clear();
  node_conf.crypto_allow_algorithms.push_back(node::parse_crypto_algorithm_name(conf.crypto));
}

bool setup_compression(atbus::node::conf_t& node_conf) {
  using namespace atbus;
  node_conf.compression_allow_algorithms.clear();
  if (conf.compression == "none") {
    return true;
  }
  if (conf.compression == "lz4") {
    node_conf.compression_allow_algorithms.push_back(protocol::ATBUS_COMPRESSION_ALGORITHM_LZ4);
  } else if (conf.compression == "zstd") {
    node_conf.compression_allow_algorithms.push_back(protocol::ATBUS_COMPRESSION_ALGORITHM_ZSTD);
  } else {
    return false;
  }

  if (conf.level == "fast") {
    node_conf.compression_level = protocol::ATBUS_COMPRESSION_LEVEL_FAST;
  } else if (conf.level == "low-cpu") {
    node_conf.compression_level = protocol::ATBUS_COMPRESSION_LEVEL_LOW_CPU;
  } else if (conf.level == "balanced") {
    node_conf.compression_level = protocol::ATBUS_COMPRESSION_LEVEL_BALANCED;
  } else if (conf.level == "high-ratio") {
    node_conf.compression_level = protocol::ATBUS_COMPRESSION_LEVEL_HIGH_RATIO;
  } else if (conf.level == "max-ratio") {
    node_conf.compression_level = protocol::ATBUS_COMPRESSION_LEVEL_MAX_RATIO;
  } else if (conf.level == "default") {
    node_conf.compression_level = protocol::ATBUS_COMPRESSION_LEVEL_DEFAULT;
  } else {
    return false;
  }
  return true;
}

int on_forward_request(const atbus::node&, const atbus::endpoint*, const atbus::connection* conn, const atbus::message&,
                       gsl::span<const unsigned char> data) {
  ++bench_stat.msgs;
  bench_stat.bytes += static_cast<uint64_t>(data.size());

  if (!bench_stat.got_connection && nullptr != conn) {
    bench_stat.got_connection = true;
    // get_connection_context() is not const-qualified upstream; only the negotiated algorithms are read here
    auto& conn_context = const_cast<atbus::connection*>(conn)->get_connection_context();
    bench_stat.negotiated_crypto = crypto_algorithm_name(conn_context.get_crypto_select_algorithm());
    bench_stat.negotiated_compression = compression_algorithm_name(conn_context.get_compression_select_algorithm());
  }

  // Attribute every message to its connection so a runner can tell whether the
  // payload is split across the ctrl/data connections.
  if (nullptr != conn) {
    ++bench_stat.conn_msg_count[conn];
    bench_stat.conn_bytes_count[conn] += static_cast<uint64_t>(data.size());
  }

  // Light integrity check: the first 8 bytes carry a monotonically increasing sequence
  if (data.size() >= sizeof(uint64_t)) {
    uint64_t seq = 0;
    memcpy(&seq, data.data(), sizeof(uint64_t));
    if (bench_stat.has_seq) {
      if (seq <= bench_stat.last_seq) {
        ++bench_stat.errors;  // duplicated or out-of-order message
        fprintf(stderr, "[anomaly] sample=%zu dup/regress last_seq=%" PRIu64 " seq=%" PRIu64 "\n",
                bench_stat.samples.size(), bench_stat.last_seq, seq);
      } else if (seq != bench_stat.last_seq + 1) {
        ++bench_stat.seq_gaps;
        fprintf(stderr, "[anomaly] sample=%zu gap last_seq=%" PRIu64 " seq=%" PRIu64 "\n", bench_stat.samples.size(),
                bench_stat.last_seq, seq);
      }
    }
    bench_stat.last_seq = seq;
    bench_stat.has_seq = true;
  }

  return 0;
}

int on_new_connection(const atbus::node&, const atbus::connection* conn) {
  ++bench_stat.connections_seen;
  bench_stat.live_connections.insert(conn);
  fprintf(stderr, "[conn] new connection #%zu (%zu live)\n", bench_stat.connections_seen,
          bench_stat.live_connections.size());
  return 0;
}

int on_invalid_connection(const atbus::node&, const atbus::connection*, ATBUS_ERROR_TYPE err) {
  fprintf(stderr, "[conn] invalid connection, err=%d\n", static_cast<int>(err));
  return 0;
}

int on_close_connection(const atbus::node&, const atbus::endpoint*, const atbus::connection* conn) {
  bench_stat.live_connections.erase(conn);
  fprintf(stderr, "[conn] closed connection (%zu live)\n", bench_stat.live_connections.size());
  // The ctrl/data pair means atbus may open and close several connections; only
  // finish the run when every connection is gone.
  if (bench_stat.live_connections.empty()) {
    bench_stat.done = true;
    // Wake the main loop immediately so the process exits promptly
    if (nullptr != main_loop) {
      uv_stop(main_loop);
    }
  }
  return 0;
}

void on_stat_timer(uv_timer_t* /*handle*/) {
  static uint64_t last_msgs = 0;
  static uint64_t last_bytes = 0;
  static double last_cpu = 0;
  static int idle_secs = 0;
  static int secs = 0;

  ++secs;
  double now_cpu = get_cpu_time();
  sample_t s;
  s.sec = secs;
  s.msgs_delta = bench_stat.msgs - last_msgs;
  s.bytes_delta = bench_stat.bytes - last_bytes;
  s.cpu_percent = (now_cpu - last_cpu) * 100.0;  // interval is 1 second, so cpu seconds == percent of one core
  s.rss_kb = get_peak_rss_kb();
  last_msgs = bench_stat.msgs;
  last_bytes = bench_stat.bytes;
  last_cpu = now_cpu;
  bench_stat.samples.push_back(s);

  fprintf(stderr, "[sec %3d] recv=%" PRIu64 " msgs, %" PRIu64 " bytes, cpu=%.1f%%, peak_rss=%ldKB\n", s.sec,
          s.msgs_delta, s.bytes_delta, s.cpu_percent, s.rss_kb);
  if (!bench_stat.conn_bytes_count.empty()) {
    fprintf(stderr, "         per-conn bytes:");
    for (const auto& kv : bench_stat.conn_bytes_count) {
      fprintf(stderr, " %p=%.1fMB", reinterpret_cast<const void*>(kv.first),
              static_cast<double>(kv.second) / 1048576.0);
    }
    fprintf(stderr, "\n");
  }

  // Safety exit: stop 10 seconds after the stream of messages goes idle, so a
  // lost sender cannot keep the receiver running forever.
  if (bench_stat.msgs > 0) {
    if (s.msgs_delta > 0) {
      idle_secs = 0;
    } else {
      ++idle_secs;
      if (idle_secs >= 10 && !bench_stat.done) {
        bench_stat.done = true;
        if (nullptr != main_loop) {
          uv_stop(main_loop);
        }
      }
    }
  }
}

void write_json(double elapsed_sec) {
  double cpu_user = 0;
  double cpu_system = 0;
  uv_rusage_t usage;
  if (0 == uv_getrusage(&usage)) {
    cpu_user = static_cast<double>(usage.ru_utime.tv_sec) + static_cast<double>(usage.ru_utime.tv_usec) / 1e6;
    cpu_system = static_cast<double>(usage.ru_stime.tv_sec) + static_cast<double>(usage.ru_stime.tv_usec) / 1e6;
  }

  FILE* out = stdout;
  if (!conf.json_output.empty()) {
    out = fopen(conf.json_output.c_str(), "w");
    if (nullptr == out) {
      fprintf(stderr, "open json output %s failed\n", conf.json_output.c_str());
      out = stdout;
    }
  }

  fprintf(out, "{\n");
  fprintf(out, "  \"role\": \"recv\",\n");
  fprintf(out, "  \"address\": \"%s\",\n", conf.listen_addr.c_str());
  fprintf(out, "  \"bus_id\": %" PRIu64 ",\n", conf.bus_id);
  fprintf(out,
          "  \"config\": {\"crypto\": \"%s\", \"compression\": \"%s\", \"level\": \"%s\", \"payload_size\": %zu},\n",
          conf.crypto.c_str(), conf.compression.c_str(), conf.level.c_str(), conf.payload_size);
  fprintf(out, "  \"negotiated\": {\"crypto\": \"%s\", \"compression\": \"%s\"},\n",
          bench_stat.negotiated_crypto.c_str(), bench_stat.negotiated_compression.c_str());
  fprintf(out,
          "  \"totals\": {\"msgs\": %" PRIu64 ", \"payload_bytes\": %" PRIu64 ", \"errors\": %" PRIu64
          ", \"seq_gaps\": %" PRIu64 ", \"elapsed_sec\": %.3f},\n",
          bench_stat.msgs, bench_stat.bytes, bench_stat.errors, bench_stat.seq_gaps, elapsed_sec);
  fprintf(out, "  \"cpu\": {\"user_sec\": %.3f, \"system_sec\": %.3f, \"total_sec\": %.3f, \"percent_avg\": %.2f},\n",
          cpu_user, cpu_system, cpu_user + cpu_system,
          elapsed_sec > 0 ? (cpu_user + cpu_system) * 100.0 / elapsed_sec : 0);
  fprintf(out, "  \"peak_rss_kb\": %ld,\n", get_peak_rss_kb());
  fprintf(out, "  \"samples\": [\n");
  for (size_t i = 0; i < bench_stat.samples.size(); ++i) {
    const sample_t& s = bench_stat.samples[i];
    fprintf(out,
            "    {\"sec\": %d, \"msgs\": %" PRIu64 ", \"bytes\": %" PRIu64
            ", \"cpu_percent\": %.2f, \"rss_kb\": %ld}%s\n",
            s.sec, s.msgs_delta, s.bytes_delta, s.cpu_percent, s.rss_kb, i + 1 < bench_stat.samples.size() ? "," : "");
  }
  fprintf(out, "  ]\n}\n");

  if (out != stdout) {
    fclose(out);
  }
}
}  // namespace

int verbose_log_sink(const atfw::util::log::log_formatter::caller_info_t&, atfw::util::nostd::string_view content) {
  fwrite(content.data(), 1, content.size(), stderr);
  fputc('\n', stderr);
  return 0;
}

int main(int argc, char* argv[]) {
  if (argc < 3) {
    printf(
        "usage: %s <listen_addr> <bus_id> [--crypto=...] [--compression=...] [--level=...] [--payload-size=N] "
        "[--json=file]\n",
        argv[0]);
    return 0;
  }

  conf.listen_addr = argv[1];
  conf.bus_id = strtoull(argv[2], nullptr, 0);
  for (int i = 3; i < argc; ++i) {
    std::string arg = argv[i];
    auto pos = arg.find('=');
    if (std::string::npos == pos) {
      continue;
    }
    std::string key = arg.substr(0, pos);
    std::string value = arg.substr(pos + 1);
    if (key == "--crypto") {
      conf.crypto = value;
    } else if (key == "--compression") {
      conf.compression = value;
    } else if (key == "--level") {
      conf.level = value;
    } else if (key == "--payload-size") {
      conf.payload_size = static_cast<size_t>(strtoul(value.c_str(), nullptr, 10));
    } else if (key == "--json") {
      conf.json_output = value;
    } else if (key == "--verbose") {
      conf.verbose = true;
    }
  }

  uv_loop_t loop;
  main_loop = &loop;
  int loop_ret = uv_loop_init(&loop);
  if (0 != loop_ret) {
    fprintf(stderr, "uv_loop_init failed: %d\n", loop_ret);
    return -1;
  }

  atbus::node::conf_t node_conf;
  node_conf.ev_loop = &loop;
  setup_crypto(node_conf);
  if (!setup_compression(node_conf)) {
    fprintf(stderr, "invalid compression config: %s / %s\n", conf.compression.c_str(), conf.level.c_str());
    uv_loop_close(&loop);
    return -1;
  }

  atbus::node::ptr_t node = atbus::node::create();
  node->init(conf.bus_id, &node_conf);
  // keep the data path quiet unless --verbose is given
  node->get_logger()->set_level(conf.verbose ? atfw::util::log::log_level::kDebug : atfw::util::log::log_level::kError);
  if (conf.verbose) {
    node->get_logger()->clear_sinks();
    node->get_logger()->add_sink(verbose_log_sink);
    node->enable_debug_message_verbose();
  }

  int ret = node->listen(conf.listen_addr);
  if (ret < 0) {
    fprintf(stderr, "listen %s failed, ret=%d\n", conf.listen_addr.c_str(), ret);
    uv_loop_close(&loop);
    return -1;
  }

  node->set_on_forward_request_handle(on_forward_request);
  node->set_on_new_connection_handle(on_new_connection);
  node->set_on_invalid_connection_handle(on_invalid_connection);
  node->set_on_close_connection_handle(on_close_connection);

  uv_timer_t stat_timer;
  uv_timer_init(&loop, &stat_timer);
  uv_timer_start(&stat_timer, on_stat_timer, 1000, 1000);

  bench_stat.start_time = std::chrono::steady_clock::now();
  bench_stat.cpu_user_start = get_cpu_time();

  while (!bench_stat.done) {
    node->poll();
  }

  double elapsed_sec = std::chrono::duration_cast<std::chrono::duration<double>>(std::chrono::steady_clock::now() -
                                                                                 bench_stat.start_time)
                           .count();

  uv_timer_stop(&stat_timer);
  uv_close(reinterpret_cast<uv_handle_t*>(&stat_timer), nullptr);
  uv_run(&loop, UV_RUN_NOWAIT);
  uv_loop_close(&loop);

  write_json(elapsed_sec);
  return 0;
}
