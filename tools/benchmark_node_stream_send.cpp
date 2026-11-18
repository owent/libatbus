// Copyright 2026 atframework
// Node-level TCP stream benchmark sender.
//
// Connects to a benchmark_node_stream_recv node and floods data-transform
// messages of a fixed payload size until the duration elapses, then drains and
// writes per-second samples and final statistics as JSON.
//
// usage: benchmark_node_stream_send <connect_addr> <bus_id> <target_id> <payload_size> <duration_sec> [options]
//   --crypto=<none|aes-128-gcm|aes-192-gcm|aes-256-gcm|chacha20|chacha20-poly1305-ietf>
//   --compression=<none|lz4|zstd>
//   --level=<fast|low-cpu|balanced|high-ratio|max-ratio>  (unified compression level, default balanced)
//   --json=<output file>                                  (default: stdout)

#include <chrono>
#include <cinttypes>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iostream>
#include <string>
#include <vector>

#include <algorithm/compression.h>
#include <atbus_node.h>
#include <detail/libatbus_channel_export.h>  // IWYU pragma: keep (provides uv.h)

namespace {
constexpr int32_t kBenchmarkMessageType = 10001;

struct run_config {
  std::string connect_addr;
  std::string listen_addr;
  bool verbose = false;
  uint64_t bus_id = 0;
  uint64_t target_id = 0;
  size_t payload_size = 1024;
  double duration_sec = 15.0;
  std::string crypto = "none";
  std::string compression = "none";
  std::string level = "balanced";
  std::string json_output;
};

struct sample_t {
  int sec;
  uint64_t msgs_delta;
  uint64_t bytes_delta;
  double cpu_percent;
  long rss_kb;
};

struct stats_t {
  bool ready = false;
  bool done = false;
  bool peer_lost = false;
  uint64_t msgs = 0;
  uint64_t bytes = 0;
  uint64_t backpressure = 0;  // BUFF_LIMIT retries
  uint64_t errors = 0;
  uint64_t seq = 0;
  std::vector<sample_t> samples;

  std::chrono::steady_clock::time_point start_time;
};

run_config conf;
stats_t bench_stat;
uv_loop_t* main_loop = nullptr;
std::vector<unsigned char> payload;

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

void build_payload() {
  payload.clear();
  if (conf.payload_size < sizeof(uint64_t)) {
    conf.payload_size = sizeof(uint64_t);
  }
  payload.resize(conf.payload_size);
  // Reserve the first 8 bytes for the per-message sequence counter.
  // Deterministic, moderately compressible JSON-like records; the measured
  // compression ratio is reported alongside the throughput numbers.
  static const char* kKeys[] = {"player", "guild", "level", "score", "item", "quest", "zone", "match"};
  static const char* kFillers[] = {"aabbccdd", "00112233", "deadbeef", "01234567", "89abcdef"};

  size_t pos = sizeof(uint64_t);
  uint32_t rng = 0x12345678u;
  char* text = reinterpret_cast<char*>(payload.data());
  while (pos < conf.payload_size) {
    rng = rng * 1103515245u + 12345u;
    const char* key = kKeys[(rng >> 16) & 7];
    rng = rng * 1103515245u + 12345u;
    uint32_t num = (rng >> 8) & 0xFFFF;
    rng = rng * 1103515245u + 12345u;
    const char* filler = kFillers[(rng >> 16) % (sizeof(kFillers) / sizeof(kFillers[0]))];
    int written = snprintf(text + pos, conf.payload_size - pos, "{\"%s\":%u,\"tag\":\"%s%06u\"}", key, num, filler,
                           num & 0xFFFFFF);
    if (written <= 0) {
      break;
    }
    pos += static_cast<size_t>(written);
  }
  for (; pos < conf.payload_size; ++pos) {
    text[pos] = static_cast<char>('0' + (pos & 7));  // tail padding, still compressible
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

// Measure the compressed size of the payload with the configured algorithm/level.
// This mirrors what the protocol stack does to the message body, so the JSON
// report can show the actual compression ratio behind the throughput numbers.
bool measure_compression_ratio(size_t& compressed_size) {
  compressed_size = 0;
  if (conf.compression == "none") {
    return false;
  }

  ::atfw::util::compression::algorithm_t algo;
  if (conf.compression == "lz4") {
    algo = ::atfw::util::compression::algorithm_t::kLz4;
  } else if (conf.compression == "zstd") {
    algo = ::atfw::util::compression::algorithm_t::kZstd;
  } else {
    return false;
  }

  auto level = ::atfw::util::compression::level_t::kBalanced;
  if (conf.level == "fast") {
    level = ::atfw::util::compression::level_t::kFast;
  } else if (conf.level == "low-cpu") {
    level = ::atfw::util::compression::level_t::kLowCpu;
  } else if (conf.level == "balanced") {
    level = ::atfw::util::compression::level_t::kBalanced;
  } else if (conf.level == "high-ratio") {
    level = ::atfw::util::compression::level_t::kHighRatio;
  } else if (conf.level == "max-ratio") {
    level = ::atfw::util::compression::level_t::kMaxRatio;
  } else if (conf.level == "default") {
    level = ::atfw::util::compression::level_t::kDefault;
  }

  std::vector<unsigned char> compressed;
  int res = ::atfw::util::compression::compress(
      algo, gsl::span<const unsigned char>(payload.data() + sizeof(uint64_t), payload.size() - sizeof(uint64_t)),
      compressed, level);
  if (0 != res) {
    return false;
  }
  compressed_size = compressed.size();
  return true;
}

int on_add_endpoint(const atbus::node&, atbus::endpoint*, ATBUS_ERROR_TYPE) {
  // The run duration starts when the peer is registered, not when the process starts,
  // so the connect handshake does not eat into the measured window.
  bench_stat.ready = true;
  bench_stat.start_time = std::chrono::steady_clock::now();
  return 0;
}

int on_close_connection(const atbus::node&, const atbus::endpoint*, const atbus::connection*) {
  bench_stat.peer_lost = true;
  bench_stat.done = true;
  fprintf(stderr, "[conn] connection closed, msgs=%" PRIu64 ", seq=%" PRIu64 ", backpressure=%" PRIu64 "\n",
          bench_stat.msgs, bench_stat.seq, bench_stat.backpressure);
  if (nullptr != main_loop) {
    uv_stop(main_loop);
  }
  return 0;
}

void on_stat_timer(uv_timer_t* /*handle*/) {
  static uint64_t last_msgs = 0;
  static uint64_t last_bytes = 0;
  static double last_cpu = 0;
  static int secs = 0;

  ++secs;
  double now_cpu = get_cpu_time();
  sample_t s;
  s.sec = secs;
  s.msgs_delta = bench_stat.msgs - last_msgs;
  s.bytes_delta = bench_stat.bytes - last_bytes;
  s.cpu_percent = (now_cpu - last_cpu) * 100.0;
  s.rss_kb = get_peak_rss_kb();
  last_msgs = bench_stat.msgs;
  last_bytes = bench_stat.bytes;
  last_cpu = now_cpu;
  bench_stat.samples.push_back(s);

  fprintf(stderr, "[sec %3d] sent=%" PRIu64 " msgs, %" PRIu64 " bytes, bp=%" PRIu64 ", cpu=%.1f%%, peak_rss=%ldKB\n",
          s.sec, s.msgs_delta, s.bytes_delta, bench_stat.backpressure, s.cpu_percent, s.rss_kb);
}

void write_json(double elapsed_sec) {
  double cpu_user = 0;
  double cpu_system = 0;
  uv_rusage_t usage;
  if (0 == uv_getrusage(&usage)) {
    cpu_user = static_cast<double>(usage.ru_utime.tv_sec) + static_cast<double>(usage.ru_utime.tv_usec) / 1e6;
    cpu_system = static_cast<double>(usage.ru_stime.tv_sec) + static_cast<double>(usage.ru_stime.tv_usec) / 1e6;
  }

  size_t compressed_size = 0;
  bool has_ratio = measure_compression_ratio(compressed_size);

  FILE* out = stdout;
  if (!conf.json_output.empty()) {
    out = fopen(conf.json_output.c_str(), "w");
    if (nullptr == out) {
      fprintf(stderr, "open json output %s failed\n", conf.json_output.c_str());
      out = stdout;
    }
  }

  fprintf(out, "{\n");
  fprintf(out, "  \"role\": \"send\",\n");
  fprintf(out, "  \"address\": \"%s\",\n", conf.connect_addr.c_str());
  fprintf(out, "  \"bus_id\": %" PRIu64 ",\n", conf.bus_id);
  fprintf(out,
          "  \"config\": {\"crypto\": \"%s\", \"compression\": \"%s\", \"level\": \"%s\", \"payload_size\": %zu, "
          "\"duration_sec\": %.1f},\n",
          conf.crypto.c_str(), conf.compression.c_str(), conf.level.c_str(), conf.payload_size, conf.duration_sec);
  fprintf(out,
          "  \"totals\": {\"msgs\": %" PRIu64 ", \"payload_bytes\": %" PRIu64 ", \"backpressure\": %" PRIu64
          ", \"errors\": %" PRIu64 ", \"elapsed_sec\": %.3f},\n",
          bench_stat.msgs, bench_stat.bytes, bench_stat.backpressure, bench_stat.errors, elapsed_sec);
  fprintf(out, "  \"cpu\": {\"user_sec\": %.3f, \"system_sec\": %.3f, \"total_sec\": %.3f, \"percent_avg\": %.2f},\n",
          cpu_user, cpu_system, cpu_user + cpu_system,
          elapsed_sec > 0 ? (cpu_user + cpu_system) * 100.0 / elapsed_sec : 0);
  fprintf(out, "  \"peak_rss_kb\": %ld,\n", get_peak_rss_kb());
  if (has_ratio) {
    fprintf(out, "  \"compression\": {\"payload_size\": %zu, \"compressed_size\": %zu, \"ratio\": %.4f},\n",
            conf.payload_size - sizeof(uint64_t), compressed_size,
            static_cast<double>(compressed_size) / static_cast<double>(conf.payload_size - sizeof(uint64_t)));
  }
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

int verbose_log_sink(const atfw::util::log::log_formatter::caller_info_t&, atfw::util::nostd::string_view content) {
  fwrite(content.data(), 1, content.size(), stderr);
  fputc('\n', stderr);
  return 0;
}
}  // namespace

int main(int argc, char* argv[]) {
  if (argc < 6) {
    printf(
        "usage: %s <connect_addr> <bus_id> <target_id> <payload_size> <duration_sec> [--crypto=...] "
        "[--compression=...] [--level=...] [--json=file]\n",
        argv[0]);
    return 0;
  }

  conf.connect_addr = argv[1];
  conf.bus_id = strtoull(argv[2], nullptr, 0);
  conf.target_id = strtoull(argv[3], nullptr, 0);
  conf.payload_size = static_cast<size_t>(strtoul(argv[4], nullptr, 10));
  conf.duration_sec = atof(argv[5]);
  for (int i = 6; i < argc; ++i) {
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
    } else if (key == "--json") {
      conf.json_output = value;
    } else if (key == "--listen") {
      conf.listen_addr = value;
    } else if (key == "--verbose") {
      conf.verbose = true;
    }
  }

  build_payload();

  // libuv requires applications to ignore SIGPIPE; otherwise a write into a
  // closed socket (peer reset) kills the process before uv reports the error.
#ifdef SIGPIPE
  signal(SIGPIPE, SIG_IGN);
#endif

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

  // Listening makes this node advertise an address, so the peer's connect-back
  // builds the designed ctrl/data connection pair instead of a degenerate self loop.
  if (!conf.listen_addr.empty()) {
    int listen_ret = node->listen(conf.listen_addr);
    if (listen_ret < 0) {
      fprintf(stderr, "listen %s failed, ret=%d\n", conf.listen_addr.c_str(), listen_ret);
      uv_loop_close(&loop);
      return -1;
    }
  }

  int ret = node->connect(conf.connect_addr);
  if (ret < 0) {
    fprintf(stderr, "connect %s failed, ret=%d\n", conf.connect_addr.c_str(), ret);
    uv_loop_close(&loop);
    return -1;
  }

  node->set_on_add_endpoint_handle(on_add_endpoint);
  node->set_on_close_connection_handle(on_close_connection);

  uv_timer_t stat_timer;
  uv_timer_init(&loop, &stat_timer);
  uv_timer_start(&stat_timer, on_stat_timer, 1000, 1000);

  bench_stat.start_time = std::chrono::steady_clock::now();
  const auto connect_deadline = bench_stat.start_time + std::chrono::seconds(30);

  while (!bench_stat.done) {
    node->poll();
    if (!bench_stat.ready) {
      if (std::chrono::steady_clock::now() > connect_deadline) {
        fprintf(stderr, "connect timeout, peer not registered in 30s\n");
        bench_stat.errors += 1;
        break;
      }
      continue;
    }

    double elapsed = 0;
    // Flood until the channel reports backpressure (BUFF_LIMIT) or a hard error.
    while (!bench_stat.done) {
      elapsed = std::chrono::duration_cast<std::chrono::duration<double>>(std::chrono::steady_clock::now() -
                                                                          bench_stat.start_time)
                    .count();
      if (elapsed >= conf.duration_sec) {
        break;
      }

      uint64_t seq = ++bench_stat.seq;
      memcpy(payload.data(), &seq, sizeof(uint64_t));
      int res = node->send_data(conf.target_id, kBenchmarkMessageType,
                                gsl::span<const unsigned char>(payload.data(), payload.size()));
      if (0 == res) {
        ++bench_stat.msgs;
        bench_stat.bytes += payload.size();
        continue;
      }

      // Undo the sequence allocation on failure; the same value is retried later.
      --bench_stat.seq;
      if (EN_ATBUS_ERR_BUFF_LIMIT == res) {
        ++bench_stat.backpressure;
        break;  // wait for the write queue to drain on the next poll
      }

      ++bench_stat.errors;
      fprintf(stderr, "send_data failed, ret=%d\n", res);
      if (EN_ATBUS_ERR_ATNODE_NO_CONNECTION == res || EN_ATBUS_ERR_NODE_TIMEOUT == res) {
        bench_stat.peer_lost = true;
        bench_stat.done = true;
      }
      break;
    }

    if (elapsed >= conf.duration_sec) {
      break;
    }
  }

  // Drain in-flight data for a moment before reporting.
  const auto drain_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
  while (!bench_stat.done && std::chrono::steady_clock::now() < drain_deadline) {
    node->poll();
  }

  bench_stat.done = true;
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
