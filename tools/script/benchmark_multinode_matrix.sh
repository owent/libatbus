#!/usr/bin/env bash
# Copyright 2026 atframework
#
# Multi-node interconnect matrix: node counts x payload sizes x crypto/compression
# combos over TCP loopback, 1 receiver (hub) + N-1 senders per run.
# Run on the target machine.
#
# usage: benchmark_multinode_matrix.sh <bin_dir> <result_dir> <duration> <port_base>
#   <bin_dir>     directory holding benchmark_node_stream_recv / benchmark_node_stream_send.
#                 Use one build flavour for the whole matrix (and for any baseline it is
#                 compared with): a statically linked libatbus and a shared-library
#                 build differ by ~20% in small-packet QPS on the same machine.
#   RESULT_DIR    one sub-directory per run: n<N>__<crypto>__<comp>-<level>__<size>/
#
# Environment:
#   PRELOAD_LIB       optional allocator (e.g. libmimalloc.so) prepended via LD_PRELOAD
#   NODES_FILTER      optional space-separated subset of node counts (default: 2 10 100 1000)
#   SIZES_FILTER      optional space-separated subset of payload sizes
#   COMBO_FILTER      optional space-separated subset of "crypto|comp|level" specs
#   SEND_BUFFER_BYTES          io_stream send buffer limit per sender for node counts up to
#                              LARGE_FANOUT_NODES (default 0 = libatbus default, 8MB)
#   LARGE_FANOUT_BUFFER_BYTES  the same for larger node counts (default 1048576)
#   LARGE_FANOUT_NODES         node-count threshold between the two (default 256)
#                              A sender that outruns the receiver fills its send buffer. With
#                              999 senders the 8MB default costs about 21GB of process memory
#                              for 200B messages and leaves the machine short of memory; a
#                              1MB limit keeps about 5GB free, and the receiver's throughput
#                              does not depend on the limit once it is the bottleneck.
#   WARMUP_SEC                 samples of the receiver that end within this time are not rated
#                              (default 2)
#   CPU_PIN           0 leaves the CPU placement of every process to the scheduler; by
#                     default the hub owns one CPU and the senders share the others
#   MIN_AVAIL_MB      a run whose senders bring MemAvailable below this is stopped and
#                     counted as failed (default 512)
#
# CPU placement: the hub is pinned to one CPU and the senders are spread round-robin
# over the remaining CPUs. The CPU list is read from this process's affinity, because
# VM guests often expose non-contiguous CPU numbers (e.g. 0-1,13-14,17-19); a naive
# "-c 1-N" intersects that list down to a single CPU and stacks every sender on it.
#
# Connection setup:
# - Every sender listens on port_base+<id>; port_base must stay below the kernel's
#   ephemeral port range, otherwise outbound connections can land on a port that a
#   sender is about to listen on and that sender fails with EADDRINUSE.
# - The hub's listen backlog is set to node count + 128 so that all clients can
#   connect at the same time, and the runner raises its own file descriptor limit,
#   which otherwise caps the hub near 510 clients (2 connections each).
# - Senders connect and register first and wait at a gate file, so all of them start
#   flooding from the same instant no matter how long launching and registering them
#   took (a receiver that already digests a flood serves the remaining handshakes slowly).
# - A run only counts as OK when every sender reported having sent messages.

set -u
export LC_ALL=C
BIN_DIR="${1:?bin_dir required}"
RESULT_DIR="${2:?result_dir required}"
DURATION="${3:-10}"
PORT_BASE="${4:-15000}"
SEND_BUFFER_BYTES="${SEND_BUFFER_BYTES:-0}"
LARGE_FANOUT_BUFFER_BYTES="${LARGE_FANOUT_BUFFER_BYTES:-1048576}"
LARGE_FANOUT_NODES="${LARGE_FANOUT_NODES:-256}"
CPU_PIN="${CPU_PIN:-1}"
WARMUP_SEC="${WARMUP_SEC:-2}"
MIN_AVAIL_MB="${MIN_AVAIL_MB:-512}"

read -r -a NODE_COUNTS <<<"${NODES_FILTER:-2 10 100 1000}"
read -r -a SIZES <<<"${SIZES_FILTER:-200 256 1024 8192 32768 307200}"

MAX_NODES=0
for n in "${NODE_COUNTS[@]}"; do [ "$n" -gt "$MAX_NODES" ] && MAX_NODES=$n; done

# The hub keeps two connections per client (control + data), so the common soft limit
# of 1024 file descriptors caps it near 510 clients: the rest never get accepted.
NEED_FDS=$(( MAX_NODES * 2 + 256 ))
if [ "$(ulimit -Sn)" -lt "$NEED_FDS" ]; then
  ulimit -n "$NEED_FDS" 2>/dev/null ||
    { echo "need $NEED_FDS file descriptors for $MAX_NODES nodes; raise 'ulimit -n' (hard limit: $(ulimit -Hn))" >&2; exit 1; }
fi
if [ -r /proc/sys/net/ipv4/ip_local_port_range ]; then
  read -r EPH_LO EPH_HI < /proc/sys/net/ipv4/ip_local_port_range
  LAST_PORT=$((PORT_BASE + MAX_NODES - 1))
  if [ "$LAST_PORT" -ge "$EPH_LO" ] && [ "$PORT_BASE" -le "$EPH_HI" ]; then
    echo "ports ${PORT_BASE}..${LAST_PORT} overlap the ephemeral port range ${EPH_LO}-${EPH_HI};" \
      "senders would fail to listen. Pick a port_base below ${EPH_LO}." >&2
    exit 1
  fi
fi

RECV_BIN="$BIN_DIR/benchmark_node_stream_recv"
SEND_BIN="$BIN_DIR/benchmark_node_stream_send"
for f in "$RECV_BIN" "$SEND_BIN"; do
  [ -x "$f" ] || { echo "not executable: $f" >&2; exit 1; }
done

RECV_ADDR="ipv4://127.0.0.1:${PORT_BASE}"
RECV_BUS_ID=200000001

# Expand the affinity list ("0-1,13-14,17") into one CPU number per line.
mapfile -t ALL_CPUS < <(taskset -pc $$ | sed 's/^[^:]*: //' | tr ',' '\n' |
  awk -F- '{ if (NF < 2 || $2 == "") print $1; else for (i = $1 + 0; i <= $2 + 0; ++i) print i }')
[ "${#ALL_CPUS[@]}" -ge 2 ] || { echo "need at least 2 usable CPUs, got: ${ALL_CPUS[*]:-none}" >&2; exit 1; }
RECV_CPU="${ALL_CPUS[0]}"
SEND_CPUS=("${ALL_CPUS[@]:1}")
N_SEND_CPUS=${#SEND_CPUS[@]}

COMBOS=(
  "none|none|default"
  "none|lz4|fast"
  "none|lz4|default"
  "none|zstd|default"
  "none|zstd|high-ratio"
  "aes-128-gcm|none|default"
  "aes-256-gcm|none|default"
  "chacha20-poly1305-ietf|none|default"
  "aes-128-gcm|lz4|fast"
  "aes-256-gcm|lz4|fast"
  "chacha20-poly1305-ietf|lz4|fast"
  "aes-128-gcm|lz4|default"
  "aes-256-gcm|lz4|default"
  "chacha20-poly1305-ietf|lz4|default"
  "aes-128-gcm|zstd|default"
  "aes-256-gcm|zstd|default"
  "chacha20-poly1305-ietf|zstd|default"
  "aes-128-gcm|zstd|high-ratio"
  "aes-256-gcm|zstd|high-ratio"
  "chacha20-poly1305-ietf|zstd|high-ratio"
)
if [ -n "${COMBO_FILTER:-}" ]; then
  read -r -a WANTED <<<"$COMBO_FILTER"
  FILTERED=()
  for c in "${COMBOS[@]}"; do
    for w in "${WANTED[@]}"; do
      [ "$c" = "$w" ] && FILTERED+=("$c")
    done
  done
  [ "${#FILTERED[@]}" -gt 0 ] || { echo "COMBO_FILTER matches nothing" >&2; exit 1; }
  COMBOS=("${FILTERED[@]}")
fi

# Start one benchmark process in a background subshell: with the optional allocator
# preloaded and, unless CPU_PIN=0, on the given CPU. exec turns the subshell into the
# process, so the PID the runner tracks ($!) is the process itself.
start_proc() {
  if [[ -n "${PRELOAD_LIB:-}" ]]; then
    export LD_PRELOAD="${PRELOAD_LIB}"
  else
    unset LD_PRELOAD
  fi
  if [ "$CPU_PIN" -eq 1 ]; then
    exec taskset -c "$1" "${@:2}"
  else
    shift
    exec "$@"
  fi
}

TOTAL=$(( ${#COMBOS[@]} * ${#SIZES[@]} * ${#NODE_COUNTS[@]} ))
RUN=0
FAIL=0

# Steady-state QPS of one receiver report.
#   Every sample line carries "msgs" (messages received) and "interval" (the real time
#   the sample covers; reports of builds without it are read as 1 s). The stat timer of
#   the receiver only fires when its event loop gets to run, and with many connections
#   one poll() can keep the loop busy for seconds, so the rate of a sample is
#   msgs / interval.
#   Samples that end within the warm-up window are dropped, and the samples that reached
#   >=80% of the peak rate form the plateau. The result is the rate at the middle of the
#   plateau's duration (samples weighted by their length). It ignores the ramp-up and
#   ramp-down seconds and the partial sample before the receiver exits, which drag a
#   plain average down by 5-10%.
plateau_qps() {
  awk -v warm="$WARMUP_SEC" '
    /"sec":/ {
      m = 0; iv = 1
      if (match($0, /"msgs": [0-9]+/)) m = substr($0, RSTART + 8, RLENGTH - 8) + 0
      if (match($0, /"interval": [0-9.]+/)) iv = substr($0, RSTART + 12, RLENGTH - 12) + 0
      t += iv
      if (t <= warm + 0.1 || iv < 0.2) next   # +0.1: timer jitter at the warm-up boundary
      n++; r[n] = m / iv; w[n] = iv
      if (r[n] > mx) mx = r[n]
    }
    END {
      k = 0; tw = 0
      for (i = 1; i <= n; i++) if (r[i] >= 0.8 * mx) { k++; pr[k] = r[i]; pw[k] = w[i]; tw += w[i] }
      if (k == 0 || mx <= 0) { print "NA 0"; exit }
      # insertion sort by rate, weights kept aligned
      for (i = 2; i <= k; i++) {
        x = pr[i]; xw = pw[i]; j = i - 1
        while (j >= 1 && pr[j] > x) { pr[j + 1] = pr[j]; pw[j + 1] = pw[j]; j-- }
        pr[j + 1] = x; pw[j + 1] = xw
      }
      c = 0
      for (i = 1; i <= k; i++) {
        c += pw[i]
        if (2 * c >= tw) {
          if (2 * c == tw && i < k) q = (pr[i] + pr[i + 1]) / 2; else q = pr[i]
          print int(q), int(tw)
          exit
        }
      }
    }' "$1"
}

mem_available_mb() { awk '/^MemAvailable:/ { printf "%d", $2 / 1024 }' /proc/meminfo; }

echo "=== matrix: $TOTAL runs start $(date) ==="
echo "cpus: hub=$RECV_CPU senders=${SEND_CPUS[*]} (cpu_pin=$CPU_PIN)"
echo "binaries: $BIN_DIR  send_buffer_bytes=${SEND_BUFFER_BYTES:-default} (node count > $LARGE_FANOUT_NODES: $LARGE_FANOUT_BUFFER_BYTES)  duration=${DURATION}s"

for NC in "${NODE_COUNTS[@]}"; do
  SENDERS=$((NC - 1))
  [ "$SENDERS" -lt 1 ] && SENDERS=1
  HUB_BACKLOG=$((NC + 128))
  if [ "$NC" -gt "$LARGE_FANOUT_NODES" ]; then
    RUN_SEND_BUFFER="$LARGE_FANOUT_BUFFER_BYTES"
  else
    RUN_SEND_BUFFER="$SEND_BUFFER_BYTES"
  fi
  SEND_BUFFER_ARG=()
  [ "$RUN_SEND_BUFFER" -gt 0 ] && SEND_BUFFER_ARG=("--send-buffer=${RUN_SEND_BUFFER}")

  for SIZE in "${SIZES[@]}"; do
    for COMBO in "${COMBOS[@]}"; do
      IFS='|' read -r CRYPTO COMP LEVEL <<<"$COMBO"
      RUN=$((RUN + 1))
      NAME="n${NC}__${CRYPTO}__${COMP}-${LEVEL}__${SIZE}"
      COMBO_DIR="$RESULT_DIR/$NAME"
      mkdir -p "$COMBO_DIR"
      GATE="$COMBO_DIR/go"
      rm -f "$GATE" "$GATE".ready.*

      # The processes of the previous run release their memory asynchronously; give
      # them up to 30 seconds before the next lot is started.
      for _ in $(seq 1 30); do
        [ "$(mem_available_mb)" -ge "$MIN_AVAIL_MB" ] && break
        sleep 1
      done

      start_proc "$RECV_CPU" "$RECV_BIN" "$RECV_ADDR" "$RECV_BUS_ID" \
        --crypto="$CRYPTO" --compression="$COMP" --level="$LEVEL" --payload-size="$SIZE" \
        --backlog="$HUB_BACKLOG" \
        --json="$COMBO_DIR/recv.json" >"$COMBO_DIR/recv.log" 2>&1 &
      RP=$!
      sleep 1

      pids=()
      for sid in $(seq 1 "$SENDERS"); do
        BID=$((RECV_BUS_ID + sid))
        cpu="${SEND_CPUS[$(( (sid - 1) % N_SEND_CPUS ))]}"
        start_proc "$cpu" "$SEND_BIN" "$RECV_ADDR" "$BID" "$RECV_BUS_ID" "$SIZE" "$DURATION" \
          --crypto="$CRYPTO" --compression="$COMP" --level="$LEVEL" "${SEND_BUFFER_ARG[@]}" \
          --listen="ipv4://127.0.0.1:$((PORT_BASE + sid))" --gate="$GATE" \
          --json="$COMBO_DIR/send_${sid}.json" >"$COMBO_DIR/send_${sid}.log" 2>&1 &
        pids+=($!)
      done

      # open the gate once every sender is registered (or one of them has already died);
      # senders publish their ready file after their handshake, not at process start
      min_avail=$(mem_available_mb)
      gate_t0=$SECONDS
      gate_deadline=$(( SECONDS + SENDERS / 30 + 60 ))
      while [ "$(ls "$GATE".ready.* 2>/dev/null | wc -l)" -lt "$SENDERS" ] &&
            kill -0 "${pids[@]}" 2>/dev/null && [ "$SECONDS" -lt "$gate_deadline" ]; do
        avail=$(mem_available_mb)
        [ "$avail" -lt "$min_avail" ] && min_avail=$avail
        sleep 0.2
      done
      gate_wait=$(( SECONDS - gate_t0 ))
      rm -f "$GATE".ready.*
      touch "$GATE"

      # wait for the senders while tracking the memory floor; never hang on a stuck one,
      # and stop the senders before the machine runs out of memory (the run is a FAIL then)
      lowmem=0
      deadline=$(( SECONDS + DURATION * 4 + 120 ))
      while kill -0 "${pids[@]}" 2>/dev/null; do
        avail=$(mem_available_mb)
        [ "$avail" -lt "$min_avail" ] && min_avail=$avail
        if [ "$avail" -lt "$MIN_AVAIL_MB" ]; then
          echo "    $NAME: only ${avail}MB memory available, stopping its senders" >&2
          lowmem=1
          kill -9 "${pids[@]}" 2>/dev/null
          break
        fi
        if [ "$SECONDS" -ge "$deadline" ]; then
          echo "    senders of $NAME did not exit in time, killing" >&2
          kill -9 "${pids[@]}" 2>/dev/null
          break
        fi
        sleep 0.5
      done
      for p in "${pids[@]}"; do wait "$p" 2>/dev/null; done

      for _ in $(seq 1 20); do kill -0 "$RP" 2>/dev/null || break; sleep 1; done
      kill -TERM "$RP" 2>/dev/null
      sleep 1
      kill -9 "$RP" 2>/dev/null
      wait "$RP" 2>/dev/null
      rm -f "$GATE" "$GATE".ready.*

      # A run is only valid if every sender took part: it wrote a report and sent
      # something. A sender report carries "msgs" in its totals and again in every
      # periodic sample, so only the first occurrence of each file is counted.
      n_json=0
      sent_msgs=0
      idle_senders=0
      bp_sum=0
      send_rss_max=0
      send_rss_min=0
      if ls "$COMBO_DIR"/send_*.json >/dev/null 2>&1; then
        read -r n_json sent_msgs idle_senders bp_sum send_rss_max send_rss_min < <(awk '
          function num(key) {
            if (match($0, "\"" key "\": [0-9]+")) return substr($0, RSTART + length(key) + 4, RLENGTH - length(key) - 4) + 0
            return -1
          }
          FNR == 1 { seen = 0 }
          {
            if (!seen) {
              m = num("msgs")
              if (m >= 0) { n++; s += m; if (m == 0) z++; b = num("backpressure"); if (b >= 0) bp += b; seen = 1 }
            }
            r = num("peak_rss_kb")
            if (r >= 0) {
              if (r > rmax) rmax = r
              if (rmin == 0 || r < rmin) rmin = r
              nextfile
            }
          }
          END { print n + 0, s + 0, z + 0, bp + 0, rmax + 0, rmin + 0 }' "$COMBO_DIR"/send_*.json)
      fi
      qps=NA
      plateau_secs=0
      recv_msgs=NA
      if [ -f "$COMBO_DIR/recv.json" ]; then
        read -r qps plateau_secs < <(plateau_qps "$COMBO_DIR/recv.json")
        recv_msgs=$(grep -oE '"msgs": [0-9]+' "$COMBO_DIR/recv.json" | head -1 | awk '{print $2}')
      fi

      STATUS=OK
      [ -f "$COMBO_DIR/recv.json" ] || STATUS=FAIL
      [ "$n_json" -eq "$SENDERS" ] || STATUS=FAIL
      [ "$idle_senders" -eq 0 ] || STATUS=FAIL
      [ "$plateau_secs" -ge 3 ] || STATUS=FAIL
      [ "$lowmem" -eq 0 ] || STATUS=FAIL
      echo "[$RUN/$TOTAL] $STATUS $NAME qps=$qps plateau_secs=$plateau_secs recv=$recv_msgs sent=$sent_msgs" \
        "senders=$n_json/$SENDERS idle_senders=$idle_senders backpressure=$bp_sum" \
        "send_rss_kb=$send_rss_min-$send_rss_max send_buffer=$RUN_SEND_BUFFER gate_wait_sec=$gate_wait min_avail_mb=$min_avail"
      [ "$STATUS" = OK ] || FAIL=$((FAIL + 1))
    done
  done
done

echo "=== matrix done: $RUN runs, $FAIL failed, $(date) ==="
