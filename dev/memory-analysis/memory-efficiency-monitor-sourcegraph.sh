#!/usr/bin/env bash
set -euo pipefail

namespace="${SRC_AUTH_PERMS_SYNC_MONITOR_NAMESPACE:-m}"
interval_seconds="${SRC_AUTH_PERMS_SYNC_MONITOR_INTERVAL_SECONDS:-5}"
postgres_interval_seconds="${SRC_AUTH_PERMS_SYNC_MONITOR_POSTGRES_INTERVAL_SECONDS:-10}"
statements_interval_seconds="${SRC_AUTH_PERMS_SYNC_MONITOR_STATEMENTS_INTERVAL_SECONDS:-30}"
duration_seconds="${SRC_AUTH_PERMS_SYNC_MONITOR_DURATION_SECONDS:-}"
output_dir="${SRC_AUTH_PERMS_SYNC_MONITOR_OUTPUT_DIR:-}"
frontend_target="${SRC_AUTH_PERMS_SYNC_MONITOR_FRONTEND_TARGET:-deployment/sourcegraph-frontend}"
postgres_target="${SRC_AUTH_PERMS_SYNC_MONITOR_POSTGRES_TARGET:-pod/pgsql-0}"
kubectl_bin="${KUBECTL:-kubectl}"
psql_command="${SRC_AUTH_PERMS_SYNC_MONITOR_PSQL_COMMAND:-psql -X -U sg -d sg}"
stream_logs=true

usage() {
  cat <<'EOF'
Usage: dev/memory-efficiency-monitor-sourcegraph.sh [options]

Collect timestamped Sourcegraph pod load evidence while the e2e script runs.
Press Ctrl-C to stop, or pass --duration-seconds.

Options:
  --namespace NAME                  Kubernetes namespace (default: m)
  --interval-seconds N              Pod/process/cgroup sample interval (default: 5)
  --postgres-interval-seconds N     pg_stat_activity sample interval (default: 10)
  --statements-interval-seconds N   pg_stat_statements sample interval (default: 30)
  --duration-seconds N              Stop automatically after N seconds
  --output-dir PATH                 Output directory (default: /tmp/src-auth-perms-sync-sourcegraph-load-<timestamp>)
  --frontend-target TARGET          kubectl target for frontend (default: deployment/sourcegraph-frontend)
  --postgres-target TARGET          kubectl target for Postgres (default: pod/pgsql-0)
  --psql-command COMMAND            Command to run inside Postgres pod (default: psql -X -U sg -d sg)
  --no-logs                         Do not stream frontend logs
  -h, --help                        Show this help

Examples:
  dev/memory-efficiency-monitor-sourcegraph.sh

  dev/memory-efficiency-monitor-sourcegraph.sh \
    --duration-seconds 1800 \
    --output-dir /tmp/src-auth-perms-sync-load-$(date -u +%Y%m%d-%H%M%S)

In another terminal, run:
  uv run python dev/test-end-to-end.py --fetch-sg-traces --sample-interval 0 --external-sample-interval 0
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --namespace)
      namespace="$2"
      shift 2
      ;;
    --interval-seconds)
      interval_seconds="$2"
      shift 2
      ;;
    --postgres-interval-seconds)
      postgres_interval_seconds="$2"
      shift 2
      ;;
    --statements-interval-seconds)
      statements_interval_seconds="$2"
      shift 2
      ;;
    --duration-seconds)
      duration_seconds="$2"
      shift 2
      ;;
    --output-dir)
      output_dir="$2"
      shift 2
      ;;
    --frontend-target)
      frontend_target="$2"
      shift 2
      ;;
    --postgres-target)
      postgres_target="$2"
      shift 2
      ;;
    --psql-command)
      psql_command="$2"
      shift 2
      ;;
    --no-logs)
      stream_logs=false
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "${output_dir}" ]]; then
  output_dir="/tmp/src-auth-perms-sync-sourcegraph-load-$(date -u +%Y%m%d-%H%M%S)"
fi
mkdir -p "${output_dir}"

end_epoch=""
if [[ -n "${duration_seconds}" ]]; then
  end_epoch="$(( $(date +%s) + duration_seconds ))"
fi

pids=()

timestamp() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

should_continue() {
  [[ -z "${end_epoch}" || "$(date +%s)" -lt "${end_epoch}" ]]
}

append_header() {
  local file="$1"
  local title="$2"
  {
    printf '\n===== %s %s =====\n' "$(timestamp)" "${title}"
  } >>"${file}"
}

run_sample_loop() {
  local name="$1"
  local sleep_seconds="$2"
  local pid
  shift 2
  (
    while should_continue; do
      "$@" || true
      sleep "${sleep_seconds}"
    done
  ) &
  pid="$!"
  pids+=("${pid}")
  echo "Started ${name} sampler: pid=${pid} interval=${sleep_seconds}s"
}

run_stream() {
  local name="$1"
  local pid
  shift
  (
    "$@" || true
  ) &
  pid="$!"
  pids+=("${pid}")
  echo "Started ${name} stream: pid=${pid}"
}

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [[ ${#pids[@]} -gt 0 ]]; then
    kill "${pids[@]}" 2>/dev/null || true
    wait "${pids[@]}" 2>/dev/null || true
  fi
  echo "Stopped Sourcegraph load monitor. Output: ${output_dir}"
  exit "${status}"
}

trap cleanup EXIT INT TERM

kubectl_exec() {
  local target="$1"
  shift
  "${kubectl_bin}" exec -n "${namespace}" "${target}" -- "$@"
}

kubectl_exec_stdin() {
  local target="$1"
  shift
  "${kubectl_bin}" exec -i -n "${namespace}" "${target}" -- "$@"
}

prepare_pg_stat_statements() {
  local file="${output_dir}/postgres-statements-setup.log"
  append_header "${file}" "create pg_stat_statements extension and reset stats"
  cat <<'SQL' | kubectl_exec_stdin "${postgres_target}" sh -lc "${psql_command} -P pager=off" >>"${file}" 2>&1 || true
select current_database(), current_user;
show shared_preload_libraries;
show track_io_timing;
create extension if not exists pg_stat_statements;
select pg_stat_statements_reset();
SQL
}

sample_kubectl_top() {
  local file="${output_dir}/kubectl-top-pods-containers.log"
  append_header "${file}" "kubectl top pods --containers"
  "${kubectl_bin}" top pods -n "${namespace}" --containers >>"${file}" 2>&1 || true
}

sample_frontend_processes() {
  local file="${output_dir}/frontend-processes.log"
  append_header "${file}" "${frontend_target} process CPU/RSS"
  kubectl_exec "${frontend_target}" sh -lc '
    echo "--- top CPU ---"
    ps auxww | sort -nrk3 | head -30
    echo "--- top RSS ---"
    ps auxww | sort -nrk4 | head -30
  ' >>"${file}" 2>&1 || true
}

sample_postgres_processes() {
  local file="${output_dir}/postgres-processes.log"
  append_header "${file}" "${postgres_target} process CPU/RSS"
  kubectl_exec "${postgres_target}" sh -lc '
    echo "--- top CPU ---"
    ps auxww | sort -nrk3 | head -30
    echo "--- top RSS ---"
    ps auxww | sort -nrk4 | head -30
  ' >>"${file}" 2>&1 || true
}

sample_cgroups() {
  local file="${output_dir}/cgroups.log"
  append_header "${file}" "cgroup CPU/memory"
  for target in "${frontend_target}" "${postgres_target}"; do
    {
      echo "--- ${target} ---"
      kubectl_exec "${target}" sh -lc '
        echo "cpu.stat"
        cat /sys/fs/cgroup/cpu.stat 2>/dev/null || cat /sys/fs/cgroup/cpu/cpu.stat 2>/dev/null || true
        echo "memory.current"
        cat /sys/fs/cgroup/memory.current 2>/dev/null || cat /sys/fs/cgroup/memory/memory.usage_in_bytes 2>/dev/null || true
        echo "memory.events"
        cat /sys/fs/cgroup/memory.events 2>/dev/null || true
        echo "memory.max"
        cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory/memory.limit_in_bytes 2>/dev/null || true
      '
    } >>"${file}" 2>&1 || true
  done
}

sample_postgres_activity() {
  local file="${output_dir}/postgres-activity.log"
  append_header "${file}" "pg_stat_activity, waits, locks"
  cat <<'SQL' | kubectl_exec_stdin "${postgres_target}" sh -lc "${psql_command} -P pager=off" >>"${file}" 2>&1 || true
select
  pid,
  now() - query_start as age,
  state,
  wait_event_type,
  wait_event,
  left(query, 220) as query
from pg_stat_activity
where state <> 'idle'
order by age desc
limit 30;

select
  wait_event_type,
  wait_event,
  state,
  count(*)
from pg_stat_activity
group by 1,2,3
order by count(*) desc;

select
  locktype,
  mode,
  granted,
  count(*)
from pg_locks
group by 1,2,3
order by count(*) desc;
SQL
}

sample_pg_stat_statements() {
  local file="${output_dir}/postgres-statements.log"
  append_header "${file}" "pg_stat_statements top total_exec_time"
  cat <<'SQL' | kubectl_exec_stdin "${postgres_target}" sh -lc "${psql_command} -P pager=off" >>"${file}" 2>&1 || true
select
  calls,
  round(total_exec_time::numeric, 1) as total_ms,
  round(mean_exec_time::numeric, 1) as mean_ms,
  rows,
  left(query, 260) as query
from pg_stat_statements
order by total_exec_time desc
limit 25;
SQL
}

snapshot_pod_descriptions() {
  local file="${output_dir}/pod-descriptions.log"
  append_header "${file}" "kubectl describe selected targets"
  "${kubectl_bin}" describe -n "${namespace}" "${frontend_target}" >>"${file}" 2>&1 || true
  "${kubectl_bin}" describe -n "${namespace}" "${postgres_target}" >>"${file}" 2>&1 || true
}

stream_frontend_logs() {
  "${kubectl_bin}" logs -n "${namespace}" "${frontend_target}" --since=1m --timestamps -f \
    >"${output_dir}/frontend.log" 2>"${output_dir}/frontend-log-errors.log"
}

stream_frontend_error_logs() {
  "${kubectl_bin}" logs -n "${namespace}" "${frontend_target}" --since=1m --timestamps -f 2>/dev/null \
    | grep -Ei 'timeout|deadline|database|postgres|graphql|error|slow|cancel' \
    >"${output_dir}/frontend-errors-filtered.log" || true
}

cat >"${output_dir}/metadata.txt" <<EOF
started_at=$(timestamp)
namespace=${namespace}
frontend_target=${frontend_target}
postgres_target=${postgres_target}
interval_seconds=${interval_seconds}
postgres_interval_seconds=${postgres_interval_seconds}
statements_interval_seconds=${statements_interval_seconds}
duration_seconds=${duration_seconds}
psql_command=${psql_command}
EOF

echo "Writing Sourcegraph load monitor output to ${output_dir}"
prepare_pg_stat_statements
snapshot_pod_descriptions
run_sample_loop "kubectl-top" "${interval_seconds}" sample_kubectl_top
run_sample_loop "frontend-processes" "${interval_seconds}" sample_frontend_processes
run_sample_loop "postgres-processes" "${interval_seconds}" sample_postgres_processes
run_sample_loop "cgroups" "${interval_seconds}" sample_cgroups
run_sample_loop "postgres-activity" "${postgres_interval_seconds}" sample_postgres_activity
run_sample_loop "postgres-statements" "${statements_interval_seconds}" sample_pg_stat_statements

if [[ "${stream_logs}" == true ]]; then
  run_stream "frontend-logs" stream_frontend_logs
  run_stream "frontend-error-logs" stream_frontend_error_logs
fi

if [[ -n "${duration_seconds}" ]]; then
  while should_continue; do
    sleep 1
  done
else
  while true; do
    sleep 3600
  done
fi
