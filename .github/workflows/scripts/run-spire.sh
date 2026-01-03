#!/usr/bin/env bash
set -euo pipefail

# -------------------------
# Constants
# -------------------------
spire_version="1.14.0"
spire_folder="spire-${spire_version}"

spire_server_log_file="/tmp/spire-server/server.log"
spire_server_socket_path="/tmp/spire-server/private/api.sock"

spire_server_federated_log_file="/tmp/spire-server-federated/server.log"
spire_server_federated_socket_path="/tmp/spire-server-federated/private/api.sock"

spire_agent_log_file="/tmp/spire-agent/agent.log"
spire_agent_admin_socket_path="/tmp/spire-agent/admin/api.sock"
spire_agent_workload_socket_path="/tmp/spire-agent/public/api.sock"

spire_agent_federated_log_file="/tmp/spire-agent-federated/agent.log"
spire_agent_federated_admin_socket_path="/tmp/spire-agent-federated/admin/api.sock"
spire_agent_federated_workload_socket_path="/tmp/spire-agent-federated/public/api.sock"

agent_id="spiffe://example.org/myagent"
agent_federated_id="spiffe://example-federated.org/myagent"

# -------------------------
# Cleanup
# -------------------------
cleanup() {
  pkill -f "spire-server run" 2>/dev/null || true
  pkill -f "spire-agent run"  2>/dev/null || true

  rm -rf \
    /tmp/spire-server \
    /tmp/spire-server-federated \
    /tmp/spire-agent \
    /tmp/spire-agent-federated
}
cleanup
trap cleanup EXIT

# -------------------------
# Helpers
# -------------------------
wait_for_service() {
  local command="$1"
  local description="$2"
  local log_file="$3"
  local attempts="${4:-60}"
  local sleep_seconds="${5:-1}"

  for _ in $(seq 1 "${attempts}"); do
    if eval "${command}" >/dev/null 2>&1; then
      return 0
    fi
    sleep "${sleep_seconds}"
  done

  echo "${description} failed to become ready" >&2
  if [[ -n "${log_file}" && -f "${log_file}" ]]; then
    echo "--- ${description} log (tail) ---" >&2
    tail -n 200 "${log_file}" >&2
    echo "-------------------------------" >&2
  fi
  exit 1
}

wait_for_unix_socket() {
  local path="$1"
  local description="$2"
  local attempts="${3:-60}"

  for _ in $(seq 1 "${attempts}"); do
    if [[ -S "${path}" ]]; then
      return 0
    fi
    sleep 1
  done

  echo "Timed out waiting for unix socket: ${path} (${description})" >&2
  exit 1
}

# Workload API readiness: proves the socket exists AND the agent can serve Workload API requests
wait_for_workload_api_ready() {
  local workload_socket_path="$1"
  local description="$2"
  local log_file="$3"
  local attempts="${4:-60}"

  wait_for_unix_socket "${workload_socket_path}" "${description} workload socket" "${attempts}"

  for _ in $(seq 1 "${attempts}"); do
    if bin/spire-agent api fetch x509 -socketPath "${workload_socket_path}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done

  echo "${description} Workload API failed to become ready" >&2
  if [[ -n "${log_file}" && -f "${log_file}" ]]; then
    echo "--- ${description} log (tail) ---" >&2
    tail -n 200 "${log_file}" >&2
    echo "-------------------------------" >&2
  fi

  echo "--- ${description} fetch x509 error (unsuppressed) ---" >&2
  bin/spire-agent api fetch x509 -socketPath "${workload_socket_path}" >&2 || true
  exit 1
}

# Identity check: proves the *calling process* is mapped to an entry that yields the expected SPIFFE ID.
wait_for_expected_spiffe_id() {
  local workload_socket_path="$1"
  local expected_spiffe_id="$2"
  local description="$3"
  local attempts="${4:-60}"

  for _ in $(seq 1 "${attempts}"); do
    if bin/spire-agent api fetch x509 -socketPath "${workload_socket_path}" 2>/dev/null | grep -q "${expected_spiffe_id}"; then
      return 0
    fi
    sleep 1
  done

  echo "Timed out waiting for SPIFFE ID '${expected_spiffe_id}' via Workload API (${description})" >&2
  echo "--- ${description} fetch x509 (unsuppressed) ---" >&2
  bin/spire-agent api fetch x509 -socketPath "${workload_socket_path}" >&2 || true
  exit 1
}

# Negative identity check: proves a different UID/process does NOT get an identity for the entry selectors.
assert_no_identity_for_uid() {
  local uid="$1"
  local workload_socket_path="$2"
  local description="$3"

  if command -v sudo >/dev/null 2>&1; then
    if sudo -n -u "#${uid}" -- bin/spire-agent api fetch x509 -socketPath "${workload_socket_path}" >/dev/null 2>&1; then
      echo "Expected NO identity for uid=${uid}, but fetch x509 succeeded (${description})" >&2
      sudo -n -u "#${uid}" -- bin/spire-agent api fetch x509 -socketPath "${workload_socket_path}" >&2 || true
      exit 1
    fi
  else
    echo "sudo not available; skipping negative UID identity check (${description})" >&2
  fi
}

wait_for_federation_bundle() {
  local workload_socket_path="$1"
  local trust_domain="$2"
  local description="$3"
  local attempts="${4:-90}"

  for _ in $(seq 1 "${attempts}"); do
    if bin/spire-agent api fetch x509 -socketPath "${workload_socket_path}" 2>/dev/null | grep -q "${trust_domain}"; then
      return 0
    fi
    sleep 1
  done

  echo "Timed out waiting for bundle '${trust_domain}' via Workload API (${description})" >&2
  echo "--- ${description} fetch x509 (unsuppressed) ---" >&2
  bin/spire-agent api fetch x509 -socketPath "${workload_socket_path}" >&2 || true
  exit 1
}

download_spire() {
  local os arch tarball

  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m)"

  case "${arch}" in
    x86_64|amd64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *) echo "Unsupported arch: $(uname -m)" >&2; exit 1 ;;
  esac

  # SPIRE provides different artifacts; this keeps your current default but makes it portable.
  # If your environment is CI linux-amd64, this will match your prior behavior.
  if [[ "${os}" == "linux" && "${arch}" == "amd64" ]]; then
    tarball="spire-${spire_version}-linux-amd64-musl.tar.gz"
  else
    tarball="spire-${spire_version}-${os}-${arch}.tar.gz"
  fi

  curl -sSfL "https://github.com/spiffe/spire/releases/download/v${spire_version}/${tarball}" | tar xz
}

# -------------------------
# SPIRE prerequisites
# -------------------------
download_spire
pushd "${spire_folder}" >/dev/null

mkdir -p conf/server conf/agent

mkdir -p /tmp/spire-server/private /tmp/spire-server
mkdir -p /tmp/spire-server-federated/private /tmp/spire-server-federated
mkdir -p /tmp/spire-agent/public /tmp/spire-agent/admin /tmp/spire-agent
mkdir -p /tmp/spire-agent-federated/public /tmp/spire-agent-federated/admin /tmp/spire-agent-federated

# -------------------------
# Generate configs
# -------------------------
cat > conf/server/server-federated.conf <<'EOF'
server {
  bind_address = "127.0.0.1"
  bind_port = "8082"
  trust_domain = "example-federated.org"

  data_dir = "/tmp/spire-server-federated"
  socket_path = "/tmp/spire-server-federated/private/api.sock"

  log_level = "DEBUG"
  ca_ttl = "168h"
  default_x509_svid_ttl = "48h"

  federation {
    bundle_endpoint {
      address = "127.0.0.1"
      port = 8443
      profile "https_spiffe" {}
    }
  }
}

plugins {
  DataStore "sql" {
    plugin_data {
      database_type = "sqlite3"
      connection_string = "/tmp/spire-server-federated/datastore.sqlite3"
    }
  }

  KeyManager "disk" {
    plugin_data {
      keys_path = "/tmp/spire-server-federated/keys.json"
    }
  }

  NodeAttestor "join_token" {
    plugin_data {}
  }
}
EOF

cat > conf/server/server.conf <<'EOF'
server {
  bind_address = "127.0.0.1"
  bind_port = "8081"
  trust_domain = "example.org"

  data_dir = "/tmp/spire-server"
  socket_path = "/tmp/spire-server/private/api.sock"

  log_level = "DEBUG"
  ca_ttl = "168h"
  default_x509_svid_ttl = "48h"

  federation {
    federates_with "example-federated.org" {
      bundle_endpoint_url = "https://127.0.0.1:8443"
      bundle_endpoint_profile "https_spiffe" {
        endpoint_spiffe_id = "spiffe://example-federated.org/spire/server"
      }
    }
  }
}

plugins {
  DataStore "sql" {
    plugin_data {
      database_type = "sqlite3"
      connection_string = "/tmp/spire-server/datastore.sqlite3"
    }
  }

  KeyManager "disk" {
    plugin_data {
      keys_path = "/tmp/spire-server/keys.json"
    }
  }

  NodeAttestor "join_token" {
    plugin_data {}
  }
}
EOF

cat > conf/agent/agent.conf <<'EOF'
agent {
  trust_domain = "example.org"
  log_level = "DEBUG"

  server_address = "127.0.0.1"
  server_port = 8081

  socket_path = "/tmp/spire-agent/public/api.sock"
  admin_socket_path = "/tmp/spire-agent/admin/api.sock"

  data_dir = "/tmp/spire-agent/data"

  insecure_bootstrap = true

  authorized_delegates = [
    "spiffe://example.org/myservice",
  ]
}

plugins {
  KeyManager "disk" {
    plugin_data {
      directory = "/tmp/spire-agent/keys"
    }
  }

  NodeAttestor "join_token" {
    plugin_data {}
  }

  WorkloadAttestor "unix" {
    plugin_data {}
  }
}
EOF

cat > conf/agent/agent-federated.conf <<'EOF'
agent {
  trust_domain = "example-federated.org"
  log_level = "DEBUG"

  server_address = "127.0.0.1"
  server_port = 8082

  socket_path = "/tmp/spire-agent-federated/public/api.sock"
  admin_socket_path = "/tmp/spire-agent-federated/admin/api.sock"

  data_dir = "/tmp/spire-agent-federated/data"

  insecure_bootstrap = true
}

plugins {
  KeyManager "disk" {
    plugin_data {
      directory = "/tmp/spire-agent-federated/keys"
    }
  }

  NodeAttestor "join_token" {
    plugin_data {}
  }

  WorkloadAttestor "unix" {
    plugin_data {}
  }
}
EOF

# -------------------------------
# 1) Start federated SPIRE server
# -------------------------------
echo "Starting Federated SPIRE Server"
bin/spire-server run -config conf/server/server-federated.conf > "${spire_server_federated_log_file}" 2>&1 &
wait_for_service \
  "bin/spire-server healthcheck -socketPath ${spire_server_federated_socket_path}" \
  "SPIRE Federated Server" \
  "${spire_server_federated_log_file}"

bin/spire-server bundle show \
  -socketPath "${spire_server_federated_socket_path}" \
  -format spiffe \
  > example-federated.org.bundle

# -------------------------------
# 2) Start primary SPIRE server
# -------------------------------
echo "Starting Primary SPIRE Server"
bin/spire-server run -config conf/server/server.conf > "${spire_server_log_file}" 2>&1 &
wait_for_service \
  "bin/spire-server healthcheck -socketPath ${spire_server_socket_path}" \
  "SPIRE Server" \
  "${spire_server_log_file}"

bin/spire-server bundle set \
  -socketPath "${spire_server_socket_path}" \
  -format spiffe \
  -id spiffe://example-federated.org \
  -path example-federated.org.bundle

# -------------------------------
# 3) Start primary SPIRE agent
# -------------------------------
bin/spire-server token generate \
  -socketPath "${spire_server_socket_path}" \
  -spiffeID "${agent_id}" \
  > token_primary
awk '{print $2}' token_primary > token_primary_stripped

echo "Starting primary SPIRE Agent"
bin/spire-agent run -config conf/agent/agent.conf -joinToken "$(< token_primary_stripped)" > "${spire_agent_log_file}" 2>&1 &

# Agent admin healthcheck proves the *agent process* is serving.
wait_for_service \
  "bin/spire-agent healthcheck -socketPath ${spire_agent_admin_socket_path}" \
  "SPIRE Agent (admin)" \
  "${spire_agent_log_file}"

# Workload API readiness proves the Workload API socket is live and responsive.
wait_for_workload_api_ready \
  "${spire_agent_workload_socket_path}" \
  "SPIRE Agent (workload)" \
  "${spire_agent_log_file}"

# -------------------------------
# 4) Start federated SPIRE agent
# -------------------------------
bin/spire-server token generate \
  -socketPath "${spire_server_federated_socket_path}" \
  -spiffeID "${agent_federated_id}" \
  > token_federated
awk '{print $2}' token_federated > token_federated_stripped

echo "Starting federated SPIRE Agent"
bin/spire-agent run -config conf/agent/agent-federated.conf -joinToken "$(< token_federated_stripped)" > "${spire_agent_federated_log_file}" 2>&1 &

wait_for_service \
  "bin/spire-agent healthcheck -socketPath ${spire_agent_federated_admin_socket_path}" \
  "SPIRE Federated Agent (admin)" \
  "${spire_agent_federated_log_file}"

wait_for_workload_api_ready \
  "${spire_agent_federated_workload_socket_path}" \
  "SPIRE Federated Agent (workload)" \
  "${spire_agent_federated_log_file}"

# -------------------------------
# 5) Register workloads (primary TD)
# -------------------------------
uid="$(id -u)"
gid="$(id -g)"

for service in "myservice" "myservice2"; do
  echo "Creating primary entry for '${service}'"
  bin/spire-server entry create \
    -socketPath "${spire_server_socket_path}" \
    -parentID "${agent_id}" \
    -spiffeID "spiffe://example.org/${service}" \
    -hint "${service}" \
    -dns example.org \
    -selector "unix:uid:${uid}" \
    -selector "unix:gid:${gid}" \
    -x509SVIDTTL 300 \
    -jwtSVIDTTL 300 \
    -federatesWith spiffe://example-federated.org
done

uid_plus_one=$((uid + 1))
echo "Creating primary entry for 'different-process' (uid=${uid_plus_one})"
bin/spire-server entry create \
  -socketPath "${spire_server_socket_path}" \
  -parentID "${agent_id}" \
  -spiffeID "spiffe://example.org/different-process" \
  -selector "unix:uid:${uid_plus_one}"

# -------------------------------
# 6) Register workloads (federated TD)
# -------------------------------
for service in "myservice" "myservice2"; do
  echo "Creating federated entry for '${service}'"
  bin/spire-server entry create \
    -socketPath "${spire_server_federated_socket_path}" \
    -parentID "${agent_federated_id}" \
    -spiffeID "spiffe://example-federated.org/${service}" \
    -hint "${service}" \
    -dns example.org \
    -selector "unix:uid:${uid}" \
    -selector "unix:gid:${gid}" \
    -x509SVIDTTL 300 \
    -jwtSVIDTTL 300
done

# -------------------------------
# 7) Verify correct caller identity via Workload API
# -------------------------------
# This proves the calling process (this script's uid/gid) is mapped to the intended entries.
echo "Verifying caller process receives expected identities via Workload API..."
wait_for_expected_spiffe_id "${spire_agent_workload_socket_path}" "spiffe://example.org/myservice"  "Primary agent"
wait_for_expected_spiffe_id "${spire_agent_workload_socket_path}" "spiffe://example.org/myservice2" "Primary agent"

wait_for_expected_spiffe_id "${spire_agent_federated_workload_socket_path}" "spiffe://example-federated.org/myservice"  "Federated agent"
wait_for_expected_spiffe_id "${spire_agent_federated_workload_socket_path}" "spiffe://example-federated.org/myservice2" "Federated agent"

# Negative check: a different uid should not be able to fetch an identity for the (uid,gid) selectors above.
echo "Verifying a different uid does NOT receive identities (best-effort; requires passwordless sudo)..."
assert_no_identity_for_uid "${uid_plus_one}" "${spire_agent_workload_socket_path}" "Primary agent"

# -------------------------------
# 8) Export Workload API sockets for tests
# -------------------------------
export SPIFFE_ENDPOINT_SOCKET="unix://${spire_agent_workload_socket_path}"
export SPIFFE_ENDPOINT_SOCKET_FEDERATED="unix://${spire_agent_federated_workload_socket_path}"

# -------------------------------
# 9) Wait for federation to be established (bundle presence)
# -------------------------------
echo "Waiting for federation bundles to appear in both agents..."
wait_for_federation_bundle "${spire_agent_workload_socket_path}" "example-federated.org" "Primary agent"
wait_for_federation_bundle "${spire_agent_federated_workload_socket_path}" "example.org" "Federated agent"

popd >/dev/null
echo "SPIRE primary + federated servers/agents are up."
echo "Exported:"
echo "  SPIFFE_ENDPOINT_SOCKET=${SPIFFE_ENDPOINT_SOCKET}"
echo "  SPIFFE_ENDPOINT_SOCKET_FEDERATED=${SPIFFE_ENDPOINT_SOCKET_FEDERATED}"
