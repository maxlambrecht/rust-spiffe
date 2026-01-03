#!/usr/bin/env bash
set -euf -o pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"

# Constants
spire_version="1.14.0"
spire_folder="spire-${spire_version}"

spire_server_log_file="/tmp/spire-server/server.log"
spire_server_socket_path="/tmp/spire-server/private/api.sock"

spire_server_federated_log_file="/tmp/spire-server-federated/server.log"
spire_server_federated_socket_path="/tmp/spire-server-federated/private/api.sock"

spire_agent_log_file="/tmp/spire-agent/agent.log"
spire_agent_socket_path="/tmp/spire-agent/admin/api.sock"

spire_agent_federated_log_file="/tmp/spire-agent-federated/agent.log"
spire_agent_federated_socket_path="/tmp/spire-agent-federated/admin/api.sock"

agent_id="spiffe://example.org/myagent"
agent_federated_id="spiffe://example-federated.org/myagent"

# Helper: wait for a service to be available
wait_for_service() {
  local command="$1"
  local description="$2"
  local log_file="$3"

  for _ in {1..20}; do
    if ${command} >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done

  [ -n "${log_file}" ] && cat "${log_file}" >&2
  echo "${description} failed to start" >&2
  exit 1
}

# Helper: wait until an agent has a bundle for a trust domain
wait_for_bundle() {
  local agent_socket_path="$1"   # e.g. /tmp/spire-agent/private/api.sock
  local trust_domain="$2"        # e.g. example-federated.org

  for _ in {1..60}; do
    if bin/spire-agent bundle list -socketPath "${agent_socket_path}" 2>/dev/null | grep -q "${trust_domain}"; then
      return 0
    fi
    sleep 1
  done

  echo "Timed out waiting for bundle '${trust_domain}' in agent at '${agent_socket_path}'" >&2
  return 1
}

# SPIRE prerequisites
curl -s -N -L "https://github.com/spiffe/spire/releases/download/v${spire_version}/spire-${spire_version}-linux-amd64-musl.tar.gz" | tar xz
pushd "${spire_folder}" >/dev/null

# -------------------------------
# 1) Start federated SPIRE server
# -------------------------------
export SPIRE_FEDERATED_SOCKET_PATH="${spire_server_federated_socket_path}"
cat "${SCRIPT_DIR}/server-federated.conf" | envsubst > "conf/server/server-federated.conf"
mkdir -p /tmp/spire-server-federated

bin/spire-server run -config conf/server/server-federated.conf > "${spire_server_federated_log_file}" 2>&1 &
wait_for_service \
  "bin/spire-server healthcheck -socketPath ${spire_server_federated_socket_path}" \
  "SPIRE Federated Server" \
  "${spire_server_federated_log_file}"

# Export federated bundle to file so the primary server can ingest it
bin/spire-server bundle show \
  -socketPath "${spire_server_federated_socket_path}" \
  -format spiffe \
  > example-federated.org.bundle

# -------------------------
# 2) Start primary SPIRE server
# -------------------------
export SPIRE_SOCKET_PATH="${spire_server_socket_path}"
cat "${SCRIPT_DIR}/server.conf" | envsubst > "conf/server/server.conf"
mkdir -p /tmp/spire-server

bin/spire-server run -config conf/server/server.conf > "${spire_server_log_file}" 2>&1 &
wait_for_service \
  "bin/spire-server healthcheck -socketPath ${spire_server_socket_path}" \
  "SPIRE Server" \
  "${spire_server_log_file}"

# Ingest federated bundle into the primary server
bin/spire-server bundle set \
  -socketPath "${spire_server_socket_path}" \
  -format spiffe \
  -id spiffe://example-federated.org \
  -path example-federated.org.bundle

# -------------------------
# 3) Start primary SPIRE agent
# -------------------------
export STRIPPED_SPIRE_ADMIN_ENDPOINT_SOCKET
STRIPPED_SPIRE_ADMIN_ENDPOINT_SOCKET="$(echo "${SPIRE_ADMIN_ENDPOINT_SOCKET:-unix:///tmp/spire-server/private/api.sock}" | cut -c6-)"

cat "${SCRIPT_DIR}/agent.conf" | envsubst > "conf/agent/agent.conf"

bin/spire-server token generate \
  -socketPath "${spire_server_socket_path}" \
  -spiffeID "${agent_id}" \
  > token_primary

cut -d ' ' -f 2 token_primary > token_primary_stripped

mkdir -p /tmp/spire-agent
bin/spire-agent run -config conf/agent/agent.conf -joinToken "$(< token_primary_stripped)" > "${spire_agent_log_file}" 2>&1 &
wait_for_service \
  "bin/spire-agent healthcheck -socketPath ${spire_agent_socket_path}" \
  "SPIRE Agent" \
  "${spire_agent_log_file}"

# --------------------------------
# 4) Start federated SPIRE agent
# --------------------------------
cat "${SCRIPT_DIR}/agent-federated.conf" | envsubst > "conf/agent/agent-federated.conf"

bin/spire-server token generate \
  -socketPath "${spire_server_federated_socket_path}" \
  -spiffeID "${agent_federated_id}" \
  > token_federated

cut -d ' ' -f 2 token_federated > token_federated_stripped

mkdir -p /tmp/spire-agent-federated
bin/spire-agent run -config conf/agent/agent-federated.conf -joinToken "$(< token_federated_stripped)" > "${spire_agent_federated_log_file}" 2>&1 &
wait_for_service \
  "bin/spire-agent healthcheck -socketPath ${spire_agent_federated_socket_path}" \
  "SPIRE Federated Agent" \
  "${spire_agent_federated_log_file}"

# -------------------------
# 5) Register workloads (primary TD)
# -------------------------
uid="$(id -u)"

for service in "myservice" "myservice2"; do
  echo "Creating primary entry for '${service}'"
  bin/spire-server entry create \
    -socketPath "${spire_server_socket_path}" \
    -parentID "${agent_id}" \
    -spiffeID "spiffe://example.org/${service}" \
    -hint "${service}" \
    -dns example.org \
    -selector "unix:uid:${uid}" \
    -x509SVIDTTL 5 \
    -jwtSVIDTTL 5 \
    -federatesWith spiffe://example-federated.org
done

uid_plus_one=$((uid + 1))
echo "Creating primary entry for 'different-process' (uid=${uid_plus_one})"
bin/spire-server entry create \
  -socketPath "${spire_server_socket_path}" \
  -parentID "${agent_id}" \
  -spiffeID "spiffe://example.org/different-process" \
  -selector "unix:uid:${uid_plus_one}"

# -------------------------
# 6) Register workloads (federated TD)
# -------------------------
for service in "myservice" "myservice2"; do
  echo "Creating federated entry for '${service}'"
  bin/spire-server entry create \
    -socketPath "${spire_server_federated_socket_path}" \
    -parentID "${agent_federated_id}" \
    -spiffeID "spiffe://example-federated.org/${service}" \
    -hint "${service}" \
    -dns example.org \
    -selector "unix:uid:${uid}" \
    -x509SVIDTTL 5 \
    -jwtSVIDTTL 5
done

# -------------------------
# 7) Export Workload API sockets for tests
# -------------------------
export SPIFFE_ENDPOINT_SOCKET="unix:///tmp/spire-agent/public/api.sock"
export SPIFFE_ENDPOINT_SOCKET_FEDERATED="unix:///tmp/spire-agent-federated/public/api.sock"

# -------------------------
# 8) Wait for federation to be established (deterministic)
# -------------------------
echo "Waiting for federation bundles to appear in both agents..."
wait_for_bundle "${spire_agent_socket_path}" "example-federated.org"
wait_for_bundle "${spire_agent_federated_socket_path}" "example.org"

popd >/dev/null
echo "SPIRE primary + federated servers/agents are up. Workload API sockets exported."
