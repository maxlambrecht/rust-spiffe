#!/usr/bin/env bash
set -euf -o pipefail

# Constants
spire_version="1.14.0"
spire_folder="spire-${spire_version}"

spire_server_log_file="/tmp/spire-server/server.log"
spire_server_socket_path="/tmp/spire-server/private/api.sock"

spire_server_federated_log_file="/tmp/spire-server-federated/server.log"
spire_server_federated_socket_path="/tmp/spire-server-federated/private/api.sock"

spire_agent_log_file="/tmp/spire-agent/agent.log"
spire_agent_admin_socket_path="/tmp/spire-agent/admin/api.sock"

spire_agent_federated_log_file="/tmp/spire-agent-federated/agent.log"
spire_agent_federated_admin_socket_path="/tmp/spire-agent-federated/admin/api.sock"

agent_id="spiffe://example.org/myagent"
agent_federated_id="spiffe://example-federated.org/myagent"

pkill -f "spire-server run" 2>/dev/null || true
pkill -f "spire-agent run"  2>/dev/null || true

rm -rf \
  /tmp/spire-server \
  /tmp/spire-server-federated \
  /tmp/spire-agent \
  /tmp/spire-agent-federated


wait_for_service() {
  local command="$1"
  local description="$2"
  local log_file="$3"

  for _ in {1..60}; do
    if ${command} >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done

  echo "${description} failed to start" >&2
  if [ -n "${log_file}" ] && [ -f "${log_file}" ]; then
    echo "--- ${description} log ---" >&2
    tail -n 200 "${log_file}" >&2
    echo "-------------------------" >&2
  fi

  if [[ "${description}" == "SPIRE Agent" ]]; then
    echo "--- spire-agent healthcheck (verbose) ---" >&2
    bin/spire-agent healthcheck -socketPath /tmp/spire-agent/admin/api.sock -verbose >&2 || true
  elif [[ "${description}" == "SPIRE Federated Agent" ]]; then
    echo "--- spire-agent healthcheck (verbose) ---" >&2
    bin/spire-agent healthcheck -socketPath /tmp/spire-agent-federated/admin/api.sock -verbose >&2 || true
  fi

  exit 1
}

wait_for_bundle() {
  local agent_admin_socket_path="$1"
  local trust_domain="$2"

  for _ in {1..90}; do
    if bin/spire-agent bundle list -socketPath "${agent_admin_socket_path}" 2>/dev/null | grep -q "${trust_domain}"; then
      return 0
    fi
    sleep 1
  done

  echo "Timed out waiting for bundle '${trust_domain}' in agent at '${agent_admin_socket_path}'" >&2
  return 1
}

# SPIRE prerequisites
curl -s -N -L "https://github.com/spiffe/spire/releases/download/v${spire_version}/spire-${spire_version}-linux-amd64-musl.tar.gz" | tar xz
pushd "${spire_folder}" >/dev/null

# Ensure directories exist (some distros don't ship conf/*)
mkdir -p conf/server conf/agent

# Ensure runtime directories exist
mkdir -p /tmp/spire-server/private /tmp/spire-server
mkdir -p /tmp/spire-server-federated/private /tmp/spire-server-federated
mkdir -p /tmp/spire-agent/public /tmp/spire-agent/admin /tmp/spire-agent
mkdir -p /tmp/spire-agent-federated/public /tmp/spire-agent-federated/admin /tmp/spire-agent-federated

# -------------------------------------------------------------------
# Generate configs
# -------------------------------------------------------------------

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

# Export federated bundle to file so the primary server can ingest it
bin/spire-server bundle show \
  -socketPath "${spire_server_federated_socket_path}" \
  -format spiffe \
  > example-federated.org.bundle

# -------------------------
# 2) Start primary SPIRE server
# -------------------------
echo "Starting Primary SPIRE Server"
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
bin/spire-server token generate \
  -socketPath "${spire_server_socket_path}" \
  -spiffeID "${agent_id}" \
  > token_primary
cut -d ' ' -f 2 token_primary > token_primary_stripped

echo "Starting primary SPIRE Agent"
bin/spire-agent run -config conf/agent/agent.conf -joinToken "$(< token_primary_stripped)" > "${spire_agent_log_file}" 2>&1 &
wait_for_service \
  "bin/spire-agent healthcheck -socketPath ${spire_agent_admin_socket_path}" \
  "SPIRE Agent" \
  "${spire_agent_log_file}"

# --------------------------------
# 4) Start federated SPIRE agent
# --------------------------------
bin/spire-server token generate \
  -socketPath "${spire_server_federated_socket_path}" \
  -spiffeID "${agent_federated_id}" \
  > token_federated
cut -d ' ' -f 2 token_federated > token_federated_stripped

echo "Starting federated SPIRE Agent"
bin/spire-agent run -config conf/agent/agent-federated.conf -joinToken "$(< token_federated_stripped)" > "${spire_agent_federated_log_file}" 2>&1 &
wait_for_service \
  "bin/spire-agent healthcheck -socketPath ${spire_agent_federated_admin_socket_path}" \
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
    -x509SVIDTTL 300 \
    -jwtSVIDTTL 300
done

# -------------------------
# 7) Export Workload API sockets for tests
# -------------------------
export SPIFFE_ENDPOINT_SOCKET="unix:///tmp/spire-agent/public/api.sock"
export SPIFFE_ENDPOINT_SOCKET_FEDERATED="unix:///tmp/spire-agent-federated/public/api.sock"

# -------------------------
# 8) Wait for federation to be established
# -------------------------
echo "Waiting for federation bundles to appear in both agents..."
wait_for_bundle "${spire_agent_admin_socket_path}" "example-federated.org"
wait_for_bundle "${spire_agent_federated_admin_socket_path}" "example.org"

popd >/dev/null
echo "SPIRE primary + federated servers/agents are up. Workload API sockets exported."
