#!/usr/bin/env bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

# Constants
spire_version="1.14.0"
spire_folder="spire-${spire_version}"
spire_server_log_file="/tmp/spire-server/server.log"
spire_server_socket_path="/tmp/spire-server/private/api.sock"
spire_server_federated_log_file="/tmp/spire-server-federated/server.log"
spire_server_federated_socket_path="/tmp/spire-server-federated/private/api.sock"
spire_agent_log_file="/tmp/spire-agent/agent.log"
agent_id="spiffe://example.org/myagent"

# Helper function to wait for a service to be available
function wait_for_service() {
  local command="$1"
  local description="$2"
  local log_file="$3"

  for i in {1..10}; do
    if ${command} >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done

  [ -n "${log_file}" ] && cat ${log_file} >&2
  echo "${description} failed to start" >&2
  exit 1
}

# Main script starts here
set -euf -o pipefail

# SPIRE server pre-requisites
curl -s -N -L https://github.com/spiffe/spire/releases/download/v${spire_version}/spire-${spire_version}-linux-amd64-musl.tar.gz | tar xz
pushd "${spire_folder}"

# Install and run a SPIRE server for federation
export SPIRE_FEDERATED_SOCKET_PATH=${spire_server_federated_socket_path}
cat $SCRIPT_DIR/server-federated.conf | envsubst > "conf/server/server-federated.conf"
mkdir -p /tmp/spire-server-federated
bin/spire-server run -config conf/server/server-federated.conf > "${spire_server_federated_log_file}" 2>&1 &
wait_for_service "bin/spire-server healthcheck -socketPath ${spire_server_federated_socket_path}" "SPIRE Federated Server" "${spire_server_federated_log_file}"
bin/spire-server bundle show -socketPath ${spire_server_federated_socket_path} -format spiffe > example-federated.org.bundle

# Install and run a SPIRE server
export SPIRE_SOCKET_PATH=${spire_server_socket_path}
cat $SCRIPT_DIR/server.conf | envsubst > "conf/server/server.conf"
mkdir -p /tmp/spire-server
bin/spire-server run -config conf/server/server.conf > "${spire_server_log_file}" 2>&1 &
wait_for_service "bin/spire-server healthcheck" "SPIRE Server" "${spire_server_log_file}"
bin/spire-server bundle set -format spiffe -id spiffe://example-federated.org -path example-federated.org.bundle

# Run the SPIRE agent with the join token
export STRIPPED_SPIRE_ADMIN_ENDPOINT_SOCKET=$(echo $SPIRE_ADMIN_ENDPOINT_SOCKET| cut -c6-)
cat $SCRIPT_DIR/agent.conf | envsubst > "conf/agent/agent.conf"
bin/spire-server token generate -spiffeID ${agent_id} > token
cut -d ' ' -f 2 token > token_stripped
mkdir -p /tmp/spire-agent
bin/spire-agent run -config conf/agent/agent.conf -joinToken "$(< token_stripped)" > "${spire_agent_log_file}" 2>&1 &
wait_for_service "bin/spire-agent healthcheck" "SPIRE Agent" "${spire_agent_log_file}"

# Register workloads
for service in "myservice" "myservice2"; do
  echo "Creating entry for '${service}'"
  bin/spire-server entry create -parentID ${agent_id} -spiffeID spiffe://example.org/${service} -dns example.org -selector unix:uid:$(id -u) -x509SVIDTTL 5 -jwtSVIDTTL 5 -federatesWith spiffe://example-federated.org
done

uid=$(id -u)
# The UID in the test has to match this, so take the current UID and add 1
uid_plus_one=$((uid + 1))
echo "Creating entry for 'different-service'"
bin/spire-server entry create -parentID ${agent_id} -spiffeID spiffe://example.org/different-process -selector unix:uid:${uid_plus_one}

# Allow federation to be established
echo "Sleeping 60s to allow federation to be established"
sleep 60

popd