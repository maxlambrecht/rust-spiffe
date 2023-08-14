#!/usr/bin/env bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

# Constants
spire_version="1.7.1"
spire_folder="spire-${spire_version}"
spire_server_log_file="/tmp/spire-server/server.log"
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

# Install and run a SPIRE server
curl -s -N -L https://github.com/spiffe/spire/releases/download/v${spire_version}/spire-${spire_version}-linux-amd64-glibc.tar.gz | tar xz
pushd "${spire_folder}"
mkdir -p /tmp/spire-server
bin/spire-server run -config conf/server/server.conf > "${spire_server_log_file}" 2>&1 &
wait_for_service "bin/spire-server healthcheck" "SPIRE Server" "${spire_server_log_file}"

export STRIPPED_SPIFFE_ADMIN_ENDPOINT_SOCKET=$(echo $SPIFFE_ADMIN_ENDPOINT_SOCKET| cut -c6-)
cat $SCRIPT_DIR/agent.conf | envsubst > "conf/agent/agent.conf"

# Run the SPIRE agent with the joint token
bin/spire-server token generate -spiffeID ${agent_id} > token
cut -d ' ' -f 2 token > token_stripped
mkdir -p /tmp/spire-agent
bin/spire-agent run -config conf/agent/agent.conf -joinToken "$(< token_stripped)" > "${spire_agent_log_file}" 2>&1 &
wait_for_service "bin/spire-agent healthcheck" "SPIRE Agent" "${spire_agent_log_file}"

# Register workloads
for service in "myservice" "myservice2"; do
  bin/spire-server entry create -parentID ${agent_id} -spiffeID spiffe://example.org/${service} -selector unix:uid:$(id -u) -ttl 5
  sleep 10  # Derived from the default Agent sync interval
done


uid=$(id -u)
# The UID in the test has to match this, so take the current UID and add 1
uid_plus_one=$((uid + 1))
# Register a different UID with the SPIFFE ID "spiffe://example.org/different-process" with a TTL of 5 seconds
bin/spire-server entry create -parentID ${agent_id} -spiffeID spiffe://example.org/different-process -selector unix:uid:${uid_plus_one} -ttl 5
sleep 10


popd
