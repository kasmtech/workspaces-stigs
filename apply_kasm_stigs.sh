#!/bin/bash
set -e

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi
PRI_INTERFACE=$(ip route | grep -m 1 'default via' | grep -Po '(?<=dev )\S+')
PRI_IP=$(ip -f inet addr show "$PRI_INTERFACE" | grep -Po '(?<=inet )(\d{1,3}\.)+\d{1,3}')
RESTART_CONTAINERS="false"
CON_RED='\033[0;31m'
CON_GREEN='\033[0;32m'
CON_ORANGE='\033[0;33m'
CON_NC='\033[0m' # No Color

# Pretty logging
log_succes() {
    printf "$1, ${CON_GREEN}PASS${CON_NC}, $2\n"
}

log_failure() {
    printf "$1, ${CON_RED}FAIL${CON_NC}, $2\n"
}

log_na() {
    printf "$1, ${CON_ORANGE}N/A${CON_NC}, $2\n"
}

log_manual() {
    printf "$1, ${CON_ORANGE}MANUAL${CON_NC}, $2\n"
}

# IP check
read -p "Please verify that $PRI_IP is the IP address that docker should bind to (y/n)? " choice
    case "$choice" in
      y|Y )
        ;;
      n|N )
        echo "Cannot continue, manually set the PRI_INTERFACE and PRI_IP variables in the script as desired."
        exit 1
        ;;
      * )
        echo "Invalid Response"
        echo "Installation cannot continue"
        exit 1
        ;;
    esac

# Set cpu and memory limitations for service containers V-235807, V-235806
if ! /opt/kasm/bin/utils/yq_$(uname -m) -e '.services[].deploy.resources.limits' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1; then
  /opt/kasm/bin/utils/yq_$(uname -m) -i '.services.[] += {"deploy": {"resources": {"limits": {"cpus": "4", "memory": "2G"}}}}' /opt/kasm/current/docker/docker-compose.yaml
  RESTART_CONTAINERS="true"
  log_succes "V-235807,V-235806" "CPU and memory limits have been set"
else
  log_succes "V-235807,V-235806" "CPU and memory limits have been set"
fi

# Set restart policy for service containers V-235843
if /opt/kasm/bin/utils/yq_$(uname -m) -e '.services[].restart' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1; then
  /opt/kasm/bin/utils/yq_$(uname -m) -i 'del(.services[].restart) | .services.[] *= {"deploy": {"restart_policy": {"condition": "on-failure", "delay": "5s", "max_attempts": 5, "window": "20s" }}}' /opt/kasm/current/docker/docker-compose.yaml
  RESTART_CONTAINERS="true"
  log_succes "V-235843" "restart limits have been set on containers"
else
  log_succes "V-235843" "restart limits have been set on containers"
fi

# Set no new privilages for all containers V-235816
if ! /opt/kasm/bin/utils/yq_$(uname -m) -e '.services[].security_opt' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1; then
  /opt/kasm/bin/utils/yq_$(uname -m) -i '.services.[] *= {"security_opt": ["no-new-privileges"]}' /opt/kasm/current/docker/docker-compose.yaml
  RESTART_CONTAINERS="true"
  log_succes "V-235816" "security-opt no-new-privileges has been set for all containers"
else
  log_succes "V-235816" "security-opt no-new-privileges has been set for all containers"
fi

# Set pid limits for all containers V-235828
if ! /opt/kasm/bin/utils/yq_$(uname -m) -e '.services[].pids_limit' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1; then
  /opt/kasm/bin/utils/yq_$(uname -m) -i '.services.[] += {"pids_limit": 100}' /opt/kasm/current/docker/docker-compose.yaml
  RESTART_CONTAINERS="true"
  log_succes "V-235828" "pid limit set for all containers"
else
  log_succes "V-235828" "pid limit set for all containers"
fi

# Setup docker daemon to use TCP and modify agent V-235818
if [ ! -d "/opt/kasm/current/certs/docker" ] && /opt/kasm/bin/utils/yq_$(uname -m) -e '.services.kasm_agent' /opt/kasm/current/docker/docker-compose.yaml > /dev/null; then
  # Cert management
  mkdir /tmp/certs
  cd /tmp/certs
  SUBJECT="/C=US/ST=VA/L=City/O=Kasm/OU=Kasm Server/CN=$(hostname)"
  openssl genrsa -out ca-key.pem 4096
  openssl req -new -x509 -days 3650 -key ca-key.pem -out ca.pem -subj "$SUBJECT"
  openssl req -new -nodes -out server.csr -keyout server-key.pem -subj "$SUBJECT"
  openssl req -subj "/CN=$(hostname)" -new -key server-key.pem -out server.csr
  echo subjectAltName = DNS:$(hostname),IP:${PRI_IP} >> extfile.cnf
  echo extendedKeyUsage = serverAuth >> extfile.cnf
  openssl x509 -req -days 3650 -in server.csr -CA ca.pem -CAkey ca-key.pem   -CAcreateserial -out server-cert.pem -extfile extfile.cnf
  openssl genrsa -out key.pem 4096
  openssl req -subj '/CN=client' -new -key key.pem -out client.csr
  echo extendedKeyUsage = clientAuth > extfile-client.cnf
  openssl x509 -req -days 365 -in client.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out cert.pem -extfile extfile-client.cnf
  rm -v client.csr server.csr extfile.cnf extfile-client.cnf
  chmod -v 0400 ca-key.pem key.pem server-key.pem
  chmod -v 0444 ca.pem server-cert.pem cert.pem
  mkdir -p /etc/docker/certs
  cp ca.pem /etc/docker/certs/
  cp server-cert.pem /etc/docker/certs/
  cp server-key.pem /etc/docker/certs/
  mkdir -p /opt/kasm/current/certs/docker/
  cp cert.pem /opt/kasm/current/certs/docker/
  cp key.pem /opt/kasm/current/certs/docker/
  cp ca.pem /opt/kasm/current/certs/docker/
  cd -
  rm -Rf /tmp/certs
  # Docker modifications
  cat <<< $(jq '. *= { "hosts": ["tcp://'${PRI_IP}':2375", "unix:///var/run/docker.sock"], "tlscacert": "/etc/docker/certs/ca.pem", "tlscert": "/etc/docker/certs/server-cert.pem", "tlskey": "/etc/docker/certs/server-key.pem", "tlsverify": true }' /etc/docker/daemon.json) > /etc/docker/daemon.json
  mkdir -p /etc/systemd/system/docker.service.d/
  cat >/etc/systemd/system/docker.service.d/override.conf <<EOL
[Service]
ExecStart=
ExecStart=/usr/bin/dockerd --containerd=/run/containerd/containerd.sock
EOL
  systemctl daemon-reload
  systemctl restart docker
  # Agent modifications
  /opt/kasm/bin/utils/yq_$(uname -m) -i 'del(.services.kasm_agent.volumes[1])| .services.kasm_agent *= { "environment": {"DOCKER_HOST": "tcp://'${PRI_IP}':2375", "DOCKER_CERT_PATH": "/opt/kasm/current/certs/docker"}}' /opt/kasm/1.11.0/docker/docker-compose.yaml
  RESTART_CONTAINERS="true"
  # Done
  log_succes "V-235818" "this host and agent are configured to use docker over tcp with TLS auth"
else
  log_succes "V-235818" "this host and agent are configured to use docker over tcp with TLS auth"
fi
if ! /opt/kasm/bin/utils/yq_$(uname -m) -e '.services.kasm_agent' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1; then
  log_succes "V-235818" "this host does not have an agent on it"
fi

if /opt/kasm/bin/utils/yq_$(uname -m) -e '.services.kasm_agent' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1; then
  DOCKER_SSL_CERT=/etc/docker/certs/server-cert.pem
  DOCKER_SSL_KEY=/etc/docker/certs/server-key.pem
  DOCKER_SSL_CA=/etc/docker/certs/ca.pem
  if [ -f "$DOCKER_SSL_CERT" ] ; then
    chown root:root $DOCKER_SSL_CERT
    log_succes "V-235861" "$DOCKER_SSL_CERT owned by root:root"
  else
    log_na "V-235861" "SSL cert does not exist"
  fi
  if [ -f "$DOCKER_SSL_KEY" ] ; then
    chmod 400 $DOCKER_SSL_KEY
    log_succes "V-235864" "$DOCKER_SSL_KEY permissions set to 0400"
  else
    log_na "V-235864" "SSL key does not exist"
  fi

  if [ -f "$DOCKER_SSL_CA" ] ; then
    chown root:root $DOCKER_SSL_CA
    log_succes "V-235861" "$DOCKER_SSL_CA owned by root:root"
  else
    log_na "V-235861" "SSL cert does not exist"
  fi
fi

# Force user mode on all containers V-235830
#USEROUT=$(/opt/kasm/bin/utils/yq_$(uname -m) '.services[].user' /opt/kasm/current/docker/docker-compose.yaml)
#KUID=$(id -u kasm)
#if [[ ! "${USEROUT}" == *"${KUID}"* ]]; then
#  /opt/kasm/bin/utils/yq_$(uname -m) -i '.services[].user = "'${KUID}'"' /opt/kasm/current/docker/docker-compose.yaml
#  /opt/kasm/bin/stop
#  /opt/kasm/bin/start
#  echo "V-235830 Containers are now running as the kasm user"
#else
#  echo "V-235830 Containers are running as the kasm user"
#fi

# RO containers V-235808

# Agent changes
if /opt/kasm/bin/utils/yq_$(uname -m) -e '.services.kasm_agent' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1 && [ ! -d "/opt/kasm/current/tmp/kasm_agent" ]; then
  mkdir -p /opt/kasm/current/tmp/kasm_agent
  chown -R kasm:kasm /opt/kasm/current/tmp/
  /opt/kasm/bin/utils/yq_$(uname -m) -i '.services.kasm_agent.volumes += "/opt/kasm/current/tmp/kasm_agent:/tmp" | .services.kasm_agent += {"read_only": true}' /opt/kasm/current/docker/docker-compose.yaml
  RESTART_CONTAINERS="true"
  log_succes "V-235808" "kasm_agent is read only"
else
  log_succes "V-235808" "kasm_agent is read only"
fi

# Proxy changes
if /opt/kasm/bin/utils/yq_$(uname -m) -e '.services.proxy' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1 && [ ! -d "/opt/kasm/current/cache/nginx" ]; then
  mkdir -p /opt/kasm/current/cache/nginx
  chown -R kasm:kasm /opt/kasm/current/cache
  /opt/kasm/bin/utils/yq_$(uname -m) -i '.services.proxy.volumes += "/opt/kasm/current/cache/nginx:/var/cache/nginx" | .services.proxy += {"read_only": true} | .services.proxy += {"tmpfs": ["/var/run"]}' /opt/kasm/current/docker/docker-compose.yaml
  RESTART_CONTAINERS="true"
  log_succes "V-235808" "proxy is read only"
else
  log_succes "V-235808" "proxy is read only"
fi

# API changes
if /opt/kasm/bin/utils/yq_$(uname -m) -e '.services.kasm_api' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1 && [ ! -d "/opt/kasm/current/tmp/kasm_api" ]; then
  mkdir -p /opt/kasm/current/tmp/kasm_api
  chown -R kasm:kasm /opt/kasm/current/tmp
  /opt/kasm/bin/utils/yq_$(uname -m) -i '.services.kasm_api.volumes += "/opt/kasm/current/tmp/kasm_api:/tmp" | .services.kasm_api += {"read_only": true}' /opt/kasm/current/docker/docker-compose.yaml
  RESTART_CONTAINERS="true"
  log_succes "V-235808" "kasm_api is read only"
else
  log_succes "V-235808" "kasm_api is read only"
fi

# Manager Changes
if /opt/kasm/bin/utils/yq_$(uname -m) -e '.services.kasm_manager' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1 && [ ! -d "/opt/kasm/current/tmp/kasm_manager" ]; then
  mkdir -p /opt/kasm/current/tmp/kasm_manager
  chown -R kasm:kasm /opt/kasm/current/tmp
  /opt/kasm/bin/utils/yq_$(uname -m) -i '.services.kasm_manager.volumes += "/opt/kasm/current/tmp/kasm_manager:/tmp" | .services.kasm_manager += {"read_only": true}' /opt/kasm/current/docker/docker-compose.yaml
  RESTART_CONTAINERS="true"
  log_succes "V-235808" "kasm_manager is read only"
else
  log_succes "V-235808" "kasm_manager is read only"
fi

# Share changes
if /opt/kasm/bin/utils/yq_$(uname -m) -e '.services.kasm_share' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1 && [ ! -d "/opt/kasm/current/tmp/kasm_share" ]; then
  mkdir -p /opt/kasm/current/tmp/kasm_share
  chown -R kasm:kasm /opt/kasm/current/tmp
  /opt/kasm/bin/utils/yq_$(uname -m) -i '.services.kasm_share.volumes += "/opt/kasm/current/tmp/kasm_share:/tmp" | .services.kasm_share += {"read_only": true}' /opt/kasm/current/docker/docker-compose.yaml
  RESTART_CONTAINERS="true"
  log_succes "V-235808" "kasm_share is read only"
else
  log_succes "V-235808" "kasm_share is read only"
fi

# agent health check
if /opt/kasm/bin/utils/yq_$(uname -m) -e '.services.kasm_agent' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1 ; then
    if ! (/opt/kasm/bin/utils/yq_$(uname -m) -e '.services.kasm_agent' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1 | grep --quiet healthcheck) ; then
    /opt/kasm/bin/utils/yq_$(uname -m) -i '.services.kasm_agent += {"healthcheck": { "test": "timeout 5 bash -c '\''</dev/tcp/localhost/4444 || exit 1'\'' || exit 1", "timeout": "2s", "retries": 5 }}' /opt/kasm/current/docker/docker-compose.yaml
    RESTART_CONTAINERS="true"
    echo 'APPLIED HEATH CHECK agent'
    fi
fi

# share health check
if /opt/kasm/bin/utils/yq_$(uname -m) -e '.services.kasm_share' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1 ; then
    if ! (/opt/kasm/bin/utils/yq_$(uname -m) -e '.services.kasm_share' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1 | grep --quiet healthcheck) ; then
    /opt/kasm/bin/utils/yq_$(uname -m) -i '.services.kasm_share += {"healthcheck": { "test": "timeout 5 bash -c '\''</dev/tcp/localhost/8182 || exit 1'\'' || exit 1", "timeout": "2s", "retries": 5 }}' /opt/kasm/current/docker/docker-compose.yaml
    RESTART_CONTAINERS="true"
    echo 'APPLIED HEATH CHECK share'
    fi
fi

# proxy health check
if /opt/kasm/bin/utils/yq_$(uname -m) -e '.services.proxy' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1 ; then
    if ! (/opt/kasm/bin/utils/yq_$(uname -m) -e '.services.proxy' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1 | grep --quiet healthcheck) ; then
    /opt/kasm/bin/utils/yq_$(uname -m) -i '.services.proxy += {"healthcheck": { "test": "nginx -t", "timeout": "2s", "retries": 5 }}' /opt/kasm/current/docker/docker-compose.yaml
    RESTART_CONTAINERS="true"
    echo 'APPLIED HEATH CHECK proxy'
    fi
fi

if docker ps | grep -viP --quiet '(\(health|CONTAINER ID)' ; then
  log_failure 'V-235827' 'Containers found without health checks'
else
  log_succes 'V-235827' 'All running containers have health checks'
fi

#### Restart containers if flagged ####
if [ "${RESTART_CONTAINERS}" == "true" ]; then
  echo "Restaring containers with new compose changes"
  /opt/kasm/bin/stop
  /opt/kasm/bin/start
fi