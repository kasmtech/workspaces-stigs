#!/bin/bash
set -e

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

ARCH=$(uname -m | sed 's/aarch64/arm64/g' | sed 's/x86_64/amd64/g')
if [ "$ARCH" != "amd64" ] ; then
    echo "Unable to continue. Kasm hardening scripts support AMD64 only."
fi

PRI_INTERFACE=$(ip route | grep -m 1 'default via' | grep -Po '(?<=dev )\S+')
PRI_IP=$(ip -f inet addr show "$PRI_INTERFACE" | grep -Po '(?<=inet )(\d{1,3}\.)+\d{1,3}')
RESTART_CONTAINERS="false"
CON_RED='\033[0;31m'
CON_GREEN='\033[0;32m'
CON_ORANGE='\033[0;33m'
CON_NC='\033[0m' # No Color
KUID=$(id -u kasm)
KASM_VERSION='1.12.0'

# Check for yq
if [ ! -f '/opt/kasm/bin/utils/yq_x86_64' ]; then
    # Check for internet connectivity
    if ! curl -s --connect-timeout 5 https://www.google.com > /dev/null; then
       echo "Without internet connectivity I cannot download YQ please install it at /opt/kasm/bin/utils/yq_x86_64"
       exit 1
    fi
    YQ_RELEASE=$(curl -sX GET "https://api.github.com/repos/mikefarah/yq/releases/latest" \
    | awk '/tag_name/{print $4;exit}' FS='[""]');
    mkdir -p /opt/kasm/bin/utils/
    curl -L -o \
        /opt/kasm/bin/utils/yq_x86_64 \
        https://github.com/mikefarah/yq/releases/download/${YQ_RELEASE}/yq_linux_amd64
    chmod +x /opt/kasm/bin/utils/yq_x86_64
fi

kernel_version_greater_than_or_equal() {
  # $1 being passed in is major version to check for
  # $2 being passed in is minor version to check for
  read MAJOR_VERSION MINOR_VERSION <<<$(uname -r | awk -F '.' '{print $1, $2}')
  if [ $MAJOR_VERSION -le $1 ] && [ $MINOR_VERSION -lt $2 ] || [ $MAJOR_VERSION -lt $1 ] ; then
    echo 0
  else
    echo 1
  fi
}

# Determine role of server
if ! /opt/kasm/bin/utils/yq_x86_64 '.services.kasm_agent' /opt/kasm/current/docker/docker-compose.yaml | grep -q null; then
  ROLE=agent
fi
if ! /opt/kasm/bin/utils/yq_x86_64 '.services.db' /opt/kasm/current/docker/docker-compose.yaml | grep -q null; then
  ROLE=db
fi
if ! /opt/kasm/bin/utils/yq_x86_64 '.services.kasm_api' /opt/kasm/current/docker/docker-compose.yaml | grep -q null; then
  ROLE=app
fi

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
  if /opt/kasm/bin/utils/yq_$(uname -m) -e '.services.kasm_guac' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1; then
    /opt/kasm/bin/utils/yq_$(uname -m) -i '.services.kasm_guac += {"pids_limit": 1000}' /opt/kasm/current/docker/docker-compose.yaml
  fi
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
  /opt/kasm/bin/utils/yq_$(uname -m) -i 'del(.services.kasm_agent.volumes[1])| .services.kasm_agent *= { "environment": {"DOCKER_HOST": "tcp://'${PRI_IP}':2375", "DOCKER_CERT_PATH": "/opt/kasm/current/certs/docker", "DOCKER_TLS_VERIFY": "1"}}' /opt/kasm/current/docker/docker-compose.yaml
  RESTART_CONTAINERS="true"
  # Done
  log_succes "V-235818" "this host and agent are configured to use docker over tcp with TLS auth"
elif [ -d "/opt/kasm/current/certs/docker" ] && /opt/kasm/bin/utils/yq_$(uname -m) -e '.services.kasm_agent' /opt/kasm/current/docker/docker-compose.yaml > /dev/null; then
  log_succes "V-235818" "this host and agent are configured to use docker over tcp with TLS auth"
else
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
    log_succes "V-235859" "$DOCKER_SSL_CA owned by root:root"
  else
    log_na "V-235859" "SSL CA does not exist"
  fi
  chown -R kasm:kasm "/opt/kasm/current/certs/docker"
  log_succes "V-235859" "client certs are owned by kasm user"
fi

# RO containers V-235808

# Agent changes
if /opt/kasm/bin/utils/yq_$(uname -m) -e '.services.kasm_agent' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1 && [ ! -d "/opt/kasm/current/tmp/kasm_agent" ]; then
  if /opt/kasm/bin/utils/yq_$(uname -m) -e '.services.kasm_agent.read_only' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1; then
    log_succes "V-235808" "kasm_agent is read only"
  else
    mkdir -p /opt/kasm/current/tmp/kasm_agent
    chown -R kasm:kasm /opt/kasm/current/tmp/
    /opt/kasm/bin/utils/yq_$(uname -m) -i '.services.kasm_agent.volumes += "/opt/kasm/current/tmp/kasm_agent:/tmp" | .services.kasm_agent += {"read_only": true}' /opt/kasm/current/docker/docker-compose.yaml
    RESTART_CONTAINERS="true"
    log_succes "V-235808" "kasm_agent is read only"
  fi
else
  log_succes "V-235808" "kasm_agent is read only"
fi

# Proxy changes
if /opt/kasm/bin/utils/yq_$(uname -m) -e '.services.proxy' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1 && [ ! -d "/opt/kasm/current/cache/nginx" ]; then
  if /opt/kasm/bin/utils/yq_$(uname -m) -e '.services.proxy.read_only' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1;
then
    log_succes "V-235808" "proxy is read only"
  else
    mkdir -p /opt/kasm/current/cache/nginx
    chown -R kasm:kasm /opt/kasm/current/cache
    /opt/kasm/bin/utils/yq_$(uname -m) -i '.services.proxy.volumes += "/opt/kasm/current/cache/nginx:/var/cache/nginx" | .services.proxy += {"read_only": true} | .services.proxy += {"tmpfs": ["/var/run:uid='${KUID}',gid='${KUID}'"]}' /opt/kasm/current/docker/docker-compose.yaml
    RESTART_CONTAINERS="true"
    log_succes "V-235808" "proxy is read only"
  fi
else
  log_succes "V-235808" "proxy is read only"
fi

# API changes
if /opt/kasm/bin/utils/yq_$(uname -m) -e '.services.kasm_api' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1 && [ ! -d "/opt/kasm/current/tmp/kasm_api" ]; then
  if /opt/kasm/bin/utils/yq_$(uname -m) -e '.services.kasm_api.read_only' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1;
then
    log_succes "V-235808" "kasm_api is read only"
  else
    mkdir -p /opt/kasm/current/tmp/kasm_api
    chown -R kasm:kasm /opt/kasm/current/tmp
    /opt/kasm/bin/utils/yq_$(uname -m) -i '.services.kasm_api.volumes += "/opt/kasm/current/tmp/kasm_api:/tmp" | .services.kasm_api += {"read_only": true}' /opt/kasm/current/docker/docker-compose.yaml
    RESTART_CONTAINERS="true"
    log_succes "V-235808" "kasm_api is read only"
  fi
else
  log_succes "V-235808" "kasm_api is read only"
fi

# Manager Changes
if /opt/kasm/bin/utils/yq_$(uname -m) -e '.services.kasm_manager' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1 && [ ! -d "/opt/kasm/current/tmp/kasm_manager" ]; then
  if /opt/kasm/bin/utils/yq_$(uname -m) -e '.services.kasm_manager.read_only' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1; then
    log_succes "V-235808" "kasm_manager is read only"
  else
    mkdir -p /opt/kasm/current/tmp/kasm_manager
    chown -R kasm:kasm /opt/kasm/current/tmp
    /opt/kasm/bin/utils/yq_$(uname -m) -i '.services.kasm_manager.volumes += "/opt/kasm/current/tmp/kasm_manager:/tmp" | .services.kasm_manager += {"read_only": true}' /opt/kasm/current/docker/docker-compose.yaml
    RESTART_CONTAINERS="true"
    log_succes "V-235808" "kasm_manager is read only"
  fi
else
  log_succes "V-235808" "kasm_manager is read only"
fi

# Share changes
if /opt/kasm/bin/utils/yq_$(uname -m) -e '.services.kasm_share' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1 && [ ! -d "/opt/kasm/current/tmp/kasm_share" ]; then
  if /opt/kasm/bin/utils/yq_$(uname -m) -e '.services.kasm_share.read_only' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1; then
    log_succes "V-235808" "kasm_share is read only"
  else
    mkdir -p /opt/kasm/current/tmp/kasm_share
    chown -R kasm:kasm /opt/kasm/current/tmp
    /opt/kasm/bin/utils/yq_$(uname -m) -i '.services.kasm_share.volumes += "/opt/kasm/current/tmp/kasm_share:/tmp" | .services.kasm_share += {"read_only": true}' /opt/kasm/current/docker/docker-compose.yaml
    RESTART_CONTAINERS="true"
    log_succes "V-235808" "kasm_share is read only"
  fi
else
  log_succes "V-235808" "kasm_share is read only"
fi

# Database changes
if /opt/kasm/bin/utils/yq_$(uname -m) -e '.services.db' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1 && /opt/kasm/bin/utils/yq_$(uname -m) -e '.services.db.read_only' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1; then
    log_succes "V-235808" "kasm_db is read only"
else
    success=1
    if [[ ! -d "/opt/kasm/current/tmp/kasm_db" ]]; then
        mkdir /opt/kasm/current/tmp/kasm_db/
    fi
    if [[ ! -d "/opt/kasm/current/tmp/kasm_db_run" ]]; then
        mkdir /opt/kasm/current/tmp/kasm_db_run/
    fi
    if [[ $(/opt/kasm/bin/utils/yq_$(uname -m) '.services.db.volumes.[] | select(. == "/opt/kasm/'${KASM_VERSION}'/conf/database/:/tmp/") | (. == "/opt/kasm/'${KASM_VERSION}'/conf/database/:/tmp/")' /opt/kasm/current/docker/docker-compose.yaml) == 'true' ]]; then
        $(/opt/kasm/bin/utils/yq_$(uname -m) -i 'del(.services.db.volumes[] | select(. == "/opt/kasm/'${KASM_VERSION}'/conf/database/:/tmp/")) | .services.db.volumes += "/opt/kasm/'${KASM_VERSION}'/tmp/kasm_db/:/tmp/"' /opt/kasm/current/docker/docker-compose.yaml)
        /opt/kasm/bin/utils/yq_$(uname -m) -i '.services.db += {"read_only": true}' /opt/kasm/current/docker/docker-compose.yaml
        RESTART_CONTAINERS="true"
        success=1
    else
        if [[ $(/opt/kasm/bin/utils/yq_$(uname -m) '.services.db.volumes.[] | select(. == "/opt/kasm/'${KASM_VERSION}'/tmp/kasm_db/:/tmp/") | (. == "/opt/kasm/'${KASM_VERSION}'/tmp/kasm_db/:/tmp/")' /opt/kasm/current/docker/docker-compose.yaml) == 'false' ]]; then
            log_failure "V-235808 couldn't find tmp volume to update for the database container"
            success=0
        else
            /opt/kasm/bin/utils/yq_$(uname -m) -i '.services.db += {"read_only": true}' /opt/kasm/current/docker/docker-compose.yaml
            RESTART_CONTAINERS="true"
            success=1
        fi
    fi
    if [[ $(/opt/kasm/bin/utils/yq_$(uname -m) '.services.db.volumes.[] | select(. == "/opt/kasm/'${KASM_VERSION}'/tmp/kasm_db_run/:/var/run/postgresql/") | (. == "/opt/kasm/'${KASM_VERSION}'/tmp/kasm_db_run/:/var/run/postgresql/")' /opt/kasm/current/docker/docker-compose.yaml) == 'false' ]] && [[ "$success" -eq "1" ]]; then
        $(/opt/kasm/bin/utils/yq_$(uname -m) -i '.services.db.volumes += "/opt/kasm/'${KASM_VERSION}'/tmp/kasm_db_run/:/var/run/postgresql/"' /opt/kasm/current/docker/docker-compose.yaml)
        success=1
    fi
    if [[ "$success" -eq "1" ]]; then
        log_succes "V-235808" "kasm_db is read only"
    fi
fi

# Redis changes
if /opt/kasm/bin/utils/yq_$(uname -m) -e '.services.kasm_redis' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1 && [ ! -d "/opt/kasm/current/tmp/kasm_redis" ]; then
  if /opt/kasm/bin/utils/yq_$(uname -m) -e '.services.kasm_redis.read_only' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1; then
    log_succes "V-235808" "kasm_redis is read only"
  else
    mkdir -p /opt/kasm/current/tmp/kasm_redis
    chown -R kasm:kasm /opt/kasm/current/tmp
    /opt/kasm/bin/utils/yq_$(uname -m) -i '.services.kasm_redis.volumes += ["/opt/kasm/current/tmp/kasm_redis:/data"] | .services.kasm_redis += {"read_only": true}' /opt/kasm/current/docker/docker-compose.yaml
    RESTART_CONTAINERS="true"
    log_succes "V-235808" "kasm_redis is read only"
  fi
else
  log_succes "V-235808" "kasm_redis is read only"
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

# guac health check
if /opt/kasm/bin/utils/yq_$(uname -m) -e '.services.kasm_guac' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1 ; then
    if ! (/opt/kasm/bin/utils/yq_$(uname -m) -e '.services.kasm_guac' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1 | grep --quiet healthcheck) ; then
    /opt/kasm/bin/utils/yq_$(uname -m) -i '.services.kasm_guac += {"healthcheck": { "test": "curl -f http://localhost:3000/__healthcheck --max-time 30 || exit 1", "timeout": "3s", "retries": 5 }}' /opt/kasm/current/docker/docker-compose.yaml
    RESTART_CONTAINERS="true"
    echo 'APPLIED HEATH CHECK guac'
    fi
fi

# redis health check
if /opt/kasm/bin/utils/yq_$(uname -m) -e '.services.kasm_redis' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1 ; then
    if ! (/opt/kasm/bin/utils/yq_$(uname -m) -e '.services.kasm_redis' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1 | grep --quiet healthcheck) ; then
    /opt/kasm/bin/utils/yq_$(uname -m) -i '.services.kasm_redis += {"healthcheck": { "test": "redis-cli ping", "timeout": "3s", "retries": 5 }}' /opt/kasm/current/docker/docker-compose.yaml
    RESTART_CONTAINERS="true"
    echo 'APPLIED HEATH CHECK redis'
    fi
fi

# Force user mode on all containers V-235830
# If the kernel version is < 4.11 and the port to be mapped is 443 we can't update the user 
# (making the assumption no other port under 1024 is likely to be mapped)
CONTAINERS_TO_CHANGE=('proxy' 'kasm_share' 'kasm_redis' 'kasm_api' 'kasm_manager' 'kasm_agent' 'kasm_guac' 'db')
for container in ${CONTAINERS_TO_CHANGE[@]}; do
    if [[ $container == 'proxy' && $(/opt/kasm/bin/utils/yq_$(uname -m) '.services.proxy | (. == null)' /opt/kasm/current/docker/docker-compose.yaml) == 'false' && $(kernel_version_greater_than_or_equal "4" "11") -eq 0 && $(/opt/kasm/bin/utils/yq_$(uname -m) '.services.proxy.ports.[] | ( . == "443:443")' /opt/kasm/current/docker/docker-compose.yaml) == 'true' ]]; then
        log_failure "V-235830" "Proxy container cannot be set to run as kasm user ${KUID}. Please update the OS kernel or change the port Kasm proxy listens on"
    elif [[ $container == 'db' && $(/opt/kasm/bin/utils/yq_$(uname -m) '.services.'${container}' | (. == null)' /opt/kasm/current/docker/docker-compose.yaml) == 'false' ]]; then
        if [[ $(/opt/kasm/bin/utils/yq_$(uname -m) '.services.'${container}'.user | (. == "70:70")' /opt/kasm/current/docker/docker-compose.yaml) == 'false' ]]; then
            /opt/kasm/bin/utils/yq_$(uname -m) -i '.services.'${container}'.user = "70:70"' /opt/kasm/current/docker/docker-compose.yaml
        fi
        if [[ ! -d "/opt/kasm/current/tmp/kasm_db" ]]; then
            mkdir /opt/kasm/current/tmp/kasm_db/
            chown -R 70:70 /opt/kasm/current/tmp/kasm_db/
        else
            chown -R 70:70 /opt/kasm/current/tmp/kasm_db/
        fi
        if [[ ! -d "/opt/kasm/current/tmp/kasm_db_run" ]]; then
            mkdir /opt/kasm/current/tmp/kasm_db_run/
            chown -R 70:70 /opt/kasm/current/tmp/kasm_db_run/
        else
            chown -R 70:70 /opt/kasm/current/tmp/kasm_db_run/
        fi
        if [[ $(/opt/kasm/bin/utils/yq_$(uname -m) '.services.'${container}'.volumes.[] | select(. == "/opt/kasm/'${KASM_VERSION}'/conf/database/:/tmp/") | (. == "/opt/kasm/'${KASM_VERSION}'/conf/database/:/tmp/")' /opt/kasm/current/docker/docker-compose.yaml) == 'true' ]]; then
            $(/opt/kasm/bin/utils/yq_$(uname -m) -i 'del(.services.'${container}'.volumes[] | select(. == "/opt/kasm/'${KASM_VERSION}'/conf/database/:/tmp/")) | .services.'${container}'.volumes += "/opt/kasm/'${KASM_VERSION}'/tmp/kasm_db/:/tmp/"' /opt/kasm/current/docker/docker-compose.yaml)
        else
            if [[ $(/opt/kasm/bin/utils/yq_$(uname -m) '.services.'${container}'.volumes.[] | select(. == "/opt/kasm/'${KASM_VERSION}'/tmp/kasm_db/:/tmp/") | (. == "/opt/kasm/'${KASM_VERSION}'/tmp/kasm_db/:/tmp/")' /opt/kasm/current/docker/docker-compose.yaml) == 'false' ]]; then
                log_failure "V-235830 couldn't find tmp volumne to update for the database contaioner"
                continue
            fi
        fi
        log_succes "V-235830" "Container ${container} set to run as kasm user ${KUID}"
    else
        if [[ $(/opt/kasm/bin/utils/yq_x86_64 '.services.'${container}' | (. == null)' /opt/kasm/current/docker/docker-compose.yaml) == 'false' ]]; then
            USEROUT=$(/opt/kasm/bin/utils/yq_$(uname -m) '.services.'${container}'.user' /opt/kasm/current/docker/docker-compose.yaml)
            if [[ ! "${USEROUT}" == *"${KUID}"* ]]; then
                /opt/kasm/bin/utils/yq_$(uname -m) -i '.services.'${container}'.user = "'${KUID}'"' /opt/kasm/current/docker/docker-compose.yaml
                RESTART_CONTAINERS="true"
                if [[ $container == 'proxy' ]]; then
                    chown -R kasm:kasm /opt/kasm/current/log/nginx
                elif [[ $container == 'kasm_share' ]]; then
                    chown -R kasm:kasm /opt/kasm/current/log/share*
                elif [[ $container == 'kasm_api' ]]; then
                    chown -R kasm:kasm /opt/kasm/current/log/api*
                    chown -R kasm:kasm /opt/kasm/current/log/admin_api*
                    chown -R kasm:kasm /opt/kasm/current/log/client_api*
                    chown -R kasm:kasm /opt/kasm/current/log/subscription_api*
                elif [[ $container == 'kasm_manager' ]]; then
                    chown -R kasm:kasm /opt/kasm/current/log/manager_api*
                    chown -R kasm:kasm /opt/kasm/current/log/web_filter_access*
                elif [[ $container == 'kasm_agent' ]]; then
                    chown -R kasm:kasm /opt/kasm/current/log/agent*
                fi
                if [[ $container == 'proxy' ]]; then
                    chown -R kasm:kasm /opt/kasm/current/certs/kasm_nginx*
                fi
                log_succes "V-235830" "Container ${container} set to run as kasm user ${KUID}"   
            else
                log_succes "V-235830" "Container ${container} set to run as kasm user ${KUID}"            
            fi
        fi
    fi
done

#### Restart containers if flagged ####
if [ "${RESTART_CONTAINERS}" == "true" ]; then
  echo "Restaring containers with new compose changes"
  /opt/kasm/bin/stop
  /opt/kasm/bin/start
fi

#### Make sure containers are running with a health check
if docker ps | grep -viP --quiet '(\(health|CONTAINER ID)' ; then
  log_failure 'V-235827' 'Containers found without health checks'
else
  log_succes 'V-235827' 'All running containers have health checks'
fi
