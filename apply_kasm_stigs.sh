#!/bin/bash

set -e

## Colors
CMD="\e[0;34m"
OK='\e[0;32m'
NC='\e[0m'

function display_help() {
    echo "Usage IE:"
    echo "${0} --verbose"
    echo    ""
    echo    "Flag                                        Description"
    echo    "---------------------------------------------------------------------------------------------------------------"
    echo -e "| ${CMD}-h|--help${NC}                  | Display this help menu                                                      |"
    echo -e "| ${CMD}-v|--verbose${NC}               | Show output of STIG validation commands                                     |"
    echo    "---------------------------------------------------------------------------------------------------------------"
}

# Command line opts
ARGS=("$@")
for index in "${!ARGS[@]}"; do
    case ${ARGS[index]} in
        -v|--verbose)
            SHOW_ARTIFACT=true
            ;;
        -h|--help)
            display_help
            exit 1
            ;;
        *)
            echo "Unknown option ${ARGS[index]}"
            display_help
            cleanup_log
            exit 1
            ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

YQ_BIN="/opt/kasm/bin/utils/yq_$(uname -m)"
PRI_INTERFACE=$(ip route | grep -m 1 'default via' | grep -Po '(?<=dev )\S+')
PRI_IP=$(ip -f inet addr show "$PRI_INTERFACE" | grep -Po '(?<=inet )(\d{1,3}\.)+\d{1,3}')
RESTART_CONTAINERS="false"
CON_RED='\033[0;31m'
CON_GREEN='\033[0;32m'
CON_ORANGE='\033[0;33m'
CON_NC='\033[0m' # No Color
KASM_VERSION='1.18.0'
NUM_CPUS=$(nproc)
CPU_LIMIT=4
TOTAL_MEM=$(free -g -h -t | grep "Mem:" | awk '{print $2}')
MEMORY=$(printf "%.0f" "$(echo "${TOTAL_MEM}" | cut -d'G' -f1)")
KASM_UID=$(id kasm -u)
KASM_GID=$(id kasm -g)

#ip check
read -rp "Please verify that $PRI_IP is the IP address that docker should bind to (y/n)? " choice
    case "${choice}" in
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

if [[ "${MEMORY}" -ge 4 ]]; then
    (( MEMORY=MEMORY-1 ))
fi

# Check for yq
if [[ ! -f "${YQ_BIN}" ]]; then
    if [[ $(uname -m) == "x86_64" ]]; then
        YQ_ARCH="amd64"
    elif [[ $(uname -m) == "aarch64" ]]; then
        YQ_ARCH="arm64"
    fi
    # Check for internet connectivity
    if ! curl -s --connect-timeout 5 https://www.google.com > /dev/null; then
        echo "Without internet connectivity I cannot download YQ please install it at ${YQ_BIN}"
        exit 1
    fi
    YQ_RELEASE=$(curl -sX GET "https://api.github.com/repos/mikefarah/yq/releases/latest" \
    | awk '/tag_name/{print $4;exit}' FS='[""]');
    mkdir -p /opt/kasm/bin/utils/
    curl -L -o \
        "${YQ_BIN}" \
        "https://github.com/mikefarah/yq/releases/download/${YQ_RELEASE}/yq_linux_${YQ_ARCH}"
    chmod +x "${YQ_BIN}"
fi

kernel_version_greater_than_or_equal() {
    # $1 being passed in is major version to check for
    # $2 being passed in is minor version to check for
    read -r MAJOR_VERSION MINOR_VERSION <<<"$(uname -r | awk -F '.' '{print $1, $2}')"
    if [[ "${MAJOR_VERSION}" -le "${1}" ]]  && [[ "${MINOR_VERSION}" -lt "${2}" ]]  || [[ "${MAJOR_VERSION}" -lt "${1}" ]]; then
        echo 0
    else
        echo 1
    fi
}

# Pretty logging
log_succes() {
    printf %b "$1, ${CON_GREEN}PASS${CON_NC}, $2\n"
}

log_failure() {
    printf %b "$1, ${CON_RED}FAIL${CON_NC}, $2\n"
}

log_na() {
    printf %b "$1, ${CON_ORANGE}N/A${CON_NC}, $2\n"
}

log_manual() {
    printf %b "$1, ${CON_ORANGE}MANUAL${CON_NC}, $2\n"
}

# Set cpu and memory limitations for service containers V-235807, V-235806
if ! "${YQ_BIN}" -e '.services[].mem_limit' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1; then
    for key in $("${YQ_BIN}" '.services | keys | .[]' /opt/kasm/current/docker/docker-compose.yaml); do
       if [[ "${key}" =~ db ]]; then
            "${YQ_BIN}" -i '.services."'"${key}"'".cpus = "'"${NUM_CPUS}"'"' /opt/kasm/current/docker/docker-compose.yaml
            "${YQ_BIN}" -i '.services."'"${key}"'".mem_limit = "'"${MEMORY}"'G"' /opt/kasm/current/docker/docker-compose.yaml
        else
            if [[ "$CPU_LIMIT" -gt "$NUM_CPUS" ]]; then
                "${YQ_BIN}" -i '.services."'"${key}"'".cpus = "'"${NUM_CPUS}"'"' /opt/kasm/current/docker/docker-compose.yaml
                "${YQ_BIN}" -i '.services."'"${key}"'".mem_limit = "2G"' /opt/kasm/current/docker/docker-compose.yaml
            else
                "${YQ_BIN}" -i '.services."'"${key}"'".cpus = "'"${CPU_LIMIT}"'"' /opt/kasm/current/docker/docker-compose.yaml
                "${YQ_BIN}" -i '.services."'"${key}"'".mem_limit = "2G"' /opt/kasm/current/docker/docker-compose.yaml
            fi
        fi
    done
    RESTART_CONTAINERS="true"
    log_succes "V-235807,V-235806" "CPU and memory limits have been set"
else
    log_succes "V-235807,V-235806" "CPU and memory limits have been set"
fi
if [[ -n "${SHOW_ARTIFACT}" ]]; then
    echo "Command: ${YQ_BIN} -e '.services[].mem_limit, .services[].cpus' /opt/kasm/current/docker/docker-compose.yaml"
    echo "Output: $( "${YQ_BIN}" -e '.services[].mem_limit, .services[].cpus' /opt/kasm/current/docker/docker-compose.yaml )"
fi

# Set restart policy for service containers V-235843 
# adding a mannual delay of 60 sec on rdpgw https , since it requires healthy manager
if "${YQ_BIN}" -e '.services[].restart' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1; then
    "${YQ_BIN}" -i '.services.kasm_rdp_https_gateway.entrypoint = ["/bin/sh","-c","sleep 60 && exec /opt/rdpgw/rdpgw"]' /opt/kasm/current/docker/docker-compose.yaml
    "${YQ_BIN}" -i '(.services[].restart) = "on-failure:5"' /opt/kasm/current/docker/docker-compose.yaml 
    RESTART_CONTAINERS="true"
    log_succes "V-235843" "restart limits have been set on containers"
else
    log_succes "V-235843" "restart limits have been set on containers"
fi
if [[ -n "${SHOW_ARTIFACT}" ]]; then
    echo "Command: ${YQ_BIN} -e '.services[].restart' /opt/kasm/current/docker/docker-compose.yaml "
    echo "Output: $( "${YQ_BIN}" -e '.services[].restart' /opt/kasm/current/docker/docker-compose.yaml)"
fi

# Set no new privilages for all containers V-235816
if ! "${YQ_BIN}" -e '.services[].security_opt' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1; then
    "${YQ_BIN}" -i '.services.[] *= {"security_opt": ["no-new-privileges"]}' /opt/kasm/current/docker/docker-compose.yaml
    RESTART_CONTAINERS="true"
    log_succes "V-235816" "security-opt no-new-privileges has been set for all containers"
else
    log_succes "V-235816" "security-opt no-new-privileges has been set for all containers"
fi
if [[ -n "${SHOW_ARTIFACT}" ]]; then
    echo "Command: ${YQ_BIN} -e '.services[].security_opt' /opt/kasm/current/docker/docker-compose.yaml "
    echo "Output: $("${YQ_BIN}" -e '.services[].security_opt' /opt/kasm/current/docker/docker-compose.yaml)"
fi

# Bind open ports to host interface V-235820
if "${YQ_BIN}" -e '.services.proxy' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1; then
    if ! [[ "$("${YQ_BIN}" -e '.services.proxy.ports[0]' /opt/kasm/current/docker/docker-compose.yaml)" == *"${PRI_IP}"*  ]]; then
        PORTS="$("${YQ_BIN}" -e '.services.proxy.ports[0]' /opt/kasm/current/docker/docker-compose.yaml | grep -Po '\d+:\d+$')"
        "${YQ_BIN}" -i ".services.proxy.ports[0] = \"${PRI_IP}:${PORTS}\"" /opt/kasm/current/docker/docker-compose.yaml
        RESTART_CONTAINERS="true"
        log_succes "V-235820" "Incoming container traffic has been bound to ${PRI_IP}"
    else
        log_succes "V-235820" "Incoming container traffic has been bound to ${PRI_IP}"
    fi
fi
if [[ -n "${SHOW_ARTIFACT}" ]]; then
    echo "Command: docker ps --quiet | xargs docker inspect --format '{{ .Name }}: Ports={{ .NetworkSettings.Ports }}' "
    echo "Output: $(docker ps --quiet | xargs docker inspect --format '{{ .Name }}: Ports={{ .NetworkSettings.Ports }}' )"
fi

# Set pid limits for all containers V-235828
if ! "${YQ_BIN}" -e '.services[].pids_limit' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1; then
    "${YQ_BIN}" -i '.services.[] += {"pids_limit": 100}' /opt/kasm/current/docker/docker-compose.yaml
    if "${YQ_BIN}" -e '.services.kasm_guac' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1; then
        "${YQ_BIN}" -i '.services.kasm_guac.pids_limit = 1000' /opt/kasm/current/docker/docker-compose.yaml
    fi
    RESTART_CONTAINERS="true"
    log_succes "V-235828" "pid limit set for all containers"
else
    log_succes "V-235828" "pid limit set for all containers"
fi
if [[ -n "${SHOW_ARTIFACT}" ]]; then
    echo "Command: ${YQ_BIN} -e '.services[].pids_limit' /opt/kasm/current/docker/docker-compose.yaml "
    echo "Output: $("${YQ_BIN}" -e '.services[].pids_limit' /opt/kasm/current/docker/docker-compose.yaml)"
fi

# Setup docker daemon to use TCP and modify agent V-235818
if [[ ! -d "/opt/kasm/current/certs/docker" ]]  && "${YQ_BIN}" -e '.services.kasm_agent' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1; then
    # Cert management
    mkdir /tmp/certs
    cd /tmp/certs
    SUBJECT="/C=US/ST=VA/L=City/O=Kasm/OU=Kasm Server/CN=$(hostname)"
    openssl genrsa -out ca-key.pem 4096
    openssl req -new -x509 -days 3650 -key ca-key.pem -out ca.pem -subj "$SUBJECT"
    openssl req -new -nodes -out server.csr -keyout server-key.pem -subj "$SUBJECT"
    openssl req -subj "/CN=$(hostname)" -new -key server-key.pem -out server.csr
    echo "subjectAltName = DNS:$(hostname),IP:${PRI_IP}" >> extfile.cnf
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
    jq '. *= { "hosts": ["tcp://'"${PRI_IP}"':2375", "unix:///var/run/docker.sock"], "tlscacert": "/etc/docker/certs/ca.pem", "tlscert": "/etc/docker/certs/server-cert.pem", "tlskey": "/etc/docker/certs/server-key.pem", "tlsverify": true }' /etc/docker/daemon.json > /tmp/daemon.json.tmp
    cp /tmp/daemon.json.tmp /etc/docker/daemon.json
    rm /tmp/daemon.json.tmp
    mkdir -p /etc/systemd/system/docker.service.d/
    if [[ ! -f /etc/systemd/system/docker.service.d/override.conf ]]; then
    cat >/etc/systemd/system/docker.service.d/override.conf <<EOL
[Service]
ExecStart=
ExecStart=/usr/bin/dockerd --containerd=/run/containerd/containerd.sock
EOL
    elif [[ -f /etc/systemd/system/docker.service.d/override.conf ]] && grep -q '\[Service\]' "/etc/systemd/system/docker.service.d/override.conf"; then
        sed -i '/[Service]/a ExecStart=\nExecStart=/usr/bin/dockerd --containerd=/run/containerd/containerd.sock' /etc/systemd/system/docker.service.d/override.conf
    else
        echo -e '[Service]\nExecStart=\nExecStart=/usr/bin/dockerd --containerd=/run/containerd/containerd.sock' >> /etc/systemd/system/docker.service.d/override.conf
    fi
    systemctl daemon-reload
    systemctl restart docker
    # Agent modifications
    "${YQ_BIN}" -i 'del(.services.kasm_agent.volumes[]| select(. == "/var/run/docker.sock:/var/run/docker.sock")) | .services.kasm_agent *= { "environment": {"DOCKER_HOST": "tcp://'"${PRI_IP}"':2375", "DOCKER_CERT_PATH": "/opt/kasm/current/certs/docker", "DOCKER_TLS_VERIFY": "1"}}' /opt/kasm/current/docker/docker-compose.yaml
    RESTART_CONTAINERS="true"
    # Done
    log_succes "V-235818" "this host and agent are configured to use docker over tcp with TLS auth"
elif [[ -d "/opt/kasm/current/certs/docker" ]]  && "${YQ_BIN}" -e '.services.kasm_agent' /opt/kasm/current/docker/docker-compose.yaml > /dev/null; then
    log_succes "V-235818" "this host and agent are configured to use docker over tcp with TLS auth"
else
    log_succes "V-235818" "this host does not have an agent on it"
fi
if [[ -n "${SHOW_ARTIFACT}" ]]; then
    echo "Command: ${YQ_BIN} -e '.services.kasm_agent' /opt/kasm/current/docker/docker-compose.yaml "
    echo "Output: $("${YQ_BIN}" -e '.services.kasm_agent' /opt/kasm/current/docker/docker-compose.yaml)"
fi

if "${YQ_BIN}" -e '.services.kasm_agent' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1; then
    DOCKER_SSL_CERT=/etc/docker/certs/server-cert.pem
    DOCKER_SSL_KEY=/etc/docker/certs/server-key.pem
    DOCKER_SSL_CA=/etc/docker/certs/ca.pem
    if [[ -f "$DOCKER_SSL_CERT" ]]; then
        chown root:root $DOCKER_SSL_CERT
        log_succes "V-235861" "$DOCKER_SSL_CERT owned by root:root"
        if [[ -n "${SHOW_ARTIFACT}" ]]; then
            echo "Command: stat -c %U:%G $DOCKER_SSL_CERT "
            echo "Output: $(stat -c %U:%G $DOCKER_SSL_CERT)"
        fi
    else
        log_na "V-235861" "SSL cert does not exist"
    fi

    if [[ -f "$DOCKER_SSL_KEY" ]]; then
        chmod 400 $DOCKER_SSL_KEY
        log_succes "V-235864" "$DOCKER_SSL_KEY permissions set to 0400"
        if [[ -n "${SHOW_ARTIFACT}" ]]; then
            echo "Command: stat -c %U:%G $DOCKER_SSL_KEY "
            echo "Output: $(stat -c %U:%G $DOCKER_SSL_KEY)"
        fi
    else
        log_na "V-235864" "SSL key does not exist"
    fi

    if [[ -f "$DOCKER_SSL_CA" ]]; then
        chown root:root $DOCKER_SSL_CA
        log_succes "V-235859" "$DOCKER_SSL_CA owned by root:root"
        if [[ -n "${SHOW_ARTIFACT}" ]]; then
            echo "Command: stat -c %U:%G $DOCKER_SSL_CA "
            echo "Output: $(stat -c %U:%G $DOCKER_SSL_CA)"
        fi
    else
        log_na "V-235859" "SSL CA does not exist"
    fi
    chown -R kasm:kasm "/opt/kasm/current/certs/docker"
    log_succes "V-235859" "client certs are owned by kasm user"
    if [[ -n "${SHOW_ARTIFACT}" ]]; then
        echo "Command: stat -c %U:%G '/opt/kasm/current/certs/docker' "
        echo "Output: $(stat -c %U:%G '/opt/kasm/current/certs/docker')"
    fi
fi

# Remove the Kasm_share container from docker compose
if "${YQ_BIN}" -e '.services.kasm_share' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1; then
    RESTART_CONTAINERS="true"
    "${YQ_BIN}" eval -i 'del(.services.kasm_share)' /opt/kasm/current/docker/docker-compose.yaml
    "${YQ_BIN}" eval -i 'del(.services.proxy.depends_on[] | select(. == "kasm_share"))' /opt/kasm/current/docker/docker-compose.yaml
    if docker container inspect kasm_share > /dev/null 2>&1; then
        docker container rm -f kasm_share
    fi
fi

# Rename nginx config for the share service, if exists
if [[ -f /opt/kasm/current/conf/nginx/services.d/share_api.conf ]]; then
    mv /opt/kasm/current/conf/nginx/services.d/share_api.conf /opt/kasm/current/conf/nginx/services.d/share_api.bak
    mv /opt/kasm/current/conf/nginx/upstream_share.conf /opt/kasm/current/conf/nginx/upstream_share.bak
fi

### RO containers V-235808

# Agent changes
if "${YQ_BIN}" -e '.services.kasm_agent' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1 && [[ ! -d "/opt/kasm/current/tmp/kasm_agent" ]]; then
    if "${YQ_BIN}" -e '.services.kasm_agent.read_only' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1; then
        log_succes "V-235808" "kasm_agent is read only"
    else
        log_failure "V-235808" "kasm_agent is not read only"
    fi
else
    log_succes "V-235808" "kasm_agent is read only"
fi

# Proxy changes
if "${YQ_BIN}" -e '.services.proxy' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1 && [[ ! -d "/opt/kasm/current/cache/nginx" ]]; then
    if "${YQ_BIN}" -e '.services.proxy.read_only' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1;
    then
        log_succes "V-235808" "proxy is read only"
        if [[ -n "${SHOW_ARTIFACT}" ]]; then
            echo "Command: ${YQ_BIN} -e '.services.proxy.read_only' /opt/kasm/current/docker/docker-compose.yaml "
            echo "Output: $( "${YQ_BIN}" -e '.services.proxy.read_only' /opt/kasm/current/docker/docker-compose.yaml)"
        fi
    else
        mkdir -p /opt/kasm/current/cache/nginx
        chown -R kasm:kasm /opt/kasm/current/cache
        "${YQ_BIN}" -i '.services.proxy.volumes += "/opt/kasm/current/cache/nginx:/var/cache/nginx" | .services.proxy += {"read_only": true} | .services.proxy += {"tmpfs": ["/var/run:uid='"${KASM_UID}"',gid='"${KASM_GID}"'"]}' /opt/kasm/current/docker/docker-compose.yaml
        RESTART_CONTAINERS="true"
        log_succes "V-235808" "proxy is read only"
    fi
else
    log_succes "V-235808" "proxy is read only"
fi

# API changes
if "${YQ_BIN}" -e '.services.kasm_api' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1 && [[ ! -d "/opt/kasm/current/tmp/kasm_api" ]]; then
    if "${YQ_BIN}" -e '.services.kasm_api.read_only' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1; then
        log_succes "V-235808" "kasm_api is read only"
    else
        log_failure "V-235808" "kasm_api is not read only"
    fi
else
    log_succes "V-235808" "kasm_api is read only"
fi

# Manager Changes
if "${YQ_BIN}" -e '.services.kasm_manager' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1 && [[ ! -d "/opt/kasm/current/tmp/kasm_manager" ]]; then
    if "${YQ_BIN}" -e '.services.kasm_manager.read_only' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1; then
        log_succes "V-235808" "kasm_manager is read only"
        if [[ -n "${SHOW_ARTIFACT}" ]]; then
            echo "Command: ${YQ_BIN} -e '.services.kasm_manager.read_only' /opt/kasm/current/docker/docker-compose.yaml "
            echo "Output: $("${YQ_BIN}" -e '.services.kasm_manager.read_only' /opt/kasm/current/docker/docker-compose.yaml)"
        fi
    else
        log_failure "V-235808" "kasm_manager is not read only"
    fi
else
    log_succes "V-235808" "kasm_manager is read only"
fi

# Database changes
if "${YQ_BIN}" -e '.services.db' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1 && "${YQ_BIN}" -e '.services.db.read_only' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1; then
    log_succes "V-235808" "kasm_db is read only"
else
    success=1
    if [[ ! -d "/opt/kasm/current/tmp/kasm_db" ]]; then
        mkdir /opt/kasm/current/tmp/kasm_db/
    fi
    if [[ ! -d "/opt/kasm/current/tmp/kasm_db_run" ]]; then
        mkdir /opt/kasm/current/tmp/kasm_db_run/
    fi
    if [[ $("${YQ_BIN}" '.services.db.volumes.[] | select(. == "/opt/kasm/'${KASM_VERSION}'/conf/database/:/tmp/") | (. == "/opt/kasm/'${KASM_VERSION}'/conf/database/:/tmp/")' /opt/kasm/current/docker/docker-compose.yaml) == 'true' ]]; then
        "${YQ_BIN}" -i 'del(.services.db.volumes[] | select(. == "/opt/kasm/'${KASM_VERSION}'/conf/database/:/tmp/")) | .services.db.volumes += "/opt/kasm/'${KASM_VERSION}'/tmp/kasm_db/:/tmp/"' /opt/kasm/current/docker/docker-compose.yaml
        "${YQ_BIN}" -i '.services.db += {"read_only": true}' /opt/kasm/current/docker/docker-compose.yaml
        RESTART_CONTAINERS="true"
        success=1
    else
        if [[ $("${YQ_BIN}" '.services.db.volumes.[] | select(. == "/opt/kasm/'${KASM_VERSION}'/tmp/kasm_db/:/tmp/") | (. == "/opt/kasm/'${KASM_VERSION}'/tmp/kasm_db/:/tmp/")' /opt/kasm/current/docker/docker-compose.yaml) == 'false' ]]; then
            log_failure "V-235808 couldn't find tmp volume to update for the database container"
            success=0
        else
            "${YQ_BIN}" -i '.services.db += {"read_only": true}' /opt/kasm/current/docker/docker-compose.yaml
            RESTART_CONTAINERS="true"
            success=1
        fi
    fi
    if [[ $("${YQ_BIN}" '.services.db.volumes.[] | select(. == "/opt/kasm/'${KASM_VERSION}'/tmp/kasm_db_run/:/var/run/postgresql/") | (. == "/opt/kasm/'${KASM_VERSION}'/tmp/kasm_db_run/:/var/run/postgresql/")' /opt/kasm/current/docker/docker-compose.yaml) == 'false' ]] && [[ "$success" -eq "1" ]]; then
        "${YQ_BIN}" -i '.services.db.volumes += "/opt/kasm/'${KASM_VERSION}'/tmp/kasm_db_run/:/var/run/postgresql/"' /opt/kasm/current/docker/docker-compose.yaml
        success=1
    fi
    if [[ "$success" -eq "1" ]]; then
        log_succes "V-235808" "kasm_db is read only"
    fi
fi

# Redis changes
if "${YQ_BIN}" -e '.services.kasm_redis' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1 && [[ ! -d "/opt/kasm/current/tmp/kasm_redis" ]]; then
    if "${YQ_BIN}" -e '.services.kasm_redis.read_only' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1; then
        log_succes "V-235808" "kasm_redis is read only"
    else
        mkdir -p /opt/kasm/current/tmp/kasm_redis
        chown -R kasm:kasm /opt/kasm/current/tmp
        "${YQ_BIN}" -i '.services.kasm_redis.volumes += ["/opt/kasm/current/tmp/kasm_redis:/data"] | .services.kasm_redis += {"read_only": true}' /opt/kasm/current/docker/docker-compose.yaml
        RESTART_CONTAINERS="true"
        log_succes "V-235808" "kasm_redis is read only"
    fi
else
    log_succes "V-235808" "kasm_redis is read only"
fi

# rdp_gateway changes
if "${YQ_BIN}" -e '.services.rdp_gateway' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1 && [[ ! -d "/opt/kasm/current/tmp/rdpgw" ]]; then
    if "${YQ_BIN}" -e '.services.rdp_gateway.read_only' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1; then
        log_succes "V-235808" "rdp_gateway is read only"
    else
        log_failure "V-235808" "rdp_gateway is not read only"
    fi
else
    log_succes "V-235808" "rdp_gateway is read only"
fi

# kasm_rdp_https_gateway changes
if "${YQ_BIN}" -e '.services.kasm_rdp_https_gateway' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1; then
    if "${YQ_BIN}" -e '.services.kasm_rdp_https_gateway.read_only' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1; then
        log_succes "V-235808" "kasm_rdp_https_gateway is read only"
    else
        log_failure "V-235808" "kasm_rdp_https_gateway is not read only"
    fi
else
    log_succes "V-235808" "kasm_rdp_https_gateway is read only"
fi

# guac changes
if "${YQ_BIN}" -e '.services.kasm_guac' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1 && [[ ! -d "/opt/kasm/current/tmp/guac" ]]; then
    if "${YQ_BIN}" -e '.services.kasm_guac.read_only' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1; then
        log_succes "V-235808" "kasm_guac is read only"
    else
        log_failure "V-235808" "kasm_guac is not read only"
    fi
else
    log_succes "V-235808" "kasm_guac is read only"
fi

# Show output of all containers for v-235808
if [[ -n "${SHOW_ARTIFACT}" ]]; then
    echo "Command:  sudo docker ps --quiet --all | xargs -L 1 sudo docker inspect --format '{{ .Id }}: ReadonlyRootfs={{ .HostConfig.ReadonlyRootfs }}' "
    echo "Output: $(sudo docker ps --quiet --all | xargs -L 1 sudo docker inspect --format '{{ .Id }}: ReadonlyRootfs={{ .HostConfig.ReadonlyRootfs }}')"
fi

# proxy health check
if "${YQ_BIN}" -e '.services.proxy' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1; then
    if ! ("${YQ_BIN}" -e '.services.proxy' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1 | grep --quiet healthcheck); then
    "${YQ_BIN}" -i '.services.proxy += {"healthcheck": { "test": "nginx -t", "timeout": "2s", "retries": 5 }}' /opt/kasm/current/docker/docker-compose.yaml
    RESTART_CONTAINERS="true"
    echo 'APPLIED HEATH CHECK proxy'
    fi
fi

# redis health check
if "${YQ_BIN}" -e '.services.kasm_redis' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1; then
    if ! ("${YQ_BIN}" -e '.services.kasm_redis' /opt/kasm/current/docker/docker-compose.yaml > /dev/null 2>&1 | grep --quiet healthcheck); then
    "${YQ_BIN}" -i '.services.kasm_redis += {"healthcheck": { "test": "redis-cli ping", "timeout": "3s", "retries": 5 }}' /opt/kasm/current/docker/docker-compose.yaml
    RESTART_CONTAINERS="true"
    echo 'APPLIED HEATH CHECK redis'
    fi
fi

# Force user mode on all containers V-235830
# If the kernel version is < 4.11 and the port to be mapped is 443 we can't update the user
# (making the assumption no other port under 1024 is likely to be mapped)
CONTAINERS_TO_CHANGE=('proxy' 'kasm_agent' 'db')
# kasm_api, kasm_guac, kasm_manager, kasm_rdp_gateway, kasm_rdp_https_gateway, and kasm_redis all pass this check without any modifcation.
for container in "${CONTAINERS_TO_CHANGE[@]}"; do
    if [[ $container == 'proxy' && $("${YQ_BIN}" '.services.proxy | (. == null)' /opt/kasm/current/docker/docker-compose.yaml) == 'false' && $(kernel_version_greater_than_or_equal "4" "11") -eq 0 && $("${YQ_BIN}" '.services.proxy.ports.[] | ( . == "443:443")' /opt/kasm/current/docker/docker-compose.yaml) == 'true' ]]; then
        log_failure "V-235830" "Proxy container cannot be set to run as kasm user ${KASM_UID}. Please update the OS kernel or change the port Kasm proxy listens on"
    elif [[ $container == 'db' && $("${YQ_BIN}" '.services.'"${container}"' | (. == null)' /opt/kasm/current/docker/docker-compose.yaml) == 'false' ]]; then
        if [[ $("${YQ_BIN}" '.services.'"${container}"'.user | (. == "70:70")' /opt/kasm/current/docker/docker-compose.yaml) == 'false' ]]; then
            "${YQ_BIN}" -i '.services.'"${container}"'.user = "70:70"' /opt/kasm/current/docker/docker-compose.yaml
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
        if [[ $("${YQ_BIN}" '.services.'"${container}"'.volumes.[] | select(. == "/opt/kasm/'${KASM_VERSION}'/conf/database/:/tmp/") | (. == "/opt/kasm/'${KASM_VERSION}'/conf/database/:/tmp/")' /opt/kasm/current/docker/docker-compose.yaml) == 'true' ]]; then
            "${YQ_BIN}" -i 'del(.services.'"${container}"'.volumes[] | select(. == "/opt/kasm/'${KASM_VERSION}'/conf/database/:/tmp/")) | .services.'"${container}"'.volumes += "/opt/kasm/'${KASM_VERSION}'/tmp/kasm_db/:/tmp/"' /opt/kasm/current/docker/docker-compose.yaml
        else
            if [[ $("${YQ_BIN}" '.services.'"${container}"'.volumes.[] | select(. == "/opt/kasm/'${KASM_VERSION}'/tmp/kasm_db/:/tmp/") | (. == "/opt/kasm/'${KASM_VERSION}'/tmp/kasm_db/:/tmp/")' /opt/kasm/current/docker/docker-compose.yaml) == 'false' ]]; then
                log_failure "V-235830 couldn't find tmp volumne to update for the database contaioner"
                continue
            fi
        fi
        log_succes "V-235830" "Container db set to run as postgresql user 70"
    else
        if [[ $("${YQ_BIN}" '.services.'"${container}"' | (. == null)' /opt/kasm/current/docker/docker-compose.yaml) == 'false' ]]; then
            USEROUT=$("${YQ_BIN}" '.services.'"${container}"'.user' /opt/kasm/current/docker/docker-compose.yaml)
            # shellcheck disable=SC2016
            if [[ ! "${USEROUT}" == *'${KASM_UID?}:${KASM_GID?}'* ]]; then
                "${YQ_BIN}" -i '.services.'"${container}"'.user = "${KASM_UID?}:${KASM_GID?}"' /opt/kasm/current/docker/docker-compose.yaml
                RESTART_CONTAINERS="true"
                if [[ $container == 'proxy' ]]; then
                    chown -R kasm:kasm /opt/kasm/current/log/nginx
                    chown -R kasm:kasm /opt/kasm/current/certs/kasm_nginx*
                elif [[ $container == 'kasm_agent' ]]; then
                    chown -R kasm:kasm /opt/kasm/current/log/agent*
                    chown -R kasm:kasm /opt/kasm/current/file_mappings*
                    chown -R kasm:kasm /opt/kasm/current/conf/app
                fi
                log_succes "V-235830" "Container ${container} set to run as kasm user ${KASM_UID}"
            else
                log_succes "V-235830" "Container ${container} set to run as kasm user ${KASM_UID}"
            fi
        fi
    fi
done
if [[ -n "${SHOW_ARTIFACT}" ]]; then
    echo "Command:  docker ps -q -a | xargs docker inspect --format '{{ .Id }}: User={{ .Config.User }}' "
    echo "Output: $(docker ps -q -a | xargs docker inspect --format '{{ .Id }}: User={{ .Config.User }}')"
fi

#### Restart containers if flagged ####
if [[ "${RESTART_CONTAINERS}" == "true" ]]; then
    echo "Restarting containers with new compose changes"
    /opt/kasm/bin/stop
    /opt/kasm/bin/start
fi

#### Make sure containers are running with a health check
for container_id in $(docker compose --project-directory /opt/kasm/current/docker/ ps -q  2>/dev/null); do
    container_name=$(docker inspect "$container_id" --format '{{.Name}}' | sed 's/\///')
    if docker inspect "$container_id" --format '{{ .State.Health.Status }}' > /dev/null 2>&1; then
        log_succes "V-235827" "$container_name has health check"
    else
        log_failure "V-235827" "$container_name is missing health check"
    fi
done
if [[ -n "${SHOW_ARTIFACT}" ]]; then
    echo "Command:  docker ps | grep -viP '(\(health|CONTAINER ID)' "
    echo "Output: $(docker ps | grep -viP '(\(health|CONTAINER ID)')"
fi

echo -e "${OK}Kasm stig application complete${NC}"
