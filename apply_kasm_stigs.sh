#!/bin/bash

set -e

# This can be set explicitly if preferred
KASM_VERSION=$(readlink -f /opt/kasm/current | awk -F '/' '{print $4}')

YQ_BIN="/opt/kasm/bin/utils/yq_$(uname -m)"
KASM_COMPOSE_PROJECT="/opt/kasm/current/docker/docker-compose.yaml"
PRI_INTERFACE=$(ip route | grep -m 1 'default via' | grep -Po '(?<=dev )\S+')
PRI_IP=$(ip -f inet addr show "$PRI_INTERFACE" | grep -Po '(?<=inet )(\d{1,3}\.)+\d{1,3}')
NUM_CPUS=$(nproc)
CPU_LIMIT=4
TOTAL_MEM=$(free -g -h -t | grep "Mem:" | awk '{print $2}')
MEMORY=$(printf "%.0f" "$(echo "${TOTAL_MEM}" | cut -d'G' -f1)")
KASM_UID=$(id kasm -u)
KASM_GID=$(id kasm -g)
POSTGRES_UID=70
POSTGRES_GID=70
KASM_PID_LIMIT=1000

# Colours
CMD='\e[0;34m'
CMDB='\e[1;34m'
DBG='\e[2;30m'
WRN='\e[0;33m'
ERR='\e[0;31m'
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

#ip check
read -rp "Please verify that ${PRI_IP} is the IP address that docker should bind to (y/n)? " choice
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
    # Check for existing yq installs in PATH
    if which yq; then
        YQ_BIN=$(which yq)
        echo -e "Using host-provided yq binary from ${YQ_BIN} - $(${YQ_BIN} --version)\nIf you experience issues please ensure it is up to date"
    else
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
fi

# Pretty logging
log_success() {
    printf %b "$1, ${OK}PASS${NC}, $2\n"
}

log_failure() {
    printf %b "$1, ${ERR}FAIL${NC}, $2\n"
}

log_na() {
    printf %b "$1, ${CMD}N/A${NC}, $2\n"
}

log_manual() {
    printf %b "$1, ${WRN}MANUAL${NC}, $2\n"
}

# Set cpu and memory limitations for service containers V-235807, V-235806
if ! "${YQ_BIN}" -e '.services[].mem_limit' ${KASM_COMPOSE_PROJECT} &>/dev/null; then
    for service in $("${YQ_BIN}" '.services | keys | .[]' ${KASM_COMPOSE_PROJECT}); do
        if [[ "${service}" =~ db ]]; then
            "${YQ_BIN}" -i ".services.${service}.cpus = ${NUM_CPUS}" ${KASM_COMPOSE_PROJECT}
            "${YQ_BIN}" -i ".services.${service}.mem_limit = \"${MEMORY}G\"" ${KASM_COMPOSE_PROJECT}
        else
            if [[ "${CPU_LIMIT}" -gt "${NUM_CPUS}" ]]; then
                "${YQ_BIN}" -i ".services.${service}.cpus = ${NUM_CPUS}" ${KASM_COMPOSE_PROJECT}
                "${YQ_BIN}" -i ".services.${service}.mem_limit = \"2G\"" ${KASM_COMPOSE_PROJECT}
            else
                "${YQ_BIN}" -i ".services.${service}.cpus = ${CPU_LIMIT}" ${KASM_COMPOSE_PROJECT}
                "${YQ_BIN}" -i ".services.${service}.mem_limit = \"2G\"" ${KASM_COMPOSE_PROJECT}
            fi
        fi
    done
    log_success "V-235806" "Memory limits have been set"
    log_success "V-235807" "CPU limits have been set"
else
    log_success "V-235806" "Using existing Memory limits"
    log_success "V-235807" "Using existing CPU limits"
fi
if [[ -n "${SHOW_ARTIFACT}" ]]; then
    echo "Command: ${YQ_BIN} -e '.services.[] | \"\(.container_name) - mem_limit: \(.mem_limit) - cpus: \(.cpus)\"' ${KASM_COMPOSE_PROJECT}"
    echo "Output: $("${YQ_BIN}" -e '.services.[] | "\(.container_name) - mem_limit: \(.mem_limit) - cpus: \(.cpus)"' ${KASM_COMPOSE_PROJECT} )"
fi

# Set restart policy for service containers V-235843
if "${YQ_BIN}" -e '.services.[].restart' ${KASM_COMPOSE_PROJECT} &>/dev/null && [[ $("${YQ_BIN}" -e '[.services[].restart == "on-failure:5" | select(. == true)] | length' ${KASM_COMPOSE_PROJECT}) -eq $("${YQ_BIN}" -e '.services | length' ${KASM_COMPOSE_PROJECT}) ]]; then
    log_success "V-235843" "Restart limits are set on all containers"
else
    "${YQ_BIN}" -i '.services[].restart = "on-failure:5"' ${KASM_COMPOSE_PROJECT}
    # adding a manual delay of 60 sec on rdpgw https for single-server deploys, since it requires healthy manager
    if "${YQ_BIN}" -e '.services.kasm_rdp_https_gateway' ${KASM_COMPOSE_PROJECT} &>/dev/null && "${YQ_BIN}" -e '.services.kasm_manager' ${KASM_COMPOSE_PROJECT} &>/dev/null; then
        "${YQ_BIN}" -i '.services.kasm_rdp_https_gateway.entrypoint = ["/bin/sh","-c","sleep 60 && exec /opt/rdpgw/rdpgw"]' ${KASM_COMPOSE_PROJECT}
    fi
    log_success "V-235843" "Using existing Restart limits"
fi
if [[ -n "${SHOW_ARTIFACT}" ]]; then
    echo "Command: ${YQ_BIN} -e '.services.[] | \"\(.container_name) - restart: \(.restart)\"' ${KASM_COMPOSE_PROJECT}"
    echo "Output: $( "${YQ_BIN}" -e '.services.[] | "\(.container_name) - restart: \(.restart)"' ${KASM_COMPOSE_PROJECT})"
fi

# Set no new privileges for all containers V-235816
if "${YQ_BIN}" -e '.services.[].security_opt' ${KASM_COMPOSE_PROJECT} &>/dev/null && [[ $("${YQ_BIN}" '[.services.[].security_opt.[] == "no-new-privileges" | select(. == true)] | length' ${KASM_COMPOSE_PROJECT}) -eq $("${YQ_BIN}" -e '.services | length' ${KASM_COMPOSE_PROJECT}) ]]; then
    log_success "V-235816" "security-opt no-new-privileges is set for all containers"
else
    "${YQ_BIN}" -i '.services.[].security_opt |= (. + ["no-new-privileges"] | unique)' ${KASM_COMPOSE_PROJECT}
    log_success "V-235816" "security-opt no-new-privileges has been set for all containers"
fi
if [[ -n "${SHOW_ARTIFACT}" ]]; then
    echo "Command: ${YQ_BIN} -e '.services.[] | \"\(.container_name) - security_opt: \(.security_opt.[])\"' ${KASM_COMPOSE_PROJECT}"
    echo "Output: $("${YQ_BIN}" -e '.services.[] | "\(.container_name) - security_opt: \(.security_opt.[])"' ${KASM_COMPOSE_PROJECT})"
fi

# Bind proxy ports to host interface V-235820
if "${YQ_BIN}" -e '.services.proxy' ${KASM_COMPOSE_PROJECT} &>/dev/null; then
    if ! [[ "$("${YQ_BIN}" -e '.services.proxy.ports[0]' ${KASM_COMPOSE_PROJECT})" == *"${PRI_IP}"*  ]]; then
        PORTS="$("${YQ_BIN}" -e '.services.proxy.ports[0]' ${KASM_COMPOSE_PROJECT} | grep -Po '\d+:\d+$')"
        "${YQ_BIN}" -i ".services.proxy.ports[0] = \"${PRI_IP}:${PORTS}\"" ${KASM_COMPOSE_PROJECT}
        log_success "V-235820" "Incoming container traffic has been bound to ${PRI_IP}"
    else
        log_success "V-235820" "Incoming container traffic is bound to ${PRI_IP}"
    fi
fi
if [[ -n "${SHOW_ARTIFACT}" ]]; then
    echo "Command: ${YQ_BIN} -e '.services.proxy | \"\(.container_name) - ports: \(.ports[])\"' ${KASM_COMPOSE_PROJECT}"
    echo "Output: $("${YQ_BIN}" -e '.services.proxy | "\(.container_name) - ports: \(.ports[])"' ${KASM_COMPOSE_PROJECT})"
fi

# Set pid limits for all containers V-235828
if "${YQ_BIN}" -e '.services.[].pids_limit' ${KASM_COMPOSE_PROJECT} &>/dev/null && [[ $("${YQ_BIN}" '[.services.[].pids_limit == "'${KASM_PID_LIMIT}'"] | select(. == true) | length' ${KASM_COMPOSE_PROJECT}) -eq $("${YQ_BIN}" -e '.services | length' ${KASM_COMPOSE_PROJECT}) ]]; then
    log_success "V-235828" "Using existing pid limit"
else
    "${YQ_BIN}" -i '.services.[] += {"pids_limit": '${KASM_PID_LIMIT}'}' ${KASM_COMPOSE_PROJECT}
    log_success "V-235828" "pid limit has been set for all containers"
fi
if [[ -n "${SHOW_ARTIFACT}" ]]; then
    echo "Command: ${YQ_BIN} -e '.services.[] | \"\(.container_name) - pids_limit: \(.pids_limit)\"' ${KASM_COMPOSE_PROJECT}"
    echo "Output: $("${YQ_BIN}" -e '.services.[] | "\(.container_name) - pids_limit: \(.pids_limit)"' ${KASM_COMPOSE_PROJECT})"
fi

# Setup docker daemon to use TCP and modify agent V-235818
if "${YQ_BIN}" -e '.services.kasm_agent' ${KASM_COMPOSE_PROJECT} &>/dev/null && ! "${YQ_BIN}" -e '.services.kasm_agent.environment.DOCKER_HOST == "tcp://'"${PRI_IP}"':2375"' ${KASM_COMPOSE_PROJECT} &> /dev/null; then
    # Cert management
    CERT_TMPDIR=$(mktemp -d)
    cd "${CERT_TMPDIR}"
    SUBJECT="/C=US/ST=VA/L=City/O=Kasm/OU=Kasm Server/CN=$(hostname)"
    openssl genrsa -out ca-key.pem 4096
    openssl req -new -x509 -days 3650 -key ca-key.pem -out ca.pem -subj "${SUBJECT}"
    openssl req -new -nodes -out server.csr -keyout server-key.pem -subj "${SUBJECT}"
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
    rm -Rf "${CERT_TMPDIR}"
    # Docker modifications
    jq '. *= { "hosts": ["tcp://'"${PRI_IP}"':2375", "unix:///var/run/docker.sock"], "tlscacert": "/etc/docker/certs/ca.pem", "tlscert": "/etc/docker/certs/server-cert.pem", "tlskey": "/etc/docker/certs/server-key.pem", "tlsverify": true }' /etc/docker/daemon.json > /tmp/daemon.json.tmp && cp /tmp/daemon.json.tmp /etc/docker/daemon.json && rm /tmp/daemon.json.tmp
    if [[ ! -f /etc/systemd/system/docker.service.d/override.conf ]]; then
    mkdir -p /etc/systemd/system/docker.service.d/
    cat >/etc/systemd/system/docker.service.d/override.conf <<EOL
[Service]
ExecStart=
ExecStart=/usr/bin/dockerd --containerd=/run/containerd/containerd.sock
EOL
    elif [[ -f /etc/systemd/system/docker.service.d/override.conf ]] && grep -q '\[Service\]' "/etc/systemd/system/docker.service.d/override.conf"; then
        sed -i '/\[Service\]/a ExecStart=\nExecStart=/usr/bin/dockerd --containerd=/run/containerd/containerd.sock' /etc/systemd/system/docker.service.d/override.conf
    else
        echo -e '[Service]\nExecStart=\nExecStart=/usr/bin/dockerd --containerd=/run/containerd/containerd.sock' >> /etc/systemd/system/docker.service.d/override.conf
    fi
    systemctl daemon-reload
    systemctl restart docker
    # Agent modifications
    "${YQ_BIN}" -i 'del(.services.kasm_agent.volumes[]| select(. == "/var/run/docker.sock:/var/run/docker.sock")) | .services.kasm_agent *= { "environment": {"DOCKER_HOST": "tcp://'"${PRI_IP}"':2375", "DOCKER_CERT_PATH": "/opt/kasm/current/certs/docker", "DOCKER_TLS_VERIFY": "1"}}' ${KASM_COMPOSE_PROJECT}
    log_success "V-235818" "This host and agent have been configured to use docker over tcp with TLS auth"
elif "${YQ_BIN}" -e '.services.kasm_agent' ${KASM_COMPOSE_PROJECT} &>/dev/null && "${YQ_BIN}" -e '.services.kasm_agent.environment.DOCKER_HOST == "tcp://'"${PRI_IP}"':2375"' ${KASM_COMPOSE_PROJECT} &> /dev/null; then
    log_success "V-235818" "This host and agent are configured to use docker over tcp with TLS auth"
else
    log_success "V-235818" "This host does not have the agent service"
fi
if [[ -n "${SHOW_ARTIFACT}" ]]; then
    echo "Command: ${YQ_BIN} -e '.services.kasm_agent' ${KASM_COMPOSE_PROJECT}"
    echo "Output: $("${YQ_BIN}" -e '.services.kasm_agent' ${KASM_COMPOSE_PROJECT})"
fi

if "${YQ_BIN}" -e '.services.kasm_agent' ${KASM_COMPOSE_PROJECT} &>/dev/null; then
    DOCKER_SSL_CERT=/etc/docker/certs/server-cert.pem
    DOCKER_SSL_KEY=/etc/docker/certs/server-key.pem
    DOCKER_SSL_CA=/etc/docker/certs/ca.pem
    if [[ -f "${DOCKER_SSL_CERT}" ]]; then
        chown root:root ${DOCKER_SSL_CERT}
        log_success "V-235861" "${DOCKER_SSL_CERT} is owned by root:root"
        if [[ -n "${SHOW_ARTIFACT}" ]]; then
            echo "Command: stat -c %U:%G ${DOCKER_SSL_CERT} "
            echo "Output: $(stat -c %U:%G ${DOCKER_SSL_CERT})"
        fi
    else
        log_na "V-235861" "SSL cert does not exist on this host"
    fi

    if [[ -f "$DOCKER_SSL_KEY" ]]; then
        chmod 400 ${DOCKER_SSL_KEY}
        log_success "V-235864" "${DOCKER_SSL_KEY} permissions set to 0400"
        if [[ -n "${SHOW_ARTIFACT}" ]]; then
            echo "Command: stat -c %U:%G ${DOCKER_SSL_KEY} "
            echo "Output: $(stat -c %U:%G ${DOCKER_SSL_KEY})"
        fi
    else
        log_na "V-235864" "SSL key does not exist on this host"
    fi

    if [[ -f "$DOCKER_SSL_CA" ]]; then
        chown root:root ${DOCKER_SSL_CA}
        log_success "V-235859" "${DOCKER_SSL_CA} owned by root:root"
        if [[ -n "${SHOW_ARTIFACT}" ]]; then
            echo "Command: stat -c %U:%G ${DOCKER_SSL_CA} "
            echo "Output: $(stat -c %U:%G ${DOCKER_SSL_CA})"
        fi
    else
        log_na "V-235859" "SSL CA does not exist on this host"
    fi
    chown -R kasm:kasm "/opt/kasm/current/certs/docker"
    log_success "V-235859" "Client certs are owned by kasm user"
    if [[ -n "${SHOW_ARTIFACT}" ]]; then
        echo "Command: stat -c %U:%G '/opt/kasm/current/certs/docker' "
        echo "Output: $(stat -c %U:%G '/opt/kasm/current/certs/docker')"
    fi
fi

### RO containers V-235808

# Agent changes
if "${YQ_BIN}" -e '.services.kasm_agent' ${KASM_COMPOSE_PROJECT} &>/dev/null; then
    if "${YQ_BIN}" -e '.services.kasm_agent.read_only' ${KASM_COMPOSE_PROJECT} &>/dev/null; then
        log_success "V-235808" "kasm_agent is read only"
        if [[ -n "${SHOW_ARTIFACT}" ]]; then
            echo "Command: ${YQ_BIN} -e '.services.kasm_agent.read_only' ${KASM_COMPOSE_PROJECT}"
            echo "Output: $( "${YQ_BIN}" -e '.services.kasm_agent.read_only' ${KASM_COMPOSE_PROJECT})"
        fi
    else
        log_failure "V-235808" "kasm_agent is not read only"
    fi
else
    log_na "V-235808" "This host does not have the agent service"
fi

# Proxy changes
if "${YQ_BIN}" -e '.services.proxy' ${KASM_COMPOSE_PROJECT} &>/dev/null; then
    if "${YQ_BIN}" -e '.services.proxy.read_only' ${KASM_COMPOSE_PROJECT} &>/dev/null; then
        log_success "V-235808" "proxy is already read only"
    else
        mkdir -p /opt/kasm/current/cache/nginx
        chown -R kasm:kasm /opt/kasm/current/cache
        "${YQ_BIN}" -i '.services.proxy.volumes |= (. + "/opt/kasm/current/cache/nginx:/var/cache/nginx" | unique) | .services.proxy += {"read_only": true} | .services.proxy += {"tmpfs": ["/var/run:uid='"${KASM_UID}"',gid='"${KASM_GID}"'"]}' ${KASM_COMPOSE_PROJECT}
        log_success "V-235808" "proxy is now read only"
    fi
    if [[ -n "${SHOW_ARTIFACT}" ]]; then
        echo "Command: ${YQ_BIN} -e '.services.proxy.read_only' ${KASM_COMPOSE_PROJECT}"
        echo "Output: $( "${YQ_BIN}" -e '.services.proxy.read_only' ${KASM_COMPOSE_PROJECT})"
    fi
else
    log_na "V-235808" "This host does not have the proxy service"
fi

# API changes
if "${YQ_BIN}" -e '.services.kasm_api' ${KASM_COMPOSE_PROJECT} &>/dev/null; then
    if "${YQ_BIN}" -e '.services.kasm_api.read_only' ${KASM_COMPOSE_PROJECT} &>/dev/null; then
        log_success "V-235808" "kasm_api is read only"
        if [[ -n "${SHOW_ARTIFACT}" ]]; then
            echo "Command: ${YQ_BIN} -e '.services.kasm_api.read_only' ${KASM_COMPOSE_PROJECT}"
            echo "Output: $( "${YQ_BIN}" -e '.services.kasm_api.read_only' ${KASM_COMPOSE_PROJECT})"
        fi
    else
        log_failure "V-235808" "kasm_api is not read only"
    fi
else
    log_na "V-235808" "This host does not have the api service"
fi

# Manager Changes
if "${YQ_BIN}" -e '.services.kasm_manager' ${KASM_COMPOSE_PROJECT} &>/dev/null; then
    if "${YQ_BIN}" -e '.services.kasm_manager.read_only' ${KASM_COMPOSE_PROJECT} &>/dev/null; then
        log_success "V-235808" "kasm_manager is read only"
        if [[ -n "${SHOW_ARTIFACT}" ]]; then
            echo "Command: ${YQ_BIN} -e '.services.kasm_manager.read_only' ${KASM_COMPOSE_PROJECT}"
            echo "Output: $("${YQ_BIN}" -e '.services.kasm_manager.read_only' ${KASM_COMPOSE_PROJECT})"
        fi
    else
        log_failure "V-235808" "kasm_manager is not read only"
    fi
else
    log_na "V-235808" "This host does not have the manager service"
fi

# Database changes
if "${YQ_BIN}" -e '.services.db' ${KASM_COMPOSE_PROJECT} &>/dev/null; then
    if "${YQ_BIN}" -e '.services.db.tmpfs[] | select(. == "/var/run:uid='${POSTGRES_UID}',gid='${POSTGRES_GID}'")' ${KASM_COMPOSE_PROJECT} &>/dev/null && "${YQ_BIN}" -e '.services.db.read_only' ${KASM_COMPOSE_PROJECT} &>/dev/null; then
        log_success "V-235808" "kasm_db is already read only"
    else
        mkdir -p /opt/kasm/current/tmp/kasm_db/
        "${YQ_BIN}" -i '.services.db |= (. + {"tmpfs": ["/var/run:uid='${POSTGRES_UID}',gid='${POSTGRES_GID}'"] | unique}) | .services.db += {"read_only": true}' ${KASM_COMPOSE_PROJECT}
        log_success "V-235808" "kasm_db is now read only"
    fi
    if [[ -n "${SHOW_ARTIFACT}" ]]; then
        echo "Command: ${YQ_BIN} -e '.services.db.read_only' ${KASM_COMPOSE_PROJECT}"
        echo "Output: $("${YQ_BIN}" -e '.services.db.read_only' ${KASM_COMPOSE_PROJECT})"
    fi
else
    log_na "V-235808" "This host does not have the database service"
fi

# rdp_gateway changes
if "${YQ_BIN}" -e '.services.rdp_gateway' ${KASM_COMPOSE_PROJECT} &>/dev/null; then
    if "${YQ_BIN}" -e '.services.rdp_gateway.read_only' ${KASM_COMPOSE_PROJECT} &>/dev/null; then
        log_success "V-235808" "rdp_gateway is read only"
        if [[ -n "${SHOW_ARTIFACT}" ]]; then
            echo "Command: ${YQ_BIN} -e '.services.rdp_gateway.read_only' ${KASM_COMPOSE_PROJECT}"
            echo "Output: $("${YQ_BIN}" -e '.services.rdp_gateway.read_only' ${KASM_COMPOSE_PROJECT})"
        fi
    else
        log_failure "V-235808" "rdp_gateway is not read only"
    fi
else
    log_na "V-235808" "This host does not have the rdp gateway service"
fi

# kasm_rdp_https_gateway changes
if "${YQ_BIN}" -e '.services.kasm_rdp_https_gateway' ${KASM_COMPOSE_PROJECT} &>/dev/null; then
    if "${YQ_BIN}" -e '.services.kasm_rdp_https_gateway.read_only' ${KASM_COMPOSE_PROJECT} &>/dev/null; then
        log_success "V-235808" "kasm_rdp_https_gateway is read only"
        if [[ -n "${SHOW_ARTIFACT}" ]]; then
            echo "Command: ${YQ_BIN} -e '.services.kasm_rdp_https_gateway.read_only' ${KASM_COMPOSE_PROJECT}"
            echo "Output: $("${YQ_BIN}" -e '.services.kasm_rdp_https_gateway.read_only' ${KASM_COMPOSE_PROJECT})"
        fi
    else
        log_failure "V-235808" "kasm_rdp_https_gateway is not read only"
    fi
else
    log_na "V-235808" "This host does not have the rdp https gateway service"
fi

# guac changes
if "${YQ_BIN}" -e '.services.kasm_guac' ${KASM_COMPOSE_PROJECT} &>/dev/null; then
    if "${YQ_BIN}" -e '.services.kasm_guac.read_only' ${KASM_COMPOSE_PROJECT} &>/dev/null; then
        log_success "V-235808" "kasm_guac is read only"
        if [[ -n "${SHOW_ARTIFACT}" ]]; then
            echo "Command: ${YQ_BIN} -e '.services.kasm_guac.read_only' ${KASM_COMPOSE_PROJECT}"
            echo "Output: $("${YQ_BIN}" -e '.services.kasm_guac.read_only' ${KASM_COMPOSE_PROJECT})"
        fi
    else
        log_failure "V-235808" "kasm_guac is not read only"
    fi
else
    log_na "V-235808" "This host does not have the guac service"
fi

# Show output of all containers for v-235808
if [[ -n "${SHOW_ARTIFACT}" ]]; then
    echo "Command: ${YQ_BIN} '.services.[] | \"\(.container_name) - read_only: \(.read_only)\"' ${KASM_COMPOSE_PROJECT}"
    echo "Output: $("${YQ_BIN}" '.services.[] | "\(.container_name) - read_only: \(.read_only)"' ${KASM_COMPOSE_PROJECT})"
fi

# proxy health check
if "${YQ_BIN}" -e '.services.proxy' "${KASM_COMPOSE_PROJECT}" &>/dev/null; then
    if ! "${YQ_BIN}" -e '.services.proxy' "${KASM_COMPOSE_PROJECT}" | grep --quiet healthcheck; then
        "${YQ_BIN}" -i '.services.proxy += {"healthcheck": { "test": "nginx -t", "timeout": "2s", "retries": 5 }}' "${KASM_COMPOSE_PROJECT}"
        echo "${OK}Configured healthcheck for proxy container${NC}"
    fi
fi

# Force user mode on all containers V-235830
# All supported kernels now allow this change
# (making the assumption no other port under 1024 is likely to be mapped)
CONTAINERS_TO_CHANGE=('proxy' 'kasm_agent' 'db')
# kasm_api, kasm_guac, kasm_manager, kasm_rdp_gateway, kasm_rdp_https_gateway all pass this check without any modification.
for container in "${CONTAINERS_TO_CHANGE[@]}"; do
    if [[ ${container} == 'db' ]] && "${YQ_BIN}" -e '.services.'"${container}"'' ${KASM_COMPOSE_PROJECT} &>/dev/null; then
        if ! "${YQ_BIN}" -e '.services.db.user | (. == "'${POSTGRES_UID}:${POSTGRES_GID}'")' ${KASM_COMPOSE_PROJECT} &>/dev/null; then
            "${YQ_BIN}" -i '.services.db.user = "'${POSTGRES_UID}:${POSTGRES_GID}'"' ${KASM_COMPOSE_PROJECT}
        fi
        mkdir -p /opt/kasm/current/tmp/kasm_db/
        chown -R ${POSTGRES_UID}:${POSTGRES_GID} /opt/kasm/current/tmp/kasm_db/
        if "${YQ_BIN}" -e '.services.db.volumes.[] | select(. == "/opt/kasm/'"${KASM_VERSION}"'/conf/database/:/tmp/")' ${KASM_COMPOSE_PROJECT} &>/dev/null; then
            "${YQ_BIN}" -i 'del(.services.db.volumes[] | select(. == "/opt/kasm/'"${KASM_VERSION}"'/conf/database/:/tmp/")) | .services.db.volumes += "/opt/kasm/'"${KASM_VERSION}"'/tmp/kasm_db/:/tmp/"' ${KASM_COMPOSE_PROJECT}
        else
            if ! "${YQ_BIN}" -e '.services.db.volumes.[] | select(. == "/opt/kasm/'"${KASM_VERSION}"'/tmp/kasm_db/:/tmp/")' ${KASM_COMPOSE_PROJECT} &>/dev/null; then
                log_failure "V-235830" "couldn't find tmp volume to update for the database container"
                continue
            fi
        fi
        log_success "V-235830" "db service set to run as postgresql user 70"
    else
        if "${YQ_BIN}" -e '.services.'"${container}"'' ${KASM_COMPOSE_PROJECT} &>/dev/null; then
            USEROUT=$("${YQ_BIN}" '.services.'"${container}"'.user' ${KASM_COMPOSE_PROJECT})
            # shellcheck disable=SC2016
            if [[ ! "${USEROUT}" == *'${KASM_UID?}:${KASM_GID?}'* ]]; then
                "${YQ_BIN}" -i '.services.'"${container}"'.user = "${KASM_UID?}:${KASM_GID?}"' ${KASM_COMPOSE_PROJECT}
                if [[ ${container} == 'proxy' ]]; then
                    chown -R kasm:kasm /opt/kasm/current/log/nginx
                    chown -R kasm:kasm /opt/kasm/current/certs/kasm_nginx*
                elif [[ ${container} == 'kasm_agent' ]]; then
                    chown -R kasm:kasm /opt/kasm/current/log/agent*
                    chown -R kasm:kasm /opt/kasm/current/file_mappings*
                    chown -R kasm:kasm /opt/kasm/current/conf/app
                fi
                log_success "V-235830" "${container} service has been set to run as kasm user ${KASM_UID}"
            else
                log_success "V-235830" "${container} service is set to run as kasm user ${KASM_UID}"
            fi
        fi
    fi
done
if [[ -n "${SHOW_ARTIFACT}" ]]; then
    echo "Command: ${YQ_BIN} '.services.[] | \"\(.container_name) - user: \(.user)\"' ${KASM_COMPOSE_PROJECT}"
    echo "Output: $("${YQ_BIN}" '.services.[] | "\(.container_name) - user: \(.user)"' ${KASM_COMPOSE_PROJECT})"
fi

echo "Restarting containers where needed with new compose changes"
/opt/kasm/bin/start

#### Make sure containers are running with a health check
export KASM_UID
export KASM_GID
for container_id in $(docker compose --project-directory /opt/kasm/current/docker/ ps -q  2>/dev/null); do
    container_name=$(docker inspect "${container_id}" --format '{{.Name}}' | sed 's/\///')
    if docker inspect "${container_id}" --format '{{ .State.Health.Status }}' &>/dev/null; then
        log_success "V-235827" "${container_name} has health check"
    else
        log_failure "V-235827" "${container_name} is missing health check"
    fi
done
if [[ -n "${SHOW_ARTIFACT}" ]]; then
    echo "Command:  docker ps | grep -viP '(\(health|CONTAINER ID)' "
    echo "Output: $(docker ps | grep -viP '(\(health|CONTAINER ID)')"
fi

echo -e "${OK}Kasm stig application complete${NC}"
