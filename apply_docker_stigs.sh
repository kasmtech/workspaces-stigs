
#!/bin/bash
set -e
#set -x

jqi() {
  cat <<< "$(jq "$1" < "$2")" > "$2"
}


CON_RED='\033[0;31m'
CON_GREEN='\033[0;32m'
CON_ORANGE='\033[0;33m'
CON_NC='\033[0m' # No Color

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

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

DOCKER_DAEMON_JSON_PATH=/etc/docker/daemon.json
DOCKER_SOCK_PATH=/run/containerd/containerd.sock
DOCKER_LEGACY_CONF=/etc/default/docker
DEFAULT_DOCKER_PATH=/var/lib/docker
ETC_DOCKER_PATH=/etc/docker/
DOCKER_SOCKET_PATH=/lib/systemd/system/docker.socket
DOCKER_SERVICE_PATH=/lib/systemd/system/docker.service
PRI_INTERFACE=$(ip route | grep -m 1 'default via' | grep -Po '(?<=dev )\S+')
PRI_IP=$(ip -f inet addr show "$PRI_INTERFACE" | grep -Po '(?<=inet )(\d{1,3}\.)+\d{1,3}')

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

if [ ! -f "$DOCKER_DAEMON_JSON_PATH" ] ; then
	echo "$DOCKER_DAEMON_JSON_PATH does not exist, creating"
	echo "{}" > $DOCKER_DAEMON_JSON_PATH
else
    cp $DOCKER_DAEMON_JSON_PATH ${DOCKER_DAEMON_JSON_PATH}.bak
	echo "A backup of the docker daemon configuration has been placed at ${DOCKER_DAEMON_JSON_PATH}.bak"
fi

if [ ! -S "$DOCKER_SOCK_PATH" ] ; then
	echo "ERROR: Docker sock at $DOCKER_SOCK_PATH does not exist, exiting"
	exit 1
fi

chown root:root $DOCKER_DAEMON_JSON_PATH
log_succes "V-235867" "set daemon.json ownership to root:root"

chmod 0644 $DOCKER_DAEMON_JSON_PATH
log_succes "V-235868" "set daemon.json permissions to 644"

chmod 0660 $DOCKER_SOCK_PATH
log_succes "V-235866" "Set docker sock permission to 660"

chown root:docker $DOCKER_SOCK_PATH
log_succes "V-235865" "Set docker sock ownership to root:docker"

if [ ! -f "$DOCKER_LEGACY_CONF" ] ; then
    log_na 'V-235869' 'Legacy Docker configuration file not present.'
	log_na "V-235870" "Legacy Docker configuration file not present."
else
	chown root:root $DOCKER_LEGACY_CONF
	log_succes 'V-235869' 'Set ownership of legacy docker conf file to root:root.'
	chmod 0644 $DOCKER_LEGACY_CONF
	log_succes "V-235870" "Set $DEFAULT_DOCKER_PATH permissions to 644"
fi

chown root:root $ETC_DOCKER_PATH
log_succes "V-235855" "Set $ETC_DOCKER_PATH ownership to root:root"

chmod 755 $ETC_DOCKER_PATH
log_succes "V-235856" "Set $ETC_DOCKER_PATH permissions to 755"

chown root:root $DOCKER_SOCKET_PATH
log_succes "V-235853" "Set docker.socket file ownership to root:root"

chmod 0644 $DOCKER_SOCKET_PATH
log_succes "V-235854" "Set docker.socket file permissions to 644"

chown root:root $DOCKER_SERVICE_PATH
log_succes "V-235851" "Set docker.service file ownership to root:root"

chmod 0644 $DOCKER_SERVICE_PATH
log_succes "V-235852" "Set docker.service file permissions to 0644"

if docker ps --all | grep -iv "ucp\|kube\|dtr" | awk '{print $1}' | xargs docker inspect --format '{{ .Id }}: SecurityOpt={{ .HostConfig.SecurityOpt }}' 2>/dev/null | grep -i --quiet unconfined ; then
	log_failure "V-235812" "found container with seccomp unconfined."
else
	log_succes "V-235812" "no seccomp unconfined containers found"
fi


if docker ps --quiet --all | xargs --no-run-if-empty -- docker inspect --format '{{ .Id }}: Ulimits={{ .HostConfig.Ulimits }}' 2>/dev/null | grep -v "no value" ; then
    log_failure "V-235844" "container overrides ulimit"
else
	log_succes "V-235844" "no containers override default ulimit"
fi

# can be configured as docker daemon argument
if ps -ef | grep dockerd | grep --quiet 'insecure-registry'; then
  log_failure "V-235789" "insecure Registries are configured."
else
  log_succes "V-235789" "no insecure Registries configured."
fi
# can be configured in daemon.json
if grep --quiet 'insecure-registry' /etc/docker/daemon.json ; then
  log_failure "V-235789" "insecure Registries are configured."
else
  log_succes "V-235789" "no insecure Registries configured."
fi

if docker ps --all | grep -iv "ucp\|kube\|dtr" | awk '{print $1}' | xargs docker inspect --format '{{ .Id }}: PidMode={{ .HostConfig.PidMode }}' 2>/dev/null | grep -i pidmode=host ; then
  log_failure 'V-235784' 'containers present running with host PID namespace'
else
  log_succes 'V-235784' 'no containers running with host PID namespace detected'
fi

if docker ps --all | grep -iv "ucp\|kube\|dtr" | awk '{print $1}' | xargs docker inspect --format '{{ .Id }}: IpcMode={{ .HostConfig.IpcMode }}' 2>/dev/null | grep -i ipcmode=host ; then
  log_failure 'V-235785' 'containers present running with host IPC namespace'
else
  log_succes 'V-235785' 'no containers running with host IPC namespace detected'
fi

# can be configured as docker daemon argument
if ps -ef | grep dockerd | grep --quiet 'userland-proxy'; then
  log_failure "V-235791" "Remove userland-proxy flag from docker service arguments, use /etc/docker/daemon.json."
fi
# can be configured in daemon.json
if grep --quiet -Pi '"userland-proxy"\s*:\s*false' /etc/docker/daemon.json ; then
  log_succes "V-235791" "userland-proxy is disabled."
else
  if which jq ; then
    cat <<< $(sudo jq '. |= . + {"userland-proxy": false}' /etc/docker/daemon.json) > /etc/docker/daemon.json
    log_succes "V-235791" "userland-proxy has been disabled by this script, be sure to restart the docker service."
  else
    log_failure "V-235791" "userland-proxy is not explicitly disabled, unable to fix, jq package not installed."
	echo "	TIP: add '\"userland-proxy\": false' to /etc/docker/daemon.json and restart the docker service"
  fi
fi

if grep --quiet -Pi '"ip"\s*:\s*"[^0]' /etc/docker/daemon.json ; then
  log_succes "V-235820" "Docker is configured to listen on specific IP address."
else
  if which jq ; then
    if grep '"ip"' /etc/docker/daemon.json ; then
      log_failure 'V-235820' '/etc/docker/daemon.json configured with IP set to 0.0.0.0, manually fix and rerun'
    else
      cat <<< $(sudo jq ". |= . + {\"ip\": \"$PRI_IP\"}" /etc/docker/daemon.json) > /etc/docker/daemon.json
      log_succes "V-235820" "docker has been bound to $PRI_IP, be sure to restart the docker service."
	fi
  else
    log_failure "V-235820" "docker is not configured to bind to specific interface, unable to fix, jq package not installed."
	echo "	TIP: add '\"ip\": \"192.168.1.10\"' to /etc/docker/daemon.json, replace the IP address with the system's IP and restart the docker service"
  fi
fi

if docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: AppArmorProfile={{ .AppArmorProfile }}' | grep -i "AppArmorProfile=unconfined" ; then
  log_failure 'V-235799' 'containers present running without apparmor'
else
  log_succes 'V-235799' 'all containers running with apparmor profiles'
fi

docker ps -q | xargs docker inspect --format '{{ .Id }}: {{ .Name }}: Ports={{ .NetworkSettings.Ports }}' | grep HostPort
log_manual 'V-235837' 'review above ports and ensure they are in the SSP, look at the HostPort field.'

docker ps --quiet | xargs docker inspect --format '{{ .Id }}: Ports={{ .NetworkSettings.Ports }}' | grep -i host
log_manual 'V-235804' 'review above ports and ensure they are in the SSP, look at the HostPort field.'

if which ausearch ; then
  if sudo ausearch -k docker | grep exec | grep --quiet privileged ; then
    log_failure 'V-235813' 'there is an exec session running with privileged flag'
  else
    log_succes 'V-235813' 'no exec sessions with privilged flag found'
  fi
else
  log_failure 'V-235813' 'ausearch package not installed not able to assess. This implies auditd is not installed.'
fi

if docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: UsernsMode={{ .HostConfig.UsernsMode }}' | grep --quiet -i "UsernsMode=host" ; then
  log_failure 'V-235817' 'containers present sharing host user namespace'
else
  log_succes 'V-235817' 'no containers running sharing host user namespace detected'
fi

LOW_HOST_PORT=$(docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: Ports={{ .NetworkSettings.Ports }}' | grep -Pio '(?<=HostPort:)\d+' | sort -n | head -n 1)
if [ "$LOW_HOST_PORT" -lt 1024 ] ; then 
    log_failure 'V-235819' 'host ports below 1024 are mapped into containers.'; 
else 
	log_succes 'V-235819' 'no host ports mapped below 1024'; 
fi

if docker ps --all | grep -iv "ucp\|kube\|dtr" | awk '{print $1}' | xargs docker inspect --format '{{ .Id }}: NetworkMode={{ .HostConfig.NetworkMode }}' 2>/dev/null | grep --quiet -i "NetworkMode=host" ; then
  log_failure 'V-235805' 'containers present sharing hosts network namespace'
else
  log_succes 'V-235805' 'no containers running sharing hosts netork namespace'
fi

if docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: Devices={{ .HostConfig.Devices }}' | grep --quiet -i 'pathincontainer' ; then
  log_failure 'V-235809' 'containers present with host devices passed in.'
else
  log_succes 'V-235809' 'no containers running with host devices passed in.'
fi 

if docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: Volumes={{ .Mounts }}' | grep -iv "ucp\|kubelet\|dtr" | grep -Po 'Source:\S+' | grep -P '\:(/|/boot|/dev|/etc|/lib|/proc|/sys|/usr)$' ; then
  log_failure 'V-235783' 'sensitive directories mapped into containers detected.'
else
  log_succes 'V-235783' 'no sensitive directories found mappend into containers'
fi 

if docker info | grep --quiet -e "^Storage Driver:\s*aufs\s*$" ; then
  log_failure 'V-235790' 'aufs file system detected.'
else
  log_succes 'V-235790' 'aufs file system not detected'
fi 

if docker ps --all | grep -iv "ucp\|kube\|dtr" | awk '{print $1}' | xargs docker inspect --format '{{ .Id }}: Propagation={{range $mnt := .Mounts}} {{json $mnt.Propagation}} {{end}}' 2>/dev/null | grep --quiet 'shared' ; then
  log_failure 'V-235810' 'mount progagation mode set to shared.'
else
  log_succes 'V-235810' 'no mounts set to shared propogation mode found'
fi 

if docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: UTSMode={{ .HostConfig.UTSMode }}' | grep -i '=host' ; then
  log_failure 'V-235811' 'host UTS namespace shared to container.'
else
  log_succes 'V-235811' 'no containers found with host UTC namespace shared'
fi

if ps aux | grep 'docker exec' | grep '\-\-user' ; then
  log_failure 'V-235814' 'there is an exec session running with user flag'
else
  log_succes 'V-235814' 'no exec sessions with user flag found'
fi

if docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: CgroupParent={{ .HostConfig.CgroupParent }}' | grep -P '=\w+' ; then
  log_failure 'V-235815' 'cgroup usage detected, must be manually checked.'
else
  log_succes 'V-235815' 'only default cgroups defined on running containers'
fi

if docker ps --quiet --all | grep -iv "ucp\|kube\|dtr" | awk '{print $1}' | xargs docker inspect --format '{{ .Id }}: Privileged={{ .HostConfig.Privileged }}' | grep true ; then
  log_failure 'V-235802' 'containers running as privileged.'
else
  log_succes 'V-235802' 'no containers found running as privileged'
fi

if which auditctl ; then
  if !(systemctl show -p FragmentPath docker.service or auditctl -l | grep docker.service) then
    log_failure 'V-235779' 'docker.service auditd rule missing'
  fi
  if !(systemctl show -p FragmentPath docker.socket or auditctl -l | grep docker.sock) then
    log_failure 'V-235779' 'docker.docket auditd rule missing'
  fi
  log_succes 'V-235779' 'Required auditd rules for docker are present'
else
  log_failure 'V-235779' 'auditd does not appear to be installed, which will result in many STIG findings'
fi

if docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: CapAdd={{ .HostConfig.CapAdd }} CapDrop={{ .HostConfig.CapDrop }}' | grep -v ': CapAdd=<no value> CapDrop=<no value>$' ; then
  log_failure 'V-235801' 'containers running with added capabilities, you will need to manually confirm with SSP.'
else
  log_succes 'V-235801' 'no containers found with additional capabilities passed in.'
fi

PASS=1
for i in $(docker ps -qa); do 
  if docker exec $i ps -el | grep -i sshd ; then
    log_failure 'V-235803' 'containers running sshd found.'
    PASS=0
  fi
done
if [ $PASS -eq 1 ] ; then
  log_succes 'V-235803' 'no containers running sshd found.'  
fi

if docker version --format '{{ .Server.Experimental }}' | grep --quiet false; then
        log_succes "V-235792" "Experimental features are disabled"
else
        log_failure "V-235792" "Experimental features are enabled"
fi

if jq -e '."log-driver" == "syslog"' /etc/docker/daemon.json | grep --quiet true; then
        log_succes "V-235831" "log driver is enabled"
else
        jqi '. + {"log-driver": "syslog"}' /etc/docker/daemon.json
        log_succes "V-235831" "log driver has been configured in script"
fi

if ! (grep --quiet "syslog-address" /etc/docker/daemon.json) ; then
	jqi '. + {"log-opts": {"syslog-address": "udp://127.0.0.1:25224", "tag": "container_name/{{.Name}}", "syslog-facility": "daemon" }}' /etc/docker/daemon.json
	log_succes "V-235833" "Script configured docker daemon remote syslog settings"
else
    log_succes "V-235833" "Remote syslog already configured"
fi