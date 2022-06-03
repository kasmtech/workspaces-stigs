
#!/bin/bash
set -e
#set -x

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
fi

if [ ! -S "$DOCKER_SOCK_PATH" ] ; then
	echo "ERROR: Docker sock at $DOCKER_SOCK_PATH does not exist, exiting"
	exit 1
fi

chown root:root $DOCKER_DAEMON_JSON_PATH
echo "V-235867 PASS, set daemon.json ownership to root:root"

chmod 0644 $DOCKER_DAEMON_JSON_PATH
echo "V-235868 PASS, set daemon.json permissions to 644"

chmod 0660 $DOCKER_SOCK_PATH
echo "V-235866 PASS, Set docker sock permission to 660"

chown root:docker $DOCKER_SOCK_PATH
echo "V-235865 PASS, Set docker sock ownership to root:docker"

if [ ! -f "$DOCKER_LEGACY_CONF" ] ; then
    echo 'V-235869 N/A, Legacy Docker configuration file not present.'
	echo "V-235870 N/A, Legacy Docker configuration file not present."
else
	chown root:root $DOCKER_LEGACY_CONF
	echo 'V-235869 PASS, Set ownership of legacy docker conf file to root:root.'
	chmod 0644 $DOCKER_LEGACY_CONF
	echo "V-235870 PASS, Set $DEFAULT_DOCKER_PATH permissions to 644"
fi

chown root:root $ETC_DOCKER_PATH
echo "V-235855 PASS, Set $ETC_DOCKER_PATH ownership to root:root"

chmod 755 $ETC_DOCKER_PATH
echo "V-235856 Set $ETC_DOCKER_PATH permissions to 755"

chown root:root $DOCKER_SOCKET_PATH
echo "V-235853 Set docker.socket file ownership to root:root"

chmod 0644 $DOCKER_SOCKET_PATH
echo "V-235854 Set docker.socket file permissions to 644"

chown root:root $DOCKER_SERVICE_PATH
echo "V-235851 Set docker.service file ownership to root:root"

chmod 0644 $DOCKER_SERVICE_PATH
echo "V-235852 Set docker.service file permissions to 0644"

echo "Checking V-235812"
set +e
docker ps --all | grep -iv "ucp\|kube\|dtr" | awk '{print $1}' | tail -n +2 | xargs --no-run-if-empty docker inspect --format '{{ .Id }}: SecurityOpt={{ .HostConfig.SecurityOpt }}' | grep unconfined
pipe_status=(${PIPESTATUS[@]})
set -e
inner_commands=(${pipe_status[@]:0:5})

# We want to make sure commands that produce output we grep for succeed so we
# are checking valid data
for rc in ${inner_commands[@]}; do
	if [ $rc -ne 0 ]; then
		echo "Inner command in V-235812 check failed, exiting"
		exit 1
	fi
done

if [ $grep_rc -eq 0 ]; then
	echo "V-235812 FAIL, found container with seccomp unconfined."
	exit 1
else
	echo "V-235812 PASS, no seccomp unconfined containers found"
fi


if docker ps --quiet --all | xargs --no-run-if-empty -- docker inspect --format '{{ .Id }}: Ulimits={{ .HostConfig.Ulimits }}' | grep -v "no value" ; then
    echo "V-235844 FAIL, container overrides ulimit"
	exit 1
else
	echo "V-235844 PASS, no containers override default ulimit"
fi

# can be configured as docker daemon argument
if ps -ef | grep dockerd | grep --quiet 'insecure-registry'; then
  echo "V-235789 FAIL, insecure Registries are configured."
  exit 1
else
  echo "V-235789 PASS, no insecure Registries configured."
fi
# can be configured in daemon.json
if grep --quiet 'insecure-registry' /etc/docker/daemon.json ; then
  echo "V-235789 FAIL, insecure Registries are configured."
  exit 1
else
  echo "V-235789 PASS, no insecure Registries configured."
fi

if docker ps --all | grep -iv "ucp\|kube\|dtr" | awk '{print $1}' | xargs docker inspect --format '{{ .Id }}: PidMode={{ .HostConfig.PidMode }}' | grep -i pidmode=host ; then
  echo 'V-235784 FAIL, containers present running with host PID namespace'
  exit 1
else
  echo 'V-235784 PASS, no containers running with host PID namespace detected'
fi

if docker ps --all | grep -iv "ucp\|kube\|dtr" | awk '{print $1}' | xargs docker inspect --format '{{ .Id }}: IpcMode={{ .HostConfig.IpcMode }}' | grep -i ipcmode=host ; then
  echo 'V-235785 FAIL, containers present running with host IPC namespace'
  exit 1
else
  echo 'V-235785 PASS, no containers running with host IPC namespace detected'
fi

# can be configured as docker daemon argument
if ps -ef | grep dockerd | grep --quiet 'userland-proxy'; then
  echo "V-235789 FAIL, Remove userland-proxy flag from docker service arguments, use /etc/docker/daemon.json."
  exit 1
fi
# can be configured in daemon.json
if grep --quiet -Pi '"userland-proxy"\s*:\s*false' /etc/docker/daemon.json ; then
  echo "V-235789 PASS, userland-proxy is disabled."
else
  if which jq ; then
    cat <<< $(sudo jq '. |= . + {"userland-proxy": false}' /etc/docker/daemon.json) > /etc/docker/daemon.json
    echo "V-235789 PASS, userland-proxy has been disabled by this script, be sure to restart the docker service."
  else
    echo "V-235789 FAIL, userland-proxy is not explicitly disabled, unable to fix, jq package not installed."
	echo "TIP: add '\"userland-proxy\": false' to /etc/docker/daemon.json and restart the docker service"
    exit 1
  fi
fi

if grep --quiet -Pi '"ip"\s*:\s*"[^0]' /etc/docker/daemon.json ; then
  echo "V-235820 PASS, Docker is configured to listen on specific IP address."
else
  if which jq ; then
    if grep '"ip"' /etc/docker/daemon.json ; then
      echo 'V-235820 FAIL, /etc/docker/daemon.json configured with IP set to 0.0.0.0, manually fix and rerun'
    else
      cat <<< $(sudo jq ". |= . + {\"ip\": \"$PRI_IP\"}" /etc/docker/daemon.json) > /etc/docker/daemon.json
      echo "V-235820 PASS, docker has been bound to $PRI_IP, be sure to restart the docker service."
	fi
  else
    echo "V-235820 FAIL, docker is not configured to bind to specific interface, unable to fix, jq package not installed."
	echo "TIP: add '\"ip\": \"192.168.1.10\"' to /etc/docker/daemon.json, replace the IP address with the system's IP and restart the docker service"
    exit 1
  fi
fi

if docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: AppArmorProfile={{ .AppArmorProfile }}' | grep -i "AppArmorProfile=unconfined" ; then
  echo 'V-235799 FAIL, containers present running without apparmor'
  exit 1
else
  echo 'V-235799 PASS, all containers running with apparmor profiles'
fi

# --------------------------Matt---------------------------------------------

docker ps -q | xargs docker inspect --format '{{ .Id }}: {{ .Name }}: Ports={{ .NetworkSettings.Ports }}' | grep HostPort
echo 'V-235837 MANUAL, review above ports and ensure they are in the SSP, look at the HostPort field.'

docker ps --quiet | xargs docker inspect --format '{{ .Id }}: Ports={{ .NetworkSettings.Ports }}' | grep -i host
echo 'V-235804 MANUAL, review above ports and ensure they are in the SSP, look at the HostPort field.'

if sudo ausearch -k docker | grep exec | grep --quiet privileged ; then
  echo 'V-235813 FAIL, there is an exec session running with privileged flag'
  exit 1
else
  echo 'V-235813 PASS, no exec sessions with privilged flag found'
fi

if docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: UsernsMode={{ .HostConfig.UsernsMode }}' | grep --quiet -i "UsernsMode=host" ; then
  echo 'V-235817 FAIL, containers present sharing host user namespace'
  exit 1
else
  echo 'V-235817 PASS, no containers running sharing host user namespace detected'
fi

LOW_HOST_PORT=$(docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: Ports={{ .NetworkSettings.Ports }}' | grep -Pio '(?<=HostPort:)\d+' | sort -n | head -n 1)
if [ "$LOW_HOST_PORT" -lt 1024 ] ; then 
    echo 'V-235819 FAIL host ports below 1024 are mapped into containers.'; 
	exit 1
else 
	echo 'V-235819 PASS, no host ports mapped below 1024'; 
fi

if docker ps --all | grep -iv "ucp\|kube\|dtr" | awk '{print $1}' | xargs docker inspect --format '{{ .Id }}: NetworkMode={{ .HostConfig.NetworkMode }}' | grep --quiet -i "NetworkMode=host" ; then
  echo 'V-235805 FAIL, containers present sharing hosts network namespace'
  exit 1
else
  echo 'V-235805 PASS, no containers running sharing hosts netork namespace'
fi

if docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: Devices={{ .HostConfig.Devices }}' | grep --quiet -i 'pathincontainer' ; then
  echo 'V-235809 FAIL, containers present with host devices passed in.'
  exit 1
else
  echo 'V-235809 PASS, no containers running with host devices passed in.'
fi 

if docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: Volumes={{ .Mounts }}' | grep -iv "ucp\|kubelet\|dtr" | grep -Po 'Source:\S+' | grep -P '\:(/|/boot|/dev|/etc|/lib|/proc|/sys|/usr)$' ; then
  echo 'V-235783 FAIL, sensitive directories mapped into containers detected.'
  exit 1
else
  echo 'V-235783 PASS, no sensitive directories found mappend into containers'
fi 

if docker info | grep --quiet -e "^Storage Driver:\s*aufs\s*$" ; then
  echo 'V-235790 FAIL, aufs file system detected.'
  exit 1
else
  echo 'V-235790 PASS, aufs file system not detected'
fi 

if docker ps --all | grep -iv "ucp\|kube\|dtr" | awk '{print $1}' | xargs docker inspect --format '{{ .Id }}: Propagation={{range $mnt := .Mounts}} {{json $mnt.Propagation}} {{end}}' | grep --quiet 'shared' ; then
  echo 'V-235810 FAIL, mount progagation mode set to shared.'
  exit 1
else
  echo 'V-235810 PASS, no mounts set to shared propogation mode found'
fi 

if docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: UTSMode={{ .HostConfig.UTSMode }}' | grep -i '=host' ; then
  echo 'V-235811 FAIL, host UTS namespace shared to container.'
  exit 1
else
  echo 'V-235811 PASS, no containers found with host UTC namespace shared'
fi

if ps aux | grep 'docker exec' | grep '\-\-user' ; then
  echo 'V-235814 FAIL, there is an exec session running with user flag'
  exit 1
else
  echo 'V-235814 PASS, no exec sessions with user flag found'
fi

if docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: CgroupParent={{ .HostConfig.CgroupParent }}' | grep -P '=\w+' ; then
  echo 'V-235815 FAIL, cgroup usage detected, must be manually checked.'
  exit 1
else
  echo 'V-235815 PASS, only default cgroups defined on running containers'
fi

if docker ps --quiet --all | grep -iv "ucp\|kube\|dtr" | awk '{print $1}' | xargs docker inspect --format '{{ .Id }}: Privileged={{ .HostConfig.Privileged }}' | grep true ; then
  echo 'V-235802 FAIL, containers running as privileged.'
  exit 1
else
  echo 'V-235802 PASS, no containers found running as privileged'
fi

if which auditctl ; then
  if !(systemctl show -p FragmentPath docker.service or auditctl -l | grep docker.service) then
    echo 'V-235779 FAIL, docker.service auditd rule missing'
	exit 1
  fi
  if !(systemctl show -p FragmentPath docker.socket or auditctl -l | grep docker.sock) then
    echo 'V-235779 FAIL, docker.docket auditd rule missing'
	exit 1
  fi
  echo 'V-235779 FAIL, Required auditd rules for docker are present'
else
  echo 'V-235779 FAIL, auditd does not appear to be installed, which will result in many STIG findings'
fi

if docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: CapAdd={{ .HostConfig.CapAdd }} CapDrop={{ .HostConfig.CapDrop }}' | grep -v ': CapAdd=<no value> CapDrop=<no value>$' ; then
  echo 'V-235801 FAIL, containers running with added capabilities, you will need to manually confirm with SSP.'
  exit 1
else
  echo 'V-235801 PASS, no containers found with additional capabilities passed in.'
fi

for i in $(docker ps -qa); do 
  if docker exec $i ps -el | grep -i sshd ; then
    echo 'V-235803 FAIL, containers running sshd found.'
    exit 1
  fi
done
echo 'V-235803 PASS, no containers running sshd found.'  

#----------------------- end matt --------------------------------------------