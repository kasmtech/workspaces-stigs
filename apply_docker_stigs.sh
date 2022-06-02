
#!/bin/bash
set -e
set -x

DOCKER_DAEMON_JSON_PATH=/etc/docker/daemon.json
DOCKER_SOCK_PATH=/run/containerd/containerd.sock
DEFAULT_DOCKER_PATH=/etc/default/docker
ETC_DOCKER_PATH=/etc/docker/
DOCKER_SOCKET_PATH=/lib/systemd/system/docker.socket
DOCKER_SERVICE_PATH=/lib/systemd/system/docker.service

if [ ! -f "$DOCKER_DAEMON_JSON_PATH" ] ; then
	echo "$DOCKER_DAEMON_JSON_PATH does not exist, creating"
	touch $DOCKER_DAEMON_JSON_PATH
fi

echo "V-235867 setting daemon.json ownership to root:root"
chown root:root $DOCKER_DAEMON_JSON_PATH

echo "V-235868 setting daemon.json permissions to 644"
chmod 0644 $DOCKER_DAEMON_JSON_PATH

if [ ! -S "$DOCKER_SOCK_PATH" ] ; then
	echo "Docker sock at $DOCKER_SOCK_PATH does not exist, exiting"
	exit 1
fi

echo "V-235866 Setting docker sock permission to 660"
chmod 0660 $DOCKER_SOCK_PATH

echo "V-235865 Setting docker sock ownership to root:docker"
chown root:docker $DOCKER_SOCK_PATH

echo "V-235869 Setting $DEFAULT_DOCKER_PATH ownership to root:root"
chown root:root $DEFAULT_DOCKER_PATH

echo "V-235870 Setting $DEFAULT_DOCKER_PATH permissions to 644"
chmod 0644 $DEFAULT_DOCKER_PATH

echo "V-235855 Setting $ETC_DOCKER_PATH ownership to root:root"
chown root:root $ETC_DOCKER_PATH

echo "V-235856 Setting $ETC_DOCKER_PATH permissions to 755"
chmod 755 $ETC_DOCKER_PATH

echo "V-235853 Setting docker.socket file ownership to root:root"
chown root:root $DOCKER_SOCKET_PATH

echo "V-235854 Setting docker.socket file permissions to 644"
chmod 0644 $DOCKER_SOCKET_PATH

echo "V-235851 Setting docker.service file ownership to root:root"
chown root:root $DOCKER_SERVICE_PATH

echo "V-235852 Setting docker.service file permissions to 0644"
chmod 0644 $DOCKER_SERVICE_PATH

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
	echo "V-235812 FINDING, found container with seccomp unconfined."
	exit 1
else
	echo "V-235812 OK, no seccomp unconfined containers found"
fi

set +e
docker ps --quiet --all | xargs --no-run-if-empty -- docker inspect --format '{{ .Id }}: Ulimits={{ .HostConfig.Ulimits }}' | grep "no value"
pipe_status=(${PIPESTATUS[@]})
set -e
inner_commands=(${pipe_status[@]:0:2})
grep_rc=${pipe_status[@]:2}
for rc in ${inner_commands[@]}; do
	if [ $rc -ne 0 ]; then
		echo "Inner command in V-235844 check failed, exiting"
		exit 1
	fi
done

if [ $grep_rc -eq 0 ]; then
	echo "V-235844 FINDING container overrides ulimit"
	exit 1
else
	echo "V-235844 OK no containers override default ulimit"
fi
