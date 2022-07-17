# docker-stigs

Script to apply docker stigs

This has been tested on centos7 and ubuntu 20 on AMD64 architecture. They will not work currently on ARM64

The OS needs a linux kernel of 4.11 or newer.

Please install the jq and audit all should be available in the standard repos if they aren't already installed.

The apply_kasm_stigs.sh will pull down and install the yq utility automatically on an internet connected host. 
If you are on air gapped network please pull down the latest yq from here: https://github.com/mikefarah/yq/releases and put the binary here: /opt/kasm/bin/utilities/yq_x86_64

Kasm must be running when executing these scripts on the web app servers and agent servers. apply_kasm_stigs will handle shutting down and restarting kasm service containers when needed.
The order that the scripts are ran is important, run the apply_docker_stigs.sh first, then run the apply_kasm_stigs.sh

V-235819 will fail if Kasm was installed using the default listening port of 443. To pass this check, Kasm must be installed with the -L 8443 flag, where 8443 can be any port above 1024.
In a hardened environment, it is assumed that Kasm will be proxied behind a security device, such as an F5, which supports proxying on 443 to end-users.

V-235827 will likely fail as Kasm Workspaces does not currently provide health checks for all containers. More health checks are present in 1.11.0 than are present in 1.10.0