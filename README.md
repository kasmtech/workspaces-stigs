# docker-stigs

Script to apply docker stigs

This has been tested on centos7 and ubuntu 20 on AMD64 architecture. They will not work currently on ARM64

The OS needs a linux kernel of 4.11 or newer.

Please install the jq and audit all should be available in the standard repos if they aren't already installed.

The apply_kasm_stigs.sh will pull down and install the yq utility automatically on an internet connected host. 
If you are on air gapped network please pull down the latest yq from here: https://github.com/mikefarah/yq/releases and put the binary here: /opt/kasm/bin/utilities/yq_x86_64

Kasm must be running when executing these scripts on the web app servers and agent servers. apply_kasm_stigs will handle shutting down and restarting kasm service containers when needed.
The order that the scripts are ran is important, run the apply_docker_stigs.sh first, then run the apply_kasm_stigs.sh

V-235819 may fail if kasm is listening on the default port of 443. Setting up Kasm behind a reverse proxy is one way to shift the port Kasm is listening on above 1024.

Kasm Workspaces 1.10.0 specific
V-235827 will likely fail as not all containers have health checks in 1.10.0