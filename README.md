# Kasm Workspaces Docker STIG Hardening Scripts

## Warning
**This open-source project is not officially supported under a Kasm support license. It is an open-source project provided to the community to assist with hardening systems to meet DoD STIG requirements. Kasm Technologies does not provide any guarantees that these scripts will work as designed on every possible system and different configurations. There is the possibility that running these scripts can break systems and caution should be taken before running these scripts.**

---

## Supported Kasm Workspaces Versions
Ensure that you switch to a branch that matches the version of Kasm Workspaces that you have installed. For example, if you are running Kasm Workspaces 1.11.0, ensure that you change to the release/1.11.0 branch before applying the scripts. At this time, there is only a release for 1.11.0, however, it will work on 1.10.0 but may leave more remaining open findings.

```bash
git clone https://github.com/kasmtech/docker-stigs
cd docker-stigs
git checkout release/1.11.0
```

## Supported Architectures
These hardening scripts will only work on x86_64/AMD64 based architectures.

## Supported Operating Systems
These hardening scripts have been tested by Kasm Technologies on the following operating systems. It should be noted that we started with a base OS install and then installed Kasm Workspaces. These systems were not pre-configured in any way nor did they already have docker installed. These hardening scripts may not work on the following operating systems if they have unique non-default configurations. A Linux kernel version of 4.11 or new is required.

* Ubuntu 20.04 LTS base OS
* Ubuntu 20.04 LTS with Advantage subscription, full OS level hardened with FIPS mode enabled 
* CentOS 7 base OS

Please open an issue on the project's issue tracker to report your experience with other operating systems.

## Prerequisites

Auditd must be installed on the operating system. Auditd is required to meet base operating system STIG requirements and should therefore already be installed. The package 'jq' is also required and should be available in the operating systems package repository for most operating systems.

The apply_kasm_stigs.sh will pull down and install the yq utility automatically on an internet connected host. 
If you are on air gapped network, please pull down the latest yq from here: https://github.com/mikefarah/yq/releases and put the binary here: /opt/kasm/bin/utilities/yq_x86_64

## Applying the Scripts

Kasm must be running when executing these scripts on the web app servers and agent servers. The apply_kasm_stigs.sh will handle shutting down and restarting kasm service containers when needed.
The order that the scripts are ran is important, run the apply_docker_stigs.sh first, then run the apply_kasm_stigs.sh

```bash
# Kasm Workspaces must already be installed
git clone https://github.com/kasmtech/docker-stigs
cd docker-stigs
# switch to the release branch that matches your installed version of Kasm Workspaces
git checkout release/1.11.0
sudo bash apply_docker_stigs.sh
sudo bash apply_kasm_stigs.sh
```

V-235819 will fail if Kasm was installed using the default listening port of 443. To pass this check, Kasm must be installed with the -L 8443 flag, where 8443 can be any port above 1024.
In a hardened environment, it is assumed that Kasm will be proxied behind a security device, such as an F5 or NGINX, which supports proxying on 443 to end-users.
