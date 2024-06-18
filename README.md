[![CircleCI](https://circleci.com/gh/aws/efs-utils.svg?style=svg)](https://circleci.com/gh/aws/efs-utils)

# efs-utils

Utilities for Amazon Elastic File System (EFS)

The `efs-utils` package has been verified against the following Linux distributions:

| Distribution         | Package Type | `init` System |
|----------------------| ----- | --------- |
| Amazon Linux 2       | `rpm` | `systemd` |
| Amazon Linux 2023    | `rpm` | `systemd` |
| CentOS 8             | `rpm` | `systemd` |
| RHEL 7               | `rpm` | `systemd` |
| RHEL 8               | `rpm` | `systemd` |
| RHEL 9               | `rpm` | `systemd` |
| Fedora 29            | `rpm` | `systemd` |
| Fedora 30            | `rpm` | `systemd` |
| Fedora 31            | `rpm` | `systemd` |
| Fedora 32            | `rpm` | `systemd` |
| Debian 11            | `deb` | `systemd` |
| Ubuntu 16.04         | `deb` | `systemd` |
| Ubuntu 18.04         | `deb` | `systemd` |
| Ubuntu 20.04         | `deb` | `systemd` |
| Ubuntu 22.04         | `deb` | `systemd` |
| OpenSUSE Leap        | `rpm` | `systemd` |
| OpenSUSE Tumbleweed  | `rpm` | `systemd` |
| Oracle8              | `rpm` | `systemd` |
| SLES 12              | `rpm` | `systemd` |
| SLES 15              | `rpm` | `systemd` |

The `efs-utils` package has been verified against the following MacOS distributions:

| Distribution   | `init` System |
|----------------|---------------|
| MacOS Big Sur  | `launchd`     |
| MacOS Monterey | `launchd`     |
| MacOS Ventura  | `launchd`     |
| MacOS Sonoma   | `launchd`     |

## README contents
  - [Prerequisites](#prerequisites)
  - [Optional](#optional)
  - [Installation](#installation)
    - [On Amazon Linux distributions](#on-amazon-linux-distributions)
    - [Install via AWS Systems Manager Distributor](#install-via-aws-systems-manager-distributor)
    - [On other Linux distributions](#on-other-linux-distributions)
    - [On MacOS Big Sur, macOS Monterey and macOS Ventura distribution](#on-macos-big-sur-macos-monterey-and-macos-ventura-distribution)
      - [Run tests](#run-tests)
  - [Usage](#usage)
    - [mount.efs](#mountefs)
    - [MacOS](#macos)
    - [amazon-efs-mount-watchdog](#amazon-efs-mount-watchdog)
  - [Troubleshooting](#troubleshooting)
  - [Upgrading to efs-utils v2.0.0](#upgrading-from-efs-utils-v1-to-v2)
  - [Upgrading stunnel for RHEL/CentOS](#upgrading-stunnel-for-rhelcentos)
  - [Upgrading stunnel for SLES12](#upgrading-stunnel-for-sles12)
  - [Upgrading stunnel for MacOS](#upgrading-stunnel-for-macos)
  - [Install botocore](#install-botocore)
      - [RPM](#rpm)
      - [DEB](#deb)
      - [On Debian10 and Ubuntu20, the botocore needs to be installed in specific target folder](#on-debian10-and-ubuntu20-the-botocore-needs-to-be-installed-in-specific-target-folder)
      - [To install botocore on MacOS](#to-install-botocore-on-macos)
  - [Upgrade botocore](#upgrade-botocore)
  - [Enable mount success/failure notification via CloudWatch log](#enable-mount-successfailure-notification-via-cloudwatch-log)
    - [Step 1. Install botocore](#step-1-install-botocore)
    - [Step 2. Enable CloudWatch log feature in efs-utils config file `/etc/amazon/efs/efs-utils.conf`](#step-2-enable-cloudwatch-log-feature-in-efs-utils-config-file-etcamazonefsefs-utilsconf)
    - [Step 3. Attach the CloudWatch logs policy to the IAM role attached to instance.](#step-3-attach-the-cloudwatch-logs-policy-to-the-iam-role-attached-to-instance)
  - [Optimize readahead max window size on Linux 5.4+](#optimize-readahead-max-window-size-on-linux-54)
  - [Using botocore to retrieve mount target ip address when dns name cannot be resolved](#using-botocore-to-retrieve-mount-target-ip-address-when-dns-name-cannot-be-resolved)
    - [Step 1. Install botocore](#step-1-install-botocore-1)
    - [Step 2. Allow DescribeMountTargets and DescribeAvailabilityZones action in the IAM policy](#step-2-allow-describemounttargets-and-describeavailabilityzones-action-in-the-iam-policy)
  - [The way to access instance metadata](#the-way-to-access-instance-metadata)
  - [Use the assumed profile credentials for IAM](#use-the-assumed-profile-credentials-for-iam)
  - [Enabling FIPS Mode](#enabling-fips-mode)
  - [License Summary](#license-summary)


## Prerequisites

* `nfs-utils` (RHEL/CentOS/Amazon Linux/Fedora) or `nfs-common` (Debian/Ubuntu)
* OpenSSL-devel 1.0.2+
* Python 3.7/3.8
* `stunnel` 4.56+
- `rust` 1.68+
- `cargo`

## Optional

* `botocore` 1.12.0+

## Installation

### On Amazon Linux distributions

For those using Amazon Linux, the easiest way to install `efs-utils` is from Amazon's repositories:

```bash
$ sudo yum -y install amazon-efs-utils
```

### Install via AWS Systems Manager Distributor
You can now use AWS Systems Manage Distributor to automatically install or update `amazon-efs-utils`. 
Please refer to [Using AWS Systems Manager to automatically install or update Amazon EFS clients](https://docs.aws.amazon.com/efs/latest/ug/manage-efs-utils-with-aws-sys-manager.html) for more guidance.

The following are prerequisites for using AWS Systems Manager Distributor to install or update `amazon-efs-utils`:

1. AWS Systems Manager agent is installed on the distribution (For `Amazon Linux` and `Ubuntu`, AWS Systems Manager agent
is pre-installed, for other distributions, please refer to [install AWS Systems Manager agent on Linux EC2 instance](https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-install-ssm-agent.html)
for more guidance.)

2. Instance is attached with IAM role with AWS managed policy `AmazonElasticFileSystemsUtils`, this policy will enable your instance to be managed by
 AWS Systems Manager agent, also it contains permissions to support specific features.

### On other Linux distributions

Other distributions require building the package from source and installing it.

If your distribution doesn't provide a rust or cargo package, or it provides versions
that are older than 1.68, then you can install rust and cargo through rustup:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"
```

- To build and install an RPM:

If the distribution is not OpenSUSE or SLES

```bash
$ sudo yum -y install git rpm-build make rust cargo openssl-devel
$ git clone https://github.com/aws/efs-utils
$ cd efs-utils
$ make rpm
$ sudo yum -y install build/amazon-efs-utils*rpm
```

Otherwise

```bash
$ sudo zypper refresh
$ sudo zypper install -y git rpm-build make rust cargo openssl-devel
$ git clone https://github.com/aws/efs-utils
$ cd efs-utils
$ make rpm
$ sudo zypper --no-gpg-checks install -y build/amazon-efs-utils*rpm
```

On OpenSUSE, if you see error like `File './suse/noarch/bash-completion-2.11-2.1.noarch.rpm' not found on medium 'http://download.opensuse.org/tumbleweed/repo/oss/'`
during installation of `git`, run the following commands to re-add repo OSS and NON-OSS, then run the install script above again.

```bash
sudo zypper ar -f -n OSS http://download.opensuse.org/tumbleweed/repo/oss/ OSS
sudo zypper ar -f -n NON-OSS http://download.opensuse.org/tumbleweed/repo/non-oss/ NON-OSS
sudo zypper refresh
```

- To build and install a Debian package:

```bash
$ sudo apt-get update
$ sudo apt-get -y install git binutils rustc cargo pkg-config libssl-dev
$ git clone https://github.com/aws/efs-utils
$ cd efs-utils
$ ./build-deb.sh
$ sudo apt-get -y install ./build/amazon-efs-utils*deb
```

If your Debian distribution doesn't provide a rust or cargo package, or your distribution provides versions
that are older than 1.68, then you can install rust and cargo through rustup:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"
```

### Common installation issues with efs-utils v2.0.0
**`make rpm` fails due to "feature `edition2021` is required"**:

Update to a version of rust and cargo
that is newer than 1.68. To install a new version of rust and cargo, run
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"
```

**You installed a new version of rust with the above command, but your system is still using the rust installed by the package manager**:

When installing rust with the rustup script above, the script will fail if it detects a rust already exists on the system.
Un-install the package manager's rust, and re-install rust through rustup. Once done, you will need to install rust through the package manager again to satisfy
the RPM's dependencies.
```bash
yum remove cargo rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
yum install cargo rust
. "$HOME/.cargo/env"
```

**When you run `make rpm`, compilation of efs-proxy fails due to `error: linker cc not found`**:

Make sure that you have a linker installed on your system. For example, on Amazon Linux or RHEL, install gcc with
```bash
yum install gcc
```

### On MacOS Big Sur, macOS Monterey, macOS Sonoma and macOS Ventura distribution

For EC2 Mac instances running macOS Big Sur, macOS Monterey, macOS Sonoma and macOS Ventura, you can install amazon-efs-utils from the 
[homebrew-aws](https://github.com/aws/homebrew-aws) respository. **Note that this will ONLY work on EC2 instances
running macOS Big Sur, macOS Monterey, macOS Sonoma and macOS Ventura, not local Mac computers.**
```bash
brew install amazon-efs-utils
```

This will install amazon-efs-utils on your EC2 Mac Instance running macOS Big Sur, macOS Monterey and macOS Ventura in the directory `/usr/local/Cellar/amazon-efs-utils`. 
  		  
***Follow the instructions in caveats when using efs-utils on EC2 Mac instance for the first time.*** To check the package caveats run below command
```bash
brew info amazon-efs-utils
```

#### Run tests

- [Set up a virtualenv](http://libzx.so/main/learning/2016/03/13/best-practice-for-virtualenv-and-git-repos.html) for efs-utils

```bash
$ virtualenv ~/.envs/efs-utils
$ source ~/.envs/efs-utils/bin/activate
$ pip install -r requirements.txt
```

- Run tests

```bash
$ make test
```

## Usage

### mount.efs
`efs-utils` includes a mount helper utility, `mount.efs`, that simplifies and improves the performance of EFS file system mounts.

`mount.efs` launches a proxy process that forwards NFS traffic from the kernel's NFS client to EFS.
This proxy is responsible for TLS encryption, and for providing improved throughput performance.

To mount with the recommended default options, simply run:

```bash
$ sudo mount -t efs file-system-id efs-mount-point/
```

To mount file system to a specific mount target of the file system, run:

```bash
$ sudo mount -t efs -o mounttargetip=mount-target-ip-address file-system-id efs-mount-point/
```

To mount file system within a given network namespace, run:

```bash
$ sudo mount -t efs -o netns=netns-path file-system-id efs-mount-point/
```

To mount file system to the mount target in specific availability zone (e.g. us-east-1a), run:

```bash
$ sudo mount -t efs -o az=az-name file-system-id efs-mount-point/
```

**Note: The [prequisites in the crossaccount section below](#crossaccount-option-prerequisites) must be completed before using the crossaccount option.**

To mount the filesystem mount target in the same physical availability zone ID (e.g. use1-az1) as the client instance over cross-AWS-account mounts, run:
```
$ sudo mount -t efs -o crossaccount file-system-id efs-mount-point/
```

To mount over TLS, simply add the `tls` option:

```bash
$ sudo mount -t efs -o tls file-system-id efs-mount-point/
```

To authenticate with EFS using the system’s IAM identity, add the `iam` option. This option requires the `tls` option.

```bash
$ sudo mount -t efs -o tls,iam file-system-id efs-mount-point/
```

To mount using an access point, use the `accesspoint=` option. This option requires the `tls` option.
The access point must be in the "available" state before it can be used to mount EFS.

```bash
$ sudo mount -t efs -o tls,accesspoint=access-point-id file-system-id efs-mount-point/
```

To mount your file system automatically with any of the options above, you can add entries to `/efs/fstab` like:

```bash
file-system-id efs-mount-point efs _netdev,tls,iam,accesspoint=access-point-id 0 0
```

For more information on mounting with the mount helper, see the manual page:

```bash
man mount.efs
```

or refer to the [documentation](https://docs.aws.amazon.com/efs/latest/ug/using-amazon-efs-utils.html).

#### crossaccount Option Prerequisites

The crossaccount mount option ensures that the client instance Availability Zone ID (e.g. use1-az1) is the same as the EFS mount target Availability Zone ID for cross-AWS-account mounts (e.g. if the client instance is in Account A while the EFS instance is in Account B). 

Given a client instance in Account A/VPC A and an EFS instance in Account B/VPC B, the following prerequisites must be completed prior to using the crossaccount option:
- Cross-VPC Communication:
  - Create a VPC Peering relationship between VPC A & VPC B. Documentation to create the peering relationship can be found [here](https://docs.aws.amazon.com/vpc/latest/peering/create-vpc-peering-connection.html).
  - Configure VPC route tables to send/receive traffic. Documentation can be found [here](https://docs.aws.amazon.com/vpc/latest/peering/vpc-peering-routing.html).
  - Create subnet in VPC B in the Availability Zone of the Account A client instance if it does not exist already.
  - Create an EFS Mount Target in each of the Availability Zones from the above step in VPC B if they do not exist already.
  - Attach a VPC Security Group to each of the EFS Mount Targets which allow inbound NFS access from VPC A’s CIDR block.
- Route 53 Setup:
  - For a mount target A in \<availability-zone-id>, create a Route 53 Hosted Zone for the domain \<availability-zone-id>.\<file-system-id>.efs.\<aws-region>.amazonaws.com.
  - Then, add an A record in the Hosted Zone which resolves to mount target A's IP Address. Leave the subdomain blank.


Once the above steps have been completed, to mount the filesystem mount target in the same physical availability zone ID (e.g. use1-az1) as the client instance over cross-AWS-account mounts, run:
```
$ sudo mount -t efs -o crossaccount file-system-id efs-mount-point/
```


### MacOS 

For EC2 instances using Mac distribution, the recommended default options will perform a tls mount:

```bash
$ sudo mount -t efs file-system-id efs-mount-point/
```
 or
```bash
$ sudo mount -t efs -o tls file-system-id efs-mount-point/
```

To mount without TLS, simply add the `notls` option:

```bash
$ sudo mount -t efs -o notls file-system-id efs-mount-point/
```


### amazon-efs-mount-watchdog

`efs-utils` contains a watchdog process to monitor the health of TLS mounts. This process is managed by either `upstart` or `systemd` depending on your Linux distribution and `launchd` on Mac distribution, and is started automatically the first time an EFS file system is mounted over TLS.

## Troubleshooting
If you run into a problem with efs-utils, please open an issue in this repository.  We can more easily
assist you if relevant logs are provided.  You can find the log file at `/var/log/amazon/efs/mount.log`.  

Often times, enabling debug level logging can help us find problems more easily.  To do this, run  
`sed -i '/logging_level = INFO/s//logging_level = DEBUG/g' /etc/amazon/efs/efs-utils.conf`.  

You can also enable stunnel and efs-proxy debug logs with  
`sed -i '/stunnel_debug_enabled = false/s//stunnel_debug_enabled = true/g' /etc/amazon/efs/efs-utils.conf`.   
These logs files will also be in `/var/log/amazon/efs/`.

Make sure to perform the failed mount again after running the prior commands before pulling the logs.

## Upgrading from efs-utils v1 to v2
Efs-utils v2.0.0 replaces stunnel, which provides TLS encryptions for mounts, with efs-proxy, a component built in-house at AWS.
Efs-proxy lays the foundation for upcoming feature launches at EFS.

To utilize the improved performance benefits of efs-proxy, you must re-mount any existing mounts. 

Efs-proxy is not compatible with OCSP or Mac clients. In these cases, efs-utils will automatically revert back to using stunnel.  

If you are building efs-utils v2.0.0 from source, then you need Rust and Cargo >= 1.68.

## Upgrading stunnel for RHEL/CentOS

By default, when using the EFS mount helper with TLS, it enforces certificate hostname checking. The EFS mount helper uses the `stunnel` program for its TLS functionality. Please note that some versions of Linux do not include a version of `stunnel` that supports TLS features by default. When using such a Linux version, mounting an EFS file system using TLS will fail. 

Once you’ve installed the `amazon-efs-utils` package, to upgrade your system’s version of `stunnel`, see [Upgrading Stunnel](https://docs.aws.amazon.com/efs/latest/ug/using-amazon-efs-utils.html#upgrading-stunnel).

## Upgrading stunnel for SLES12

Run the following commands and follow the output hint of zypper package manager to upgrade the stunnel on your SLES12 instance

```bash
sudo zypper addrepo https://download.opensuse.org/repositories/security:Stunnel/SLE_12_SP5/security:Stunnel.repo
sudo zypper refresh
sudo zypper install -y stunnel
```

## Upgrading stunnel for MacOS

The installation installs latest stunnel available in brew repository. You can also upgrade the version of stunnel on your instance using the command below:
```bash
brew upgrade stunnel
```

## Install botocore

`efs-utils` uses botocore to interact with other AWS services. Please note the package type from the above table and install
botocore based on that info. If botocore is already installed and does not meet the minimum required version, 
you can upgrade the botocore by following the [upgrade botocore section](#Upgrade-botocore).
 
- Download the `get-pip.py` script
#### RPM
```bash
sudo yum -y install wget
```
```bash
if [[ "$(python3 -V 2>&1)" =~ ^(Python 3.6.*) ]]; then
    sudo wget https://bootstrap.pypa.io/pip/3.6/get-pip.py -O /tmp/get-pip.py
elif [[ "$(python3 -V 2>&1)" =~ ^(Python 3.5.*) ]]; then
    sudo wget https://bootstrap.pypa.io/pip/3.5/get-pip.py -O /tmp/get-pip.py
elif [[ "$(python3 -V 2>&1)" =~ ^(Python 3.4.*) ]]; then
    sudo wget https://bootstrap.pypa.io/pip/3.4/get-pip.py -O /tmp/get-pip.py
else
    sudo wget https://bootstrap.pypa.io/get-pip.py -O /tmp/get-pip.py
fi
```
#### DEB
```bash
sudo apt-get update
sudo apt-get -y install wget
```
```bash
if echo $(python3 -V 2>&1) | grep -e "Python 3.6"; then
    sudo wget https://bootstrap.pypa.io/pip/3.6/get-pip.py -O /tmp/get-pip.py
elif echo $(python3 -V 2>&1) | grep -e "Python 3.5"; then
    sudo wget https://bootstrap.pypa.io/pip/3.5/get-pip.py -O /tmp/get-pip.py
elif echo $(python3 -V 2>&1) | grep -e "Python 3.4"; then
    sudo wget https://bootstrap.pypa.io/pip/3.4/get-pip.py -O /tmp/get-pip.py
else
    sudo apt-get -y install python3-distutils
    sudo wget https://bootstrap.pypa.io/get-pip.py -O /tmp/get-pip.py
fi
```

- To install botocore on RPM
```bash
sudo python3 /tmp/get-pip.py
sudo pip3 install botocore || sudo /usr/local/bin/pip3 install botocore
```

- To install botocore on DEB
```bash
sudo python3 /tmp/get-pip.py
sudo pip3 install botocore || sudo /usr/local/bin/pip3 install botocore
```

#### On Debian10 and Ubuntu20, the botocore needs to be installed in specific target folder
```bash
sudo python3 /tmp/get-pip.py
sudo pip3 install --target /usr/lib/python3/dist-packages botocore || sudo /usr/local/bin/pip3 install --target /usr/lib/python3/dist-packages botocore
```

#### To install botocore on MacOS
```bash
sudo pip3 install botocore
```

## Upgrade botocore
Pass `--upgrade` to the corresponding installation scripts above based on system platform and distribution

```bash
sudo pip3 install botocore --upgrade
```

## Enable mount success/failure notification via CloudWatch log
`efs-utils` now support publishing mount success/failure logs to CloudWatch log. By default, this feature is disabled. There are three
steps you must follow to enable and use this feature:

### Step 1. Install botocore
Follow [install botocore section](#Install-botocore)

### Step 2. Enable CloudWatch log feature in efs-utils config file `/etc/amazon/efs/efs-utils.conf`
```bash
sudo sed -i -e '/\[cloudwatch-log\]/{N;s/# enabled = true/enabled = true/}' /etc/amazon/efs/efs-utils.conf
```

- For MacOS:
```bash
    EFS_UTILS_VERSION=<e.g. 1.34.5>
    sudo sed -i -e '/\[cloudwatch-log\]/{N;s/# enabled = true/enabled = true/;}' /usr/local/Cellar/amazon-efs-utils/${EFS_UTILS_VERSION}/libexec/etc/amazon/efs/efs-utils.conf
```
- For Mac2 instance:
```bash
    EFS_UTILS_VERSION=<e.g. 1.34.5>
    sudo sed -i -e '/\[cloudwatch-log\]/{N;s/# enabled = true/enabled = true/;}' /opt/homebrew/Cellar/amazon-efs-utils/${EFS_UTILS_VERSION}/libexec/etc/amazon/efs/efs-utils.conf
```
You can also configure CloudWatch log group name and log retention days in the config file.
If you want to have separate log groups in Cloudwatch for every mounted file system, add `/{fs_id}` to the end of the `log_group_name` field in `efs-utils.conf` file. For example, the `log_group_name` in `efs-utils.conf` file would look something like:

```bash
[cloudwatch-log]
log_group_name = /aws/efs/utils/{fs_id}
```
### Step 3. Attach the CloudWatch logs policy to the IAM role attached to instance.
Attach AWS managed policy `AmazonElasticFileSystemsUtils` to the iam role you attached to the instance, or the aws credentials
configured on your instance.

After completing the three prerequisite steps, you will be able to see mount status notifications in CloudWatch Logs.

## Optimize readahead max window size on Linux 5.4+

A change in the Linux kernel 5.4+ results a throughput regression on NFS client. With [patch](https://www.spinics.net/lists/linux-nfs/msg75018.html), starting from 5.4.\*, Kernels containing this patch now set the default read_ahead_kb size to 128 KB instead of the previous 15 MB. This read_ahead_kb is used by the Linux kernel to optimize performance on NFS read requests by defining the maximum amount of data an NFS client can pre-fetch in a read call. With the reduced value, an NFS client has to make more read calls to the file system, resulting in reduced performance.

To avoid above throughput regression, efs-utils will modify read_ahead_kb to 15 \* rsize (could be configured via mount option, 1MB by default) after mount success on Linux 5.4+. (not support on MacOS)

This optimization will be enabled by default. To disable this optimization:

```bash
sed -i "s/optimize_readahead = false/optimize_readahead = true/" /etc/amazon/efs/efs-utils.conf
```

To re-enable this optimization

```bash
sed -i "s/optimize_readahead = true/optimize_readahead = false/" /etc/amazon/efs/efs-utils.conf
```

You can mount file system with a given rsize, run:

```bash
$ sudo mount -t efs -o rsize=rsize-value-in-bytes file-system-id efs-mount-point/
```

You can also manually chose a value of read_ahead_kb to optimize read throughput on Linux 5.4+ after mount.

```bash
$ sudo bash -c "echo read-ahead-value-in-kb > /sys/class/bdi/0:$(stat -c '%d' efs-mount-point)/read_ahead_kb"
```

## Using botocore to retrieve mount target ip address when dns name cannot be resolved

`efs-utils` now supports using botocore to retrieve mount target ip address when dns name cannot be resolved, e.g. 
when user is mounting a file system in another VPC. There are two prerequisites to use this feature:

### Step 1. Install botocore
Follow [install botocore section](#Install-botocore)

### Step 2. Allow DescribeMountTargets and DescribeAvailabilityZones action in the IAM policy
Allow the `elasticfilesystem:DescribeMountTargets` and `ec2:DescribeAvailabilityZones` action in your policy attached to 
the iam role you attached to the instance, or the aws credentials configured on your instance. We recommend you attach 
AWS managed policy `AmazonElasticFileSystemsUtils`.

This feature will be enabled by default. To disable this feature:

```bash
sed -i "s/fall_back_to_mount_target_ip_address_enabled = true/fall_back_to_mount_target_ip_address_enabled = false/" /etc/amazon/efs/efs-utils.conf
```

If you decide that you do not want to use this feature, but need to mount a cross-VPC file system, you can use the mounttargetip 
option to do so, using the desired mount target ip address in the mount command.

## The way to access instance metadata
`efs-utils` by default uses IMDSv2, which is a session-oriented method used to access instance metadata. If you don't want to use 
IMDSv2, you can disable the token fetching feature by running the following command:

```bash
sed -i "s/disable_fetch_ec2_metadata_token = false/disable_fetch_ec2_metadata_token = true/" /etc/amazon/efs/efs-utils.conf
```

## Use the assumed profile credentials for IAM
To authenticate with EFS using the system’s IAM identity of an awsprofile, add the `iam` option and pass the profile name to 
`awsprofile` option. These options require the `tls` option.

```bash
$ sudo mount -t efs -o tls,iam,awsprofile=test-profile file-system-id efs-mount-point/
```

To configure the named profile, see the [Named Profiles doc](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-profiles.html)
and [Support Config File Settings doc](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html#cli-configure-files-settings)
for more details. If the credentials (e.g. aws_access_key_id) are not configured in `/root/.aws/credentials` or `/root/.aws/config` 
(note that the path prefix may vary based on the root path of sudo), efs-utils will use botocore to assume the named profile. 
This will require botocore is pre-installed, please follow [install botocore section](#Install-botocore) to install botocore first.

Normally you will need to configure your profile IAM policy to make the assume works. For example, if you want to perform a
cross-account mounting, suppose you have established 
[vpc-peering-connections](https://docs.aws.amazon.com/vpc/latest/peering/create-vpc-peering-connection.html) between your vpcs,
next step you need to do is giving permission to account B so that it can assume a role in account A and then mount the file system 
that belongs to account A. You can see 
[IAM doc](https://docs.aws.amazon.com/IAM/latest/UserGuide/tutorial_cross-account-with-roles.html) for more details.

After the IAM identity is setup, you can configure your awsprofile credentials or config. You can refer to 
[sdk settings](https://docs.aws.amazon.com/sdkref/latest/guide/settings-global.html). For example you can define
the profile to use the credentials of profile `default` to assume role in account A by defining the `source_profile`.

```bash
# /root/.aws/credentials
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key_id =wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# /root/.aws/config
[default]
...

[profile test-profile]
role_arn = <role-arn-in-account-A>
source_profile = default
```

Or you can use the credentials from IAM role attached to instance to assume the named profile, e.g.

```bash
# /root/.aws/config
[profile test-profile]
role_arn = <role-arn-in-account-A>
credential_source = Ec2InstanceMetadata
```

## Use AssumeRoleWithWebIdentity

You can use [web identity to assume a role](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html) which has the permission to attach to the EFS filesystem. You need to have a valid JWT token and a role arn to assume. There are two ways you can leverage them:

1) By setting environment variable the path to the file containing the JWT token in `AWS_WEB_IDENTITY_TOKEN_FILE` and by setting `ROLE_ARN` environment variable. The command below shows an example of to leverage it.

```bash
$ sudo mount -t efs -o tls,iam file-system-id efs-mount-point/
```

2) By passing the JWT token file path and the role arn as parameters to the mount command. The command below shows an example of to leverage it.

```bash
$ sudo mount -t efs -o tls,iam,rolearn="ROLE_ARN",jwtpath="PATH/JWT_TOKEN_FILE" file-system-id efs-mount-point/
```

## Enabling FIPS Mode
Efs-Utils is able to enter FIPS mode when mounting your file system. To enable FIPS you need to modify the EFS-Utils config file:
```bash
sed -i "s/fips_mode_enabled = false/fips_mode_enabled = true/" /etc/amazon/efs/efs-utils.conf
```
This will enable any potential API call from EFS-Utils to use FIPS endpoints and cause stunnel to enter FIPS mode 

Note: FIPS mode requires that the installed version of OpenSSL is compiled with FIPS.

To verify that the installed version is compiled with FIPS, look for `OpenSSL X.X.Xx-fips` in the `stunnel -version` command output e.g.
```bash
$ stunnel -version
stunnel 4.56 on x86_64-koji-linux-gnu platform
Compiled/running with OpenSSL 1.0.2k-fips  26 Jan 2017
Threading:PTHREAD Sockets:POLL,IPv6 SSL:ENGINE,OCSP,FIPS Auth:LIBWRAP
```

For more information on how to configure OpenSSL with FIPS see the [OpenSSL FIPS README](https://github.com/openssl/openssl/blob/master/README-FIPS.md).

## License Summary

This code is made available under the MIT license.
