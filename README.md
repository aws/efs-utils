[![CircleCI](https://circleci.com/gh/aws/efs-utils.svg?style=svg)](https://circleci.com/gh/aws/efs-utils)

# efs-utils

Utilities for Amazon Elastic File System (EFS)

The `efs-utils` package has been verified against the following Linux distributions:

| Distribution | Package Type | `init` System |
| ------------ | ------------ | ------------- |
| Amazon Linux 2017.09 | `rpm` | `upstart` |
| Amazon Linux 2 | `rpm` | `systemd` |
| CentOS 7 | `rpm` | `systemd` |
| CentOS 8 | `rpm` | `systemd` |
| RHEL 7 | `rpm`| `systemd` |
| RHEL 8 | `rpm`| `systemd` |
| Fedora 28 | `rpm` | `systemd` |
| Fedora 29 | `rpm` | `systemd` |
| Fedora 30 | `rpm` | `systemd` |
| Fedora 31 | `rpm` | `systemd` |
| Fedora 32 | `rpm` | `systemd` |
| Debian 9 | `deb` | `systemd` |
| Debian 10 | `deb` | `systemd` |
| Ubuntu 16.04 | `deb` | `systemd` |
| Ubuntu 18.04 | `deb` | `systemd` |
| Ubuntu 20.04 | `deb` | `systemd` |
| OpenSUSE Leap | `rpm` | `systemd` |
| OpenSUSE Tumbleweed | `rpm` | `systemd` |
| SLES 12 | `rpm` | `systemd` |
| SLES 15 | `rpm` | `systemd` |

The `efs-utils` package has been verified against the following MacOS distributions:

| Distribution   | `init` System |
| -------------- | ------------- |
| MacOS Big Sur  | `launchd` |
| MacOS Monterey | `launchd` |

## Prerequisites

* `nfs-utils` (RHEL/CentOS/Amazon Linux/Fedora) or `nfs-common` (Debian/Ubuntu)
* OpenSSL 1.0.2+
* Python 3.4+
* `stunnel` 4.56+

## Optional

* `botocore` 1.12.0+

## Installation

### On Amazon Linux distributions

For those using Amazon Linux or Amazon Linux 2, the easiest way to install `efs-utils` is from Amazon's repositories:

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

- To build and install an RPM:

If the distribution is not OpenSUSE or SLES

```bash
$ sudo yum -y install git rpm-build make
$ git clone https://github.com/aws/efs-utils
$ cd efs-utils
$ make rpm
$ sudo yum -y install build/amazon-efs-utils*rpm
```

Otherwise

```bash
$ sudo zypper refresh
$ sudo zypper install -y git rpm-build make
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
$ sudo apt-get -y install git binutils
$ git clone https://github.com/aws/efs-utils
$ cd efs-utils
$ ./build-deb.sh
$ sudo apt-get -y install ./build/amazon-efs-utils*deb
```

### On MacOS Big Sur and macOS Monterey distribution

For EC2 Mac instances running macOS Big Sur and macOS Monterey, you can install amazon-efs-utils from the 
[homebrew-aws](https://github.com/aws/homebrew-aws) respository. **Note that this will ONLY work on EC2 instances
running macOS Big Sur and macOS Monterey, not local Mac computers.**
```bash
brew install amazon-efs-utils
```

This will install amazon-efs-utils on your EC2 Mac Instance running macOS Big Sur and macOS Monterey in the directory `/usr/local/Cellar/amazon-efs-utils`. At the end of the installation, it will print a set of commands that must be executed in order to start using efs-utils. The instructions that are printed after amazon-efs-utils and must be executed are:

```bash
# Perform below actions to start using efs:
    sudo mkdir -p /Library/Filesystems/efs.fs/Contents/Resources
    sudo ln -s /usr/local/bin/mount.efs /Library/Filesystems/efs.fs/Contents/Resources/mount_efs

# Perform below actions to stop using efs:
    sudo rm /Library/Filesystems/efs.fs/Contents/Resources/mount_efs

# To enable watchdog for using TLS mounts:
    sudo cp /usr/local/Cellar/amazon-efs-utils/<version>/libexec/amazon-efs-mount-watchdog.plist /Library/LaunchAgents
    sudo launchctl load /Library/LaunchAgents/amazon-efs-mount-watchdog.plist

# To disable watchdog for using TLS mounts:
    sudo launchctl unload /Library/LaunchAgents/amazon-efs-mount-watchdog.plist
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

`efs-utils` includes a mount helper utility to simplify mounting and using EFS file systems.

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
sudo sed -i -e '/\[cloudwatch-log\]/{N;s/# enabled = true/enabled = true/;}' /usr/local/Cellar/amazon-efs-utils/<version>/libexec/etc/amazon/efs/efs-utils.conf
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
