[![CircleCI](https://circleci.com/gh/aws/efs-utils.svg?style=svg)](https://circleci.com/gh/aws/efs-utils)

# Amazon efs-utils

Amazon utilities for Amazon Elastic File System (EFS) and Amazon S3 Files. 
`efs-utils` is an open-source toolkit for mounting and managing Amazon EFS and S3 file systems (S3 support added in version 3.0.0). The package includes mount helpers that simplify mounting file systems and enable Amazon CloudWatch monitoring your mount status.

Amazon Elastic File System (EFS) is designed to provide serverless, fully elastic file storage that lets you share file data without provisioning or managing storage capacity and performance. To learn more, see [Amazon EFS](https://aws.amazon.com/efs/).

Amazon S3 Files is a shared file system that connects any AWS compute directly with your data in Amazon S3. It provides fast, direct access to all of your S3 data as files with full file system semantics and low-latency performance, without your data ever leaving S3. File-based applications, agents, and teams can access and work with S3 data as a file system using the tools they already depend on. To learn more, see [S3 Files](https://aws.amazon.com/s3/features/files/).

Efs-utils for EFS and S3 file systems are supported on the following Linux distributions:

| Distribution         | Package Type | init System |
|----------------------| ----- | --------- |
| Amazon Linux 2       | `rpm` | `systemd` |
| Amazon Linux 2023    | `rpm` | `systemd` |
| RHEL 8               | `rpm` | `systemd` |
| RHEL 9               | `rpm` | `systemd` |
| Ubuntu 20.04         | `deb` | `systemd` |
| Ubuntu 22.04         | `deb` | `systemd` |
| Ubuntu 24.04         | `deb` | `systemd` |
| OpenSUSE Leap        | `rpm` | `systemd` |
| SLES 15              | `rpm` | `systemd` |

Efs-utils for EFS file systems is supported on the following macOS distributions:

| Distribution   | init System |
|----------------|---------------|
| macOS Ventura  | `launchd`     |
| macOS Sonoma   | `launchd`     |
| macOS Sequoia  | `launchd`     |
| macOS Tahoe    | `launchd`     |

## README Contents
- [Installation](#installation)
  - [For Amazon Linux distributions](#for-amazon-linux-distributions)
  - [Install via AWS Systems Manager Distributor](#install-via-aws-systems-manager-distributor)
  - [Other Linux Distributions](#other-linux-distributions)
  - [For macOS Tahoe, Sequoia, Sonoma, and Ventura distributions](#for-macos-tahoe-sequoia-sonoma-and-ventura-distributions)
- [Mount an EFS and S3 file system](#mount-an-efs-and-s3-file-system)
  - [S3 Files-specific Mount Options](#s3-files-specific-mount-options)
  - [macOS](#macos)
  - [Amazon EFS Mount Watchdog](#amazon-efs-mount-watchdog)
- [Troubleshooting](#troubleshooting)
- [Upgrading Efs-utils Versions](#upgrading-efs-utils-versions)
- [Upgrading stunnel](#upgrading-stunnel)
- [Installing Botocore](#installing-botocore)
  - [RPM](#rpm)
  - [DEB](#deb)
  - [macOS](#macos-1)
  - [Upgrade botocore](#upgrade-botocore)
- [Enabling CloudWatch notifications](#enabling-cloudwatch-notifications)
- [Optimizing readahead max window](#optimizing-readahead-max-window)
- [Botocore for mount target IP](#botocore-for-mount-target-ip)
- [Accessing instance metadata](#accessing-instance-metadata)
- [Assumed profile credentials for IAM](#assumed-profile-credentials-for-iam)
- [Use AssumeRoleWithWebIdentity](#use-assumerolewithwebidentity)
- [Environment Variable Support](#environment-variable-support)
  - [AWS Region Environment Variables](#aws-region-environment-variables)
  - [Examples](#examples)
- [Enabling FIPS Mode](#enabling-fips-mode)
- [License Summary](#license-summary)

## Installation Instructions

### For Amazon Linux distributions

For Amazon Linux users, the simplest way to install `efs-utils` is from Amazon's repositories:

```bash
sudo yum -y install amazon-efs-utils
```

### Install via AWS Systems Manager Distributor
You can use AWS Systems Manager Distributor to automatically install or update `amazon-efs-utils`. For more information, see [Using AWS Systems Manager to automatically install or update Amazon EFS clients](https://docs.aws.amazon.com/efs/latest/ug/manage-efs-utils-with-aws-sys-manager.html). Prerequisites for using AWS Systems Manager Distributor to install or update amazon-efs-utils include:

1.	AWS Systems Manager agent is installed on the distribution (pre-installed on `Amazon Linux` and `Ubuntu`; for other distributions, see [install AWS Systems Manager agent on Linux EC2 instance](https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-install-ssm-agent.html)).

2. Instance is attached with IAM role with AWS managed policy `AmazonElasticFileSystemsUtils`, this policy will enable your instance to be managed by
 AWS Systems Manager agent, also it contains permissions to support specific features.

### Other Linux Distributions

Building from source requires Rust 1.70+, Cargo, Go 1.17.13+, CMake 3.0+, GCC/G++, and Perl. See [INSTALL.md](INSTALL.md) for detailed build instructions for your distribution.

### For macOS Tahoe, Sequoia, Sonoma, and Ventura distributions

For EC2 Mac instances running macOS Tahoe, Sonoma, or Ventura, you can install amazon-efs-utils from the [homebrew-aws](https://github.com/aws/homebrew-aws) repository. This is supported on only EC2 instances, not for local Mac computers. macOS is unsupported for S3 file systems.
```bash
brew install amazon-efs-utils
```

This installs amazon-efs-utils in:
- Intel Macs: `/usr/local/Cellar/amazon-efs-utils`
- Apple Silicon Macs: `/opt/homebrew/Cellar/amazon-efs-utils`

Follow the instructions in caveats when using efs-utils on EC2 Mac instance for the first time. To check the package caveats run the command below:
```bash
brew info amazon-efs-utils
```

## Mount an EFS and S3 file system

`efs-utils` includes two mount helper utilities: `mount.efs` for EFS file systems and `mount.s3files` for S3 file systems (v3.0.0+). Both simplify mounting and enhance file system performance. They also launch a proxy process that forwards NFS traffic from the kernel's NFS client to the file system. This proxy handles TLS encryption and improves throughput performance.

To mount your file system with the recommended default options, run:

```bash
# For an EFS file system
sudo mount -t efs file-system-id efs-mount-point/

# For an S3 file system
sudo mount -t s3files file-system-id s3files-mount-point/
```

To mount a file system to a specific mount target, run:

```bash
# For an EFS file system
sudo mount -t efs -o mounttargetip=mount-target-ip-address file-system-id efs-mount-point/

# For an S3 file system
sudo mount -t s3files -o mounttargetip=mount-target-ip-address file-system-id s3files-mount-point/
```

To mount a file system within a specific network namespace, run:

```bash
# For an EFS file system
sudo mount -t efs -o netns=netns-path file-system-id efs-mount-point/

# For an S3 file system
sudo mount -t s3files -o netns=netns-path file-system-id s3files-mount-point/
```

To mount a file system to a mount target in a specific AWS Availability Zone, run:

```bash
# For an EFS file system (use az name, e.g. us-east-1a)
sudo mount -t efs -o az=az-name file-system-id efs-mount-point/

# For an S3 file system (use az id, e.g. use1-az1)
sudo mount -t s3files -o azid=az-id-name file-system-id s3files-mount-point/
```

To mount a file system to a mount target in a specific AWS Region, run:

```bash
# For an EFS file system
sudo mount -t efs -o region=region-name file-system-id efs-mount-point/

# For an S3 file system
sudo mount -t s3files -o region=region-name file-system-id s3files-mount-point/
```

**Note:** For cross-account support, ensure the [prerequisites](#crossaccount-option-prerequisites) are met before using the cross-account option.

To mount an EFS file system mount target in the same availability zone ID (e.g., use1-az1) as the client instance for cross-account mounts, run:

**Note:** This feature is not supported for S3 Files.
```bash
sudo mount -t efs -o crossaccount file-system-id efs-mount-point/
```

To mount your EFS file system over TLS, add the `tls` flag. S3 file systems use TLS by default and require no action.

```bash
# For an EFS file system
sudo mount -t efs -o tls file-system-id efs-mount-point/

# For an S3 file system
sudo mount -t s3files file-system-id s3files-mount-point/
```

To authenticate with EFS using an IAM identity, add the `iam` and `tls` flags (TLS is required). S3 Files automatically includes both IAM and TLS and cannot be disabled.

```bash
# For an EFS file system
sudo mount -t efs -o tls,iam file-system-id efs-mount-point/

# For an S3 file system
sudo mount -t s3files file-system-id s3files-mount-point/
```

To mount using an access point, use the `accesspoint=` option, which requires the `tls` flag. The access point must be in the "available" state before it can be used for EFS or S3 file system mounts.

```bash
# For an EFS file system
sudo mount -t efs -o tls,accesspoint=access-point-id file-system-id efs-mount-point/

# For an S3 file system (iam and tls are automatically applied)
sudo mount -t s3files -o accesspoint=access-point-id file-system-id s3files-mount-point/
```

To automatically mount your file system with any of the options above, you can add entries to `/etc/fstab`:

```bash
# For an EFS file system
file-system-id efs-mount-point efs _netdev,tls,iam,accesspoint=access-point-id 0 0

# For an S3 file system (iam and tls are automatically applied)
file-system-id s3files-mount-point s3files _netdev,accesspoint=access-point-id 0 0
```
For more information on mount helpers, see manual pages below or visit our [documentation](https://docs.aws.amazon.com/efs/latest/ug/using-amazon-efs-utils.html).
```bash
man mount.efs
man mount.s3files
```

### S3 Files-specific Mount Options

**`nodirects3read`** – Optionally, you can disable direct reads from your S3 bucket. S3 Files automatically selects the optimal read path, from the file system or direct from the bucket. For large objects, it streams directly from your S3 bucket for higher throughput. When specified, all read operations use the standard NFS data path instead of streaming directly from your S3 bucket.

```bash
# Disable direct S3 read path
sudo mount -t s3files -o nodirects3read file-system-id s3files-mount-point/
```
Cross Account Prerequisites: the `crossaccount` option ensures that the client instance Availability Zone ID (e.g. use1-az1) is the same as the EFS mount target Availability Zone ID for cross-AWS-account mounts (e.g. if the client instance is in Account A while the EFS instance is in Account B). Given a client instance in Account A/VPC A and an EFS instance in Account B/VPC B, the following prerequisites must be completed prior to using the crossaccount option:

Cross-VPC Communication:
  - Create a VPC Peering relationship between VPC A & VPC B. Documentation to create the peering relationship can be found [here](https://docs.aws.amazon.com/vpc/latest/peering/create-vpc-peering-connection.html).
  - Configure VPC route tables to send/receive traffic. Documentation can be found [here](https://docs.aws.amazon.com/vpc/latest/peering/vpc-peering-routing.html).
  - Create subnet in VPC B in the Availability Zone of the Account A client instance if it does not exist already.
  - Create an EFS Mount Target in each of the Availability Zones from the above step in VPC B if they do not exist already.
  - Attach a VPC Security Group to each of the EFS Mount Targets which allow inbound NFS access from VPC A’s CIDR block.

Route 53 Setup:
  - For a mount target A in \<availability-zone-id>, create a Route 53 Hosted Zone for the domain \<availability-zone-id>.\<file-system-id>.efs.\<aws-region>.amazonaws.com.
  - Then, add an A record in the Hosted Zone which resolves to mount target A's IP Address. Leave the subdomain blank.

After the above steps are complete, mount your filesystem mount target in the same Availability Zone ID (e.g. use1-az1) as the client instance over cross-AWS-account mounts, by running:
```
sudo mount -t efs -o crossaccount file-system-id efs-mount-point/
```

Note: crossaccount is not supported for S3 Files. You can manually specify the mount target IP using the `mounttargetip` option to perform cross-account mounts.


### macOS

For EC2 instances using macOS distribution, the recommended default options will perform a tls mount:

```bash
sudo mount -t efs file-system-id efs-mount-point/
```
 or
```bash
sudo mount -t efs -o tls file-system-id efs-mount-point/
```

To mount without TLS, simply add the `notls` option (not available for S3 Files mounts):

```bash
sudo mount -t efs -o notls file-system-id efs-mount-point/
```

### Amazon EFS Mount Watchdog

`efs-utils` contains a watchdog process to monitor the health of TLS mounts. This process is managed by either `upstart` or `systemd` depending on your Linux distribution and `launchd` on macOS distribution, and is started automatically the first time an EFS or S3 file system is mounted over TLS.

## Troubleshooting
If you run into a problem with efs-utils, please open an issue in this repository.  We can more easily
assist you if relevant logs are provided. You can find the log file at `/var/log/amazon/efs/mount.log` for both EFS and S3 Files. Oftentimes, enabling debug level logging can help us find problems more easily. Turn on debug logging with the following commands:
```bash
# For EFS
sed -i '/logging_level = INFO/s//logging_level = DEBUG/g' /etc/amazon/efs/efs-utils.conf

# For S3 Files
sed -i '/logging_level = INFO/s//logging_level = DEBUG/g' /etc/amazon/efs/s3files-utils.conf
```

You can enable efs-proxy debug logs or stunnel debug logs with:
```bash
# For EFS
sed -i '/stunnel_debug_enabled = false/s//stunnel_debug_enabled = true/g' /etc/amazon/efs/efs-utils.conf

# For S3 Files: 
sed -i '/proxy_logging_level = INFO/s//proxy_logging_level = DEBUG/g' /etc/amazon/efs/s3files-utils.conf
```
Make sure to re run the failed mount again after running the prior commands before pulling the logs.

# Upgrading Efs-utils Versions

### Upgrading efs-utils from v1 to v2
Efs-utils v2.0.0 replaces stunnel, which provides TLS encryptions for mounts, with efs-proxy an AWS built component built. Efs-proxy is the primary the foundation for all new feature support for EFS. To receive the performance benefits of efs-proxy, you need to re-mount any existing mounts. Note: Efs-proxy is not compatible with OCSP or Mac clients. In these cases, efs-utils will automatically revert back to using stunnel. If you build efs-utils v2.0.0 from source Rust and Cargo are required for versions 1.70+.

### Upgrading from efs-utils v2 to v3
Efs-utils v3.0.0 adds support for S3 Files. There are no breaking changes upgrading from v2 to v3.0.0.

### Upgrading stunnel for RHEL/CentOS

By default, the EFS mount helper with TLS enforces certificate hostname checking. The EFS mount helper uses the `stunnel` program for its TLS functionality. Note that some versions of Linux do not include a version of `stunnel` that supports TLS features by default. When using such a Linux version, mounting an EFS file system using TLS will fail.

Once you’ve installed the `amazon-efs-utils` package, to upgrade your system’s version of `stunnel`, see [Upgrading Stunnel](https://docs.aws.amazon.com/efs/latest/ug/using-amazon-efs-utils.html#upgrading-stunnel).

# Upgrading stunnel

### Upgrading stunnel for SLES12

Run the following commands and follow the output hint of zypper package manager to upgrade the stunnel on your SLES12 instance

```bash
sudo zypper addrepo https://download.opensuse.org/repositories/security:Stunnel/SLE_12_SP5/security:Stunnel.repo
sudo zypper refresh
sudo zypper install -y stunnel
```

### Upgrading stunnel for macOS

The installation installs latest stunnel available in brew repository. You can also upgrade the version of stunnel on your instance using the command below:
```bash
brew upgrade stunnel
```

# Installing Botocore

`efs-utils` uses botocore to interact with other AWS services. Please note the package type from the above table and install
botocore based on that info. If botocore is already installed and does not meet the minimum required version,
you can upgrade the botocore by following the [upgrade botocore section](#Upgrade-botocore).

Download the `get-pip.py` script
### RPM
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
### DEB
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

To install botocore on RPM:
```bash
sudo python3 /tmp/get-pip.py
sudo pip3 install botocore || sudo /usr/local/bin/pip3 install botocore
```

To install botocore on DEB:
```bash
sudo python3 /tmp/get-pip.py
sudo pip3 install botocore || sudo /usr/local/bin/pip3 install botocore
```

Note: On Debian10 and Ubuntu20, botocore needs to be installed in a specific target folder:
```bash
sudo python3 /tmp/get-pip.py
sudo pip3 install --target /usr/lib/python3/dist-packages botocore || sudo /usr/local/bin/pip3 install --target /usr/lib/python3/dist-packages botocore
```

### macOS
```bash
sudo pip3 install botocore
```

### Upgrade botocore
Pass `--upgrade` to the corresponding installation scripts above based on system platform and distribution

```bash
sudo pip3 install botocore --upgrade
```

## Enabling CloudWatch notifications
You can optionally publish mount success and failure logs to CloudWatch Logs. This feature is disabled by default. To enable it:

Step 1. Install botocore. Follow the [install botocore section](#Install-botocore).

Step 2. Enable CloudWatch log feature in efs-utils config file `/etc/amazon/efs/efs-utils.conf`:
```bash
# For EFS
sudo sed -i -e '/\[cloudwatch-log\]/{N;s/# enabled = true/enabled = true/}' /etc/amazon/efs/efs-utils.conf

# For S3 Files
sudo sed -i -e '/\[cloudwatch-log\]/{N;s/# enabled = true/enabled = true/}' /etc/amazon/efs/s3files-utils.conf
```

For macOS:
```bash
    EFS_UTILS_VERSION=<e.g. 1.34.5>
    sudo sed -i -e '/\[cloudwatch-log\]/{N;s/# enabled = true/enabled = true/;}' /usr/local/Cellar/amazon-efs-utils/${EFS_UTILS_VERSION}/libexec/etc/amazon/efs/efs-utils.conf
```
For Mac2 instances:
```bash
    EFS_UTILS_VERSION=<e.g. 1.34.5>
    sudo sed -i -e '/\[cloudwatch-log\]/{N;s/# enabled = true/enabled = true/;}' /opt/homebrew/Cellar/amazon-efs-utils/${EFS_UTILS_VERSION}/libexec/etc/amazon/efs/efs-utils.conf
```
You can also configure CloudWatch log group name and log retention days in the config file.
If you want to have separate log groups in CloudWatch for every mounted file system, add `/{fs_id}` to the end of the `log_group_name` field in `efs-utils.conf` file. For example, the `log_group_name` in `efs-utils.conf` file would look something like:

```bash
[cloudwatch-log]
log_group_name = /aws/efs/utils/{fs_id}
```
Step 3. Attach AWS managed policy `AmazonElasticFileSystemsUtils` to the IAM role attached to the instance, or the AWS credentials
configured on your instance.

After completing these steps, you will be able to see mount status notifications in CloudWatch Logs.

## Optimizing readahead max window

Linux kernel 5.4+ introduced a change that reduced NFS client throughput. The default read_ahead_kb size dropped from 15 MB to 128 KB, forcing NFS clients to make more read calls and reducing performance. To fix this, efs-utils automatically sets read_ahead_kb to 15 * rsize (default 1MB) on Linux 5.4+ after a successful mount (not supported on macOS). This optimization is enabled by default. To disable it:

```bash
sed -i "s/optimize_readahead = true/optimize_readahead = false/" /etc/amazon/efs/efs-utils.conf

sed -i "s/optimize_readahead = true/optimize_readahead = false/" /etc/amazon/efs/s3files-utils.conf
```

To re-enable, run:

```bash
sed -i "s/optimize_readahead = false/optimize_readahead = true/" /etc/amazon/efs/efs-utils.conf

sed -i "s/optimize_readahead = false/optimize_readahead = true/" /etc/amazon/efs/s3files-utils.conf
```

You can mount file system with a given rsize, run:

```bash
# For EFS
sudo mount -t efs -o rsize=rsize-value-in-bytes file-system-id efs-mount-point/

# For S3 Files
sudo mount -t s3files -o rsize=rsize-value-in-bytes file-system-id s3files-mount-point/
```

You can also manually choose a value of read_ahead_kb to optimize read throughput on Linux 5.4+ after mount.

```bash
sudo bash -c "echo read-ahead-value-in-kb > /sys/class/bdi/0:$(stat -c '%d' efs-mount-point)/read_ahead_kb"
```

## Botocore for mount target IP

`efs-utils` supports using botocore to retrieve mount target IP address when DNS name cannot be resolved, such as when mounting a file system in another VPC. This feature is not supported for S3 Files. To use this feature, you must meet two prerequisites:

Step 1. Install botocore. Follow the [install botocore section](#Install-botocore).

Step 2. Allow the `elasticfilesystem:DescribeMountTargets` and `ec2:DescribeAvailabilityZones` action in your policy attached to
the IAM role attached to the instance, or the AWS credentials configured on your instance. We recommend you attach
AWS managed policy `AmazonElasticFileSystemsUtils`.

This feature will be enabled by default. To disable this feature:

```bash
sed -i "s/fall_back_to_mount_target_ip_address_enabled = true/fall_back_to_mount_target_ip_address_enabled = false/" /etc/amazon/efs/efs-utils.conf
```

If you decide that you do not want to use this feature, but need to mount a cross-VPC file system, you can use the mounttargetip
option to do so, using the desired mount target ip address in the mount command.

## Accessing instance metadata
`efs-utils` by default uses IMDSv2, which is a session-oriented method used to access instance metadata. If you don't want to use
IMDSv2, you can disable the token fetching feature by running the following command:

```bash
# For EFS
sed -i "s/disable_fetch_ec2_metadata_token = false/disable_fetch_ec2_metadata_token = true/" /etc/amazon/efs/efs-utils.conf

# For S3 Files
sed -i "s/disable_fetch_ec2_metadata_token = false/disable_fetch_ec2_metadata_token = true/" /etc/amazon/efs/s3files-utils.conf
```

## Assumed profile credentials for IAM
To authenticate with EFS using the system’s IAM identity of an awsprofile, add the `iam` option and pass the profile name to
`awsprofile` option. These options require the `tls` option. For S3 Files, only the `awsprofile` option is needed as the
`iam` and `tls` options are automatically applied.

```bash
# For EFS
sudo mount -t efs -o tls,iam,awsprofile=test-profile file-system-id efs-mount-point/

# For S3 Files (iam and tls are automatically applied)
sudo mount -t s3files -o awsprofile=test-profile file-system-id s3files-mount-point/
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
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

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

You can use [web identity to assume a role](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html) which has the permission to attach to the EFS file systems or the S3 file systems. You need to have a valid JWT token and a role arn to assume. There are two ways you can leverage them:

1) By setting environment variable the path to the file containing the JWT token in `AWS_WEB_IDENTITY_TOKEN_FILE` and by setting `AWS_ROLE_ARN` environment variable. The command below shows an example of to leverage it.

```bash
# For EFS
sudo mount -t efs -o tls,iam file-system-id efs-mount-point/

# For S3 Files (iam and tls are automatically applied)
sudo mount -t s3files file-system-id s3files-mount-point/
```

2) By passing the JWT token file path and the role arn as parameters to the mount command. The command below shows an example of to leverage it.

```bash
# For EFS
sudo mount -t efs -o tls,iam,rolearn="ROLE_ARN",jwtpath="PATH/JWT_TOKEN_FILE" file-system-id efs-mount-point/

# For S3 Files (iam and tls are automatically applied)
sudo mount -t s3files -o rolearn="ROLE_ARN",jwtpath="PATH/JWT_TOKEN_FILE" file-system-id s3files-mount-point/
```

## Environment Variable Support

Efs-utils supports AWS environment variables for configuring credentials and region settings, providing flexibility for  deployment scenarios. You can set the AWS profile using the `AWS_PROFILE` environment variable instead of specifying it in the mount command:

```bash
export AWS_PROFILE=my-profile
sudo mount -t efs -o tls,iam file-system-id efs-mount-point/
sudo mount -t s3files file-system-id s3files-mount-point/
```

The precedence order for AWS profile selection is:
1. Mount option: `-o awsprofile=profile-name`
2. Environment variable: `AWS_PROFILE`
3. Default profile from AWS credentials/config files

### AWS Region Environment Variables

You can set the AWS region using standard AWS environment variables:

```bash
# Using AWS_REGION (recommended)
export AWS_REGION=us-west-2
sudo mount -t efs -o tls,iam file-system-id efs-mount-point/
sudo mount -t s3files file-system-id s3files-mount-point/

# Using AWS_DEFAULT_REGION (fallback)
export AWS_DEFAULT_REGION=eu-central-1
sudo mount -t efs -o tls,iam file-system-id efs-mount-point/
sudo mount -t s3files file-system-id s3files-mount-point/
```

The precedence order for region selection is:
1. Mount option: `-o region=region-name`
2. Environment variable: `AWS_REGION`
3. Environment variable: `AWS_DEFAULT_REGION`
4. Configuration file setting
5. Instance metadata service
6. Legacy DNS format parsing

### Examples

Using environment variables for cross-region mounting:

```bash
export AWS_REGION=us-east-1
export AWS_PROFILE=cross-region-profile
sudo mount -t efs -o tls,iam fs-1234567890abcdef0:/ /mnt/efs-east
sudo mount -t s3files fs-1234567890abcdef0:/ /mnt/s3files-east
```

Using environment variables in containers or CI/CD:

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: efs-client
      env:
        - name: AWS_REGION
          value: "us-west-2"
        - name: AWS_PROFILE
          value: "eks-pod-profile"
      command:
        - mount
        - -t
        - efs
        - -o
        - tls,iam
        - fs-1234567890abcdef0:/
        - /mnt/efs-east
```
```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: efs-client
      env:
        - name: AWS_REGION
          value: "us-west-2"
        - name: AWS_PROFILE
          value: "eks-pod-profile"
      command:
        - mount
        - -t
        - s3files
        - fs-1234567890abcdef0:/
        - /mnt/s3files-east
```
## Enabling FIPS Mode
Efs-utils is able to enter FIPS mode when mounting your file system. To enable FIPS you need to modify the efs-utils config file:
```bash
# For EFS
sed -i "s/fips_mode_enabled = false/fips_mode_enabled = true/" /etc/amazon/efs/efs-utils.conf

# For S3 Files
sed -i "s/fips_mode_enabled = false/fips_mode_enabled = true/" /etc/amazon/efs/s3files-utils.conf
```
This enables any potential API call from efs-utils to use FIPS endpoints and cause proxy to enter FIPS mode. Efs-utils is configured to compile with AWS-LC FIPS module by default. For more information on AWS-LC FIPS module see [AWS-LC FIPS README](https://github.com/aws/aws-lc/blob/main/crypto/fipsmodule/FIPS.md).

## License Summary

This code is made available under the MIT license.
