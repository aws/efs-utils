[![CircleCI](https://circleci.com/gh/aws/efs-utils.svg?style=svg)](https://circleci.com/gh/aws/efs-utils)

# efs-utils

Utilities for Amazon Elastic File System (EFS)

The `efs-utils` package has been verified against the following Linux distributions:

| Distribution | Package Type | `init` System | Python Env|
| ------------ | ------------ | ------------- | --------- |
| Amazon Linux 2017.09 | `rpm` | `upstart` | Python2 |
| Amazon Linux 2 | `rpm` | `systemd` | Python2 |
| CentOS 7 | `rpm` | `systemd` | Python2 |
| CentOS 8 | `rpm` | `systemd` | Python3 |
| RHEL 7 | `rpm`| `systemd` | Python2 |
| RHEL 8 | `rpm`| `systemd` | Python3 |
| Fedora 28 | `rpm` | `systemd` | Python3 |
| Fedora 29 | `rpm` | `systemd` | Python3 |
| Fedora 30 | `rpm` | `systemd` | Python3 |
| Fedora 31 | `rpm` | `systemd` | Python3 |
| Fedora 32 | `rpm` | `systemd` | Python3 |
| Debian 9 | `deb` | `systemd` | Python2 |
| Debian 10 | `deb` | `systemd` | Python2 |
| Ubuntu 16.04 | `deb` | `systemd` | Python2 |
| Ubuntu 18.04 | `deb` | `systemd` | Python3 |
| Ubuntu 20.04 | `deb` | `systemd` | Python3 |

## Prerequisites

* `nfs-utils` (RHEL/CentOS/Amazon Linux/Fedora) or `nfs-common` (Debian/Ubuntu)
* OpenSSL 1.0.2+
* Python 2.7+
* `stunnel` 4.56+

## Installation

### On Amazon Linux distributions

For those using Amazon Linux or Amazon Linux 2, the easiest way to install `efs-utils` is from Amazon's repositories:

```
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

```
$ sudo yum -y install git rpm-build make
$ git clone https://github.com/aws/efs-utils
$ cd efs-utils
$ make rpm
$ sudo yum -y install build/amazon-efs-utils*rpm
```

- To build and install a Debian package:

```
$ sudo apt-get update
$ sudo apt-get -y install git binutils
$ git clone https://github.com/aws/efs-utils
$ cd efs-utils
$ ./build-deb.sh
$ sudo apt-get -y install ./build/amazon-efs-utils*deb
```

#### Run tests

- [Set up a virtualenv](http://libzx.so/main/learning/2016/03/13/best-practice-for-virtualenv-and-git-repos.html) for efs-utils

```
$ virtualenv ~/.envs/efs-utils
$ source ~/.envs/efs-utils/bin/activate
$ pip install -r requirements.txt
```

- Run tests

```
$ make test
```

## Usage

### mount.efs

`efs-utils` includes a mount helper utility to simplify mounting and using EFS file systems.

To mount with the recommended default options, simply run:

```
$ sudo mount -t efs file-system-id efs-mount-point/
```

To mount file system within a given network namespace, run:

```
$ sudo mount -t efs -o netns=netns-path file-system-id efs-mount-point/
```

To mount over TLS, simply add the `tls` option:

```
$ sudo mount -t efs -o tls file-system-id efs-mount-point/
```

To authenticate with EFS using the system’s IAM identity, add the `iam` option. This option requires the `tls` option.

```
$ sudo mount -t efs -o tls,iam file-system-id efs-mount-point/
```

To mount using an access point, use the `accesspoint=` option. This option requires the `tls` option.
The access point must be in the "available" state before it can be used to mount EFS.

```
$ sudo mount -t efs -o tls,accesspoint=access-point-id file-system-id efs-mount-point/
```

To mount your file system automatically with any of the options above, you can add entries to `/efs/fstab` like:

```
file-system-id efs-mount-point efs _netdev,tls,iam,accesspoint=access-point-id 0 0
```

For more information on mounting with the mount helper, see the manual page:

```
man mount.efs
```

or refer to the [documentation](https://docs.aws.amazon.com/efs/latest/ug/using-amazon-efs-utils.html).

### amazon-efs-mount-watchdog

`efs-utils` contains a watchdog process to monitor the health of TLS mounts. This process is managed by either `upstart` or `systemd` depending on your Linux distribution, and is started automatically the first time an EFS file system is mounted over TLS.

## Upgrading stunnel for RHEL/CentOS

By default, when using the EFS mount helper with TLS, it enforces certificate hostname checking. The EFS mount helper uses the `stunnel` program for its TLS functionality. Please note that some versions of Linux do not include a version of `stunnel` that supports TLS features by default. When using such a Linux version, mounting an EFS file system using TLS will fail. 

Once you’ve installed the `amazon-efs-utils` package, to upgrade your system’s version of `stunnel`, see [Upgrading Stunnel](https://docs.aws.amazon.com/efs/latest/ug/using-amazon-efs-utils.html#upgrading-stunnel).

## Enable mount success/failure notification via CloudWatch log
`efs-utils` now support publishing mount success/failure logs to CloudWatch log. By default, this feature is disabled. There are three
steps you must follow to enable and use this feature:

### Step 1. Install botocore
`efs-utils` uses botocore to interact with CloudWatch log service . Please note the package type and 
python env from the above table. 
- To install botocore on RPM
```bash
# Python2
sudo python /tmp/get-pip.py
sudo pip install botocore || sudo /usr/local/bin/pip install botocore

# Python3
sudo python3 /tmp/get-pip.py
sudo pip3 install botocore || sudo /usr/local/bin/pip3 install botocore
```
- To install botocore on DEB
```bash
sudo apt-get update
sudo apt-get -y install wget
wget https://bootstrap.pypa.io/get-pip.py -O /tmp/get-pip.py

# Python2
sudo python /tmp/get-pip.py
sudo pip install botocore || sudo /usr/local/bin/pip install botocore

# On Debian10, the botocore needs to be installed in specific target folder
sudo python /tmp/get-pip.py
sudo pip install --target /usr/lib/python2.7/dist-packages botocore || sudo /usr/local/bin/pip install --target /usr/lib/python2.7/dist-packages botocore

# Python3
sudo python3 /tmp/get-pip.py
sudo pip3 install botocore || sudo /usr/local/bin/pip3 install botocore

# On Ubuntu20, the botocore needs to be installed in specific target folder
sudo python3 /tmp/get-pip.py
sudo pip3 install --target /usr/lib/python3/dist-packages botocore || sudo /usr/local/bin/pip3 install --target /usr/lib/python3/dist-packages botocore
```

### Step 2. Enable CloudWatch log feature in efs-utils config file `/etc/amazon/efs/efs-utils.conf`
```bash
sudo sed -i -e '/\[cloudwatch-log\]/{N;s/# enabled = true/enabled = true/}' /etc/amazon/efs/efs-utils.conf
```
You can also configure CloudWatch log group name and log retention days in the config file. 

### Step 3. Attach the CloudWatch logs policy to the IAM role attached to instance.
Attach AWS managed policy `AmazonElastciFileSystemsUtils` to the iam role you attached to the instance, or the aws credentials
configured on your instance.

After completing the three prerequisite steps, you will be able to see mount status notifications in CloudWatch Logs.

## License Summary

This code is made available under the MIT license.

