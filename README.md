[![CircleCI](https://circleci.com/gh/aws/efs-utils.svg?style=svg)](https://circleci.com/gh/aws/efs-utils)

# efs-utils

Utilities for Amazon Elastic File System (EFS)

The `efs-utils` package has been verified against the following Linux distributions:

| Distribution | Package Type | `init` System |
| ------------ | ------------ | ------------- |
| Amazon Linux 2017.09 | `rpm` | `upstart` |
| Amazon Linux 2 | `rpm` | `systemd` |
| CentOS 7 | `rpm` | `systemd` |
| RHEL 7 | `rpm`| `systemd` |
| RHEL 8 | `rpm`| `systemd` |
| Debian 9 | `deb` | `systemd` |
| Debian 10 | `deb` | `systemd` |
| Ubuntu 16.04 | `deb` | `systemd` |
| Ubuntu 18.04 | `deb` | `systemd` |

## Prerequisites

* `nfs-utils` (RHEL/CentOS/Amazon Linux) or `nfs-common` (Debian/Ubuntu)
* OpenSSL 1.0.2+
* Python 2.7+
* `stunnel` 4.56+

## Installation

### On Amazon Linux distributions

For those using Amazon Linux or Amazon Linux 2, the easiest way to install `efs-utils` is from Amazon's repositories:

```
$ sudo yum -y install amazon-efs-utils
```

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

## License Summary

This code is made available under the MIT license.

