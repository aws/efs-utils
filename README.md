# efs-utils

Utilities for Amazon Elastic File System (EFS)

The `efs-utils` package has been verified against the following Linux distributions:

| Distribution | Package Type | `init` System |
| ------------ | ------------ | ------------- |
| Amazon Linux 2017.09 | `rpm` | `upstart` |
| Amazon Linux 2 | `rpm` | `systemd` |
| CentOS 7 | `rpm` | `systemd` |
| RHEL 7 | `rpm`| `systemd` |
| Debian 9 | `deb` | `systemd` |
| Ubuntu 16.04 | `deb` | `systemd` |

## Installation

### On Amazon Linux distributions

For those using Amazon Linux or Amazon Linux 2, the easiest way to install `efs-utils` is from Amazon's repositories:

```
$ sudo yum -y install amazon-efs-utils
```

### On other Linux distributions

Other distributions require building the package from source and installing it.

- Clone this repository:

```
$ git clone https://github.com/aws/efs-utils
$ cd efs-utils
```

- To build and install an RPM:

```
$ sudo yum -y install rpm-build
$ make rpm
$ sudo yum -y install build/amazon-efs-utils*rpm
```

- To build and install a Debian package:

```
$ sudo apt-get update
$ sudo apt-get -y install binutils
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

To mount automatically with recommended options, add an `/etc/fstab` entry like:

```
file-system-id efs-mount-point efs _netdev 0 0
```

To mount over TLS, simply add the `tls` option:

```
$ sudo mount -t efs -o tls file-system-id efs-mount-point/
```

To mount over TLS automatically, add an `/etc/fstab` entry like:

```
file-system-id efs-mount-point efs _netdev,tls 0 0
```

For cases where DNS isn't enabled, use an IP address in-place of file-system-id

```
$ sudo mount -t efs 1.2.3.4 efs-mount-point/
```

For more information on mounting with the mount helper, see the [documentation](https://docs.aws.amazon.com/efs/latest/ug/using-amazon-efs-utils.html).

#### amazon-efs-mount-watchdog

`efs-utils` contains a watchdog process to monitor the health of TLS mounts. This process is managed by either `upstart` or `systemd` depending on your Linux distribution, and is started automatically the first time an EFS file system is mounted over TLS.

## License Summary

This code is made available under the MIT license.

