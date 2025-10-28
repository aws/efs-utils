# Building efs-utils from Source

This guide provides detailed instructions for building `efs-utils` from source on various Linux distributions.

## Build Prerequisites

Building efs-utils v2.0+ requires the following dependencies:

* `rust` 1.70+
* `cargo`
* `go` 1.17.13+
* `perl`
* `cmake` 3.0+
* `gcc` and `g++` (or `gcc-c++`)
* `make`
* `git`

**Recommended Resource Size:** minimum 2 vCPUs, 4GB RAM to ensure sufficient resources for compilation. In AWS EC2, use t3.medium or larger.

## Installing Rust and Cargo

If your distribution doesn't provide a rust or cargo package, or it provides versions
that are older than 1.70, then you can install rust and cargo through rustup:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"
```

## Installing Go

Ensure you have Go 1.17.13 or later is installed and configured on your system.
Some distributions provide Go packages through package manager, but they may have outdated versions. 
```bash
# Try installing from package manager (may not be available or have outdated go version)
# RPM-based
sudo yum update -y
sudo yum -y install golang

# OpenSUSE/SLES
sudo zypper refresh
sudo zypper install -y go

# DEB-based
sudo apt-get update  
sudo apt-get -y install golang

# Verify Go 1.17.13 or later is installed
go version
```

Refer to the official [Go documentation](https://go.dev/doc/install) for detailed installation instructions of latest Go version.

## GCC Version Requirements

**For distributions with GCC 14 or later (Debian 13, Fedora 41/42, RHEL 10, openSUSE Tumbleweed):**

The AWS-LC FIPS module requires GCC version 13 or earlier. If your distribution uses GCC 14 or later by default, you'll need to use GCC 13 instead. If package manager does not provide GCC version 13 or earlier, follow [instruction](https://gcc.gnu.org/install/) to install desired version of GCC.

```bash
# Install GCC 13 (if not already installed)
# For Debian 13
sudo apt-get install -y gcc-13 g++-13

# For Fedora 41
sudo yum -y install gcc13 gcc13-c++

# For openSUSE Tumbleweed
sudo zypper install -y gcc13 gcc13-c++

# For Fedora 42 and RHEL 10, package manager does not provide GCC 13 or earlier
# Follow offical GCC instruction to install desired version of GCC
# https://gcc.gnu.org/install/

# Set GCC 13 as the compiler for the build
export CC=gcc-13
export CXX=g++-13
# Then proceed with the normal build steps
```

**Ubuntu 20.04, upgrade to use gcc-10 and g++-10**

```bash
# Install GCC 10
sudo apt-get -y install gcc-10 g++-10

# Set GCC 10 as the compiler for the build
export CC=gcc-10
export CXX=g++-10
```

**Note:** Alternatively, you can set the system default compiler using `update-alternatives` (requires sudo and affects all applications)

## CMake version requirement ##

Building AWS-LC requires CMake 3.0 or later. CMake is typically available through the standard packager manager.

**Amazon Linux 2 specific:** 

Install `cmake3` instead of `cmake`:

```bash
sudo yum -y install cmake3
```

After installation, ensure `cmake` points to version 3.0+:
```bash
sudo ln -sf $(which cmake3) /usr/bin/cmake
```

## RPM-based Distributions

### RHEL/CentOS/Amazon Linux/Fedora

```bash
sudo yum -y install git rpm-build make rust cargo openssl-devel gcc gcc-c++ cmake wget perl # remove gcc gcc-c++ here if you already installed a compatible version following GCC Version Requirements instruction
git clone https://github.com/aws/efs-utils
cd efs-utils
make rpm
sudo yum -y install build/amazon-efs-utils*rpm
```

### OpenSUSE/SLES

```bash
sudo zypper refresh
sudo zypper install -y git binutils rpm-build make rust cargo libopenssl-devel gcc gcc-c++ cmake wget perl # remove gcc gcc-c++ here if you already installed a compatible version following GCC Version Requirements instruction, if you encounter "Choose from above solutions.." in this step, remove -y flag and choose manually.
git clone https://github.com/aws/efs-utils
cd efs-utils
make rpm
sudo zypper --no-gpg-checks install -y build/amazon-efs-utils*rpm
```

## DEB-based Distributions

### Debian/Ubuntu

```bash
sudo apt-get update
sudo apt-get -y install git binutils rustc cargo libssl-dev pkg-config gettext make gcc g++ cmake wget perl # remove gcc g++ here if you already installed a compatible version following GCC Version Requirements instruction
git clone https://github.com/aws/efs-utils
cd efs-utils
./build-deb.sh
sudo apt-get -y install ./build/amazon-efs-utils*deb
```

## Common Build Issues

### OpenSUSE repository errors ###

If you encounter repository errors like `File './suse/noarch/bash-completion-2.11-2.1.noarch.rpm' not found on medium 'http://download.opensuse.org/tumbleweed/repo/oss/'` during installation of `git`, run the following commands to re-add repo OSS and NON-OSS, then run the install script above again.

```bash
sudo zypper ar -f -n OSS http://download.opensuse.org/tumbleweed/repo/oss/ OSS
sudo zypper ar -f -n NON-OSS http://download.opensuse.org/tumbleweed/repo/non-oss/ NON-OSS
sudo zypper refresh
```

### `make rpm` fails due to "feature `edition2021` is required" ###

Update to a version of rust and cargo
that is newer than 1.70. To install a new version of rust and cargo, run
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"
```

### You installed a new version of rust with the above command, but your system is still using the rust installed by the package manager ###

When installing rust with the rustup script above, the script will fail if it detects a rust already exists on the system.
Un-install the package manager's rust, and re-install rust through rustup. Once done, you will need to install rust through the package manager again to satisfy
the RPM's dependencies.
```bash
yum remove cargo rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
yum install cargo rust
. "$HOME/.cargo/env"
```

### When you run `make rpm`, compilation of efs-proxy fails due to `error: linker cc not found` ###

Make sure that you have a linker installed on your system. For example, on Amazon Linux or RHEL, install gcc with
```bash
yum install gcc
```

### Installation Issue - Failed Build Dependencies ###

If rust dependencies was installed using rustup and the package manager does not have a rust and/or cargo package installed, you may see an error like this.

```
error: Failed build dependencies:
    cargo is needed by amazon-efs-utils-2.1.0-1.el7_9.x86_64
    rust is needed by amazon-efs-utils-2.1.0-1.el7_9.x86_64
```

In this case, the 'make rpm' command in the installation script above should be replaced by 'make rpm-without-system-rust' to remove the rpmbuild dependency check.

### AWS-LC FIPS module build issue: WARNING: FIPS build is known to fail on GCC >= 14 ### 

For Debian 13, Fedora 41/42, RHEL 10 and openSUSE Tumbleweed, default GCC version is higher than 14, follow instructions in GCC Version Requirements to install a compatiable GCC version.

### AWS-LC FIPS module build issue: Your compiler (cc) is not supported due to a memcmp related bug reported ### 

For Ubuntu 20.04, GCC installed from package manager on Ubuntu 20.04 show this error during build, follow instructions in GCC Version Requirements to install a compatiable GCC version.


## Running Tests

After building from source, you can run the test suite:

1. Set up a virtualenv:

```bash
virtualenv ~/.envs/efs-utils
source ~/.envs/efs-utils/bin/activate
pip install -r requirements.txt
```

2. Run tests:

```bash
make test
```

## Verifying Installation

After installation, verify efs-utils is working:

```bash
mount.efs --version
```

## Next Steps

See the main [README](efs-utils.README.md) for usage instructions and configuration options.
