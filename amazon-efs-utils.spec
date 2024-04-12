#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

%bcond_without check

%if 0%{?amzn1}
%global python_requires python36
%else
%global python_requires python3
%endif

%if 0%{?amzn1} || 0%{?rhel} == 6
%global with_systemd 0
%else
%global with_systemd 1
%endif

%if 0%{?dist:1}
%global platform %{dist}
%else
%if 0%{?suse_version}
%global platform .suse
%else
%global platform .unknown
%endif
%endif

%if 0%{?amzn} > 2
%global efs_bindir %{_sbindir}
%else
%global efs_bindir /sbin
%endif

%global proxy_name efs-proxy
%global proxy_version 2.0.0

%{?!include_vendor_tarball:%define include_vendor_tarball true}

Name      : amazon-efs-utils
Version   : 2.0.0
Release   : 1%{platform}
Summary   : This package provides utilities for simplifying the use of EFS file systems

Group     : Amazon/Tools
License   : MIT
URL       : https://aws.amazon.com/efs

BuildArchitectures: x86_64 aarch64

Requires  : nfs-utils
%if 0%{?amzn2}
Requires  : stunnel5
%else
Requires  : stunnel >= 4.56
%endif
Requires  : %{python_requires}

Requires  : openssl >= 1.0.2
Requires  : util-linux
Requires  : which

%if %{with_systemd}
BuildRequires    : systemd
%{?systemd_requires}
%else
Requires(post)   : /sbin/chkconfig
Requires(preun)  : /sbin/service /sbin/chkconfig
Requires(postun) : /sbin/service
%endif

BuildRequires  : cargo rust
BuildRequires: openssl-devel

Source0    : %{name}.tar.gz
%if "%{include_vendor_tarball}" == "true"
Source1    : %{proxy_name}-%{proxy_version}-vendor.tar.xz
Source2    : config.toml
%endif

%description
This package provides utilities for simplifying the use of EFS file systems

%global debug_package %{nil}

%prep
%setup -n %{name}
mkdir -p %{_builddir}/%{name}/src/proxy/.cargo
%if "%{include_vendor_tarball}" == "true"
cp %{SOURCE2} %{_builddir}/%{name}/src/proxy/.cargo/
tar xf %{SOURCE1}
mv vendor %{_builddir}/%{name}/src/proxy/
%endif

%build
cd %{_builddir}/%{name}/src/proxy
cargo build --release --manifest-path %{_builddir}/%{name}/src/proxy/Cargo.toml

%install
mkdir -p %{buildroot}%{_sysconfdir}/amazon/efs
%if %{with_systemd}
mkdir -p %{buildroot}%{_unitdir}
install -p -m 644 %{_builddir}/%{name}/dist/amazon-efs-mount-watchdog.service %{buildroot}%{_unitdir}
%else
mkdir -p %{buildroot}%{_sysconfdir}/init
install -p -m 644 %{_builddir}/%{name}/dist/amazon-efs-mount-watchdog.conf %{buildroot}%{_sysconfdir}/init
%endif

mkdir -p %{buildroot}%{efs_bindir}
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_localstatedir}/log/amazon/efs
mkdir -p  %{buildroot}%{_mandir}/man8

install -p -m 644 %{_builddir}/%{name}/dist/efs-utils.conf %{buildroot}%{_sysconfdir}/amazon/efs
install -p -m 444 %{_builddir}/%{name}/dist/efs-utils.crt %{buildroot}%{_sysconfdir}/amazon/efs
install -p -m 755 %{_builddir}/%{name}/src/mount_efs/__init__.py %{buildroot}%{efs_bindir}/mount.efs
install -p -m 755 %{_builddir}/%{name}/src/watchdog/__init__.py %{buildroot}%{_bindir}/amazon-efs-mount-watchdog
install -p -m 644 %{_builddir}/%{name}/man/mount.efs.8 %{buildroot}%{_mandir}/man8
install -p -m 755 %{_builddir}/%{name}/src/proxy/target/release/efs-proxy %{buildroot}%{efs_bindir}/efs-proxy

%files
%defattr(-,root,root,-)
%if %{with_systemd}
%{_unitdir}/amazon-efs-mount-watchdog.service
%else
%config(noreplace) %{_sysconfdir}/init/amazon-efs-mount-watchdog.conf
%endif
%{_sysconfdir}/amazon/efs/efs-utils.crt
%{efs_bindir}/mount.efs
%{efs_bindir}/efs-proxy
%{_bindir}/amazon-efs-mount-watchdog
/var/log/amazon
%{_mandir}/man8/mount.efs.8.gz

%config(noreplace) %{_sysconfdir}/amazon/efs/efs-utils.conf

%if %{with_systemd}
%post
%systemd_post amazon-efs-mount-watchdog.service

%preun
%systemd_preun amazon-efs-mount-watchdog.service

%postun
%systemd_postun_with_restart amazon-efs-mount-watchdog.service

%else

%preun
if [ $1 -eq 0 ]; then
   /sbin/stop amazon-efs-mount-watchdog &> /dev/null || true
fi

%postun
if [ $1 -eq 1 ]; then
    /sbin/restart amazon-efs-mount-watchdog &> /dev/null || true
fi

%endif

%clean

%changelog
* Mon Apr 08 2024 Ryan Stankiewicz <rjstank@amazon.com> - 2.0.0
- Replace stunnel, which provides TLS encryptions for mounts, with efs-proxy, a component built in-house at AWS. Efs-proxy lays the foundation for upcoming feature launches at EFS. 

* Mon Mar 18 2024 Sean Zatz <zatzsea@amazon.com> - 1.36.0
- Support new mount option: crossaccount, conduct cross account mounts via ip address. Use client AZ-ID to choose mount target.

* Fri Feb 09 2024 Rakesh Yelisetty <rakeshye@amazon.com> - 1.35.2
- Revert "Add warning if using older Version"
- Support MacOS Sonoma

* Wed Jan 10 2024 Sean Zatz <zatsea@amazon.com> - 1.35.1
- Add 'fsap' to ignored mount option list
- Accept openssl 3.0 in rpm spec file
- Watchdog now prints a log message if efs-utils is on an old version
- Regenerate the private key if the file is empty

* Wed Mar 15 2023 Soyeon Ju <mjsoyeon@amazon.com> - 1.35.0
- Support MacOS Ventura, Oracle8 distribution
- Add debug statement for size of state file write
- Add parameters in mount options for assume web role with web identity

* Wed Jan 1 2023 Ryan Stankiewicz <rjstank@amazon.com> - 1.34.5
- Watchdog detect empty private key and regenerate
- Update man page
- Avoid redundant get_target_region call
- Handle invalid mount point name

* Tue Dec 13 2022 Ryan Stankiewicz <rjstank@amazon.com> - 1.34.4
- Fix potential tlsport selection collision by using state file as tlsport lock file.

* Thu Dec 1 2022 Preetham Puneeth Munipalli <tmunipre@amazon.com> - 1.34.3
- Fix potential tlsport selection race condition by closing socket right before establishing stunnel
- Fix stunnel constantly restart issue when upgrading from 1.32.1 and before version to latest version
- Speed up the way to check network availability by using systemctl is-active

* Tue Nov 22 2022 Preetham Puneeth Munipalli <tmunipre@amazon.com> - 1.34.2
- Fix potential issue on AL2 when watchdog trying to restart stunnel for the TLS mounts that existing before upgrade

* Thu Sep 29 2022 Preetham Puneeth Munipalli <tmunipre@amazon.com> - 1.34.1
- Update Amazon Linux 2 platform to use namespaced stunnel5

* Thu Sep 1 2022 Yuan Gao <ygaochn@amazon.com> - 1.33.4
- Fix potential issue where watchdog sending signal to incorrect processes.
- Add support for enabling FIPS mode for both stunnel and AWS API calls.

* Wed Jul 13 2022 Yuan Gao <ygaochn@amazon.com> - 1.33.3
- Fix potential stunnel hanging issue caused by full subprocess PIPE filled by stunnel log.

* Mon Jun 6 2022 Yuan Gao <ygaochn@amazon.com> - 1.33.2
- Fix the incorrect path to generate read_ahead_kb config file.
- Bump the default tls port range from 400 to 1000.

* Fri May 6 2022 Yuan Gao <ygaochn@amazon.com> - 1.33.1
- Enable mount process to retry on failed or timed out mount.nfs command.

* Thu Apr 28 2022 Yuan Gao <ygaochn@amazon.com> - 1.32.2
- Fix potential race condition issue when stunnel creating pid file.

* Thu Mar 31 2022 Shivam Gupta <lshigupt@amazon.com> - 1.32.1
- Enable watchdog to check stunnel health periodically and restart hanging stunnel process when necessary.
- Fix potential race condition issue when removing lock files.
- Add efs-utils Support for MacOS Monterey EC2 instances.

* Tue Nov 23 2021 Jigar Dedhia <dedhiajd@amazon.com> - 1.31.3
- Add unmount_time and unmount_count to handle inconsistent mount reads
- Allow specifying fs_id in cloudwatch log group name

* Thu Jun 10 2021 Yuan Gao <ygaochn@amazon.com> - 1.31.2
- Handle the fallback to IMDSv1 call when either HTTPError or unknown exception is thrown
- Cleanup private key lock file at watchdog startup

* Thu May 06 2021 Yuan Gao <ygaochn@amazon.com> - 1.31.1
- Support new option: mounttargetip, enable mount file system to specific mount target ip address
- Support using botocore to retrieve and mount via file system mount target ip address when DNS resolution fails
- Use IMDSv2 by default to access instance metadata service

* Thu Apr 15 2021 Yue Wang <wangnyue@amazon.com> - 1.30.2
- Fix the throughput regression due to read_ahead configuration change on Linux distribution with kernel version 5.4.x and above

* Mon Mar 22 2021 Yuan Gao <ygaochn@amazon.com> - 1.30.1
- Support new option: az, enable mount file system to specific availability zone mount target
- Merge PR #84 on Github. Fix to use regional AWS STS endpoints instead of the global endpoint to reduce latency

* Mon Jan 25 2021 Yuan Gao <ygaochn@amazon.com> - 1.29.1
- Update the python dependency to python3
- Support SLES and OpenSUSE

* Thu Oct 8 2020 Yuan Gao <ygaochn@amazon.com> - 1.28.2
- Fix an issue where fs cannot be mounted with iam using instance profile when IMDSv2 is enabled

* Fri Sep 18 2020 Yuan Gao <ygaochn@amazon.com> - 1.28.1
- Introduce botocore to publish mount success/failure notification to cloudwatch log
- Revert stop emitting unrecognized init system supervisord if the watchdog daemon has already been launched by supervisor check

* Tue Aug 4 2020 Karthik Basavaraj <kbbasav@amazon.com> - 1.27.1
- Merge PR #60 on GitHub. Adds support for AssumeRoleWithWebIdentity

* Wed Jul 1 2020 Yuan Gao <ygaochn@amazon.com> - 1.26.3
- Fix an issue where watchdog crashed during restart because stunnel was killed and pid key was removed from state file

* Tue Jun 16 2020 Karthik Basavaraj <kbbasav@amazon.com> - 1.26.2
- Clean up stunnel PIDs in state files persisted by previous efs-csi-driver to ensure watchdog spawns a new stunnel after driver restarts.
- Fix an issue where fs cannot be mounted with tls using systemd.automount-units due to mountpoint check

* Tue May 26 2020 Yuan Gao <ygaochn@amazon.com> - 1.25.3
- Fix an issue where subprocess was not killed successfully
- Stop emitting unrecognized init system supervisord if the watchdog daemon has already been launched by supervisor
- Support Fedora
- Check if mountpoint is already mounted beforehand for tls mount

* Tue May 05 2020 Yuan Gao <ygaochn@amazon.com> - 1.25.2
- Fix the issue that IAM role name format is not correctly encoded in python3
- Add optional override for stunnel debug log output location

* Mon Apr 20 2020 Yuan Gao <ygaochn@amazon.com> - 1.25.1
- Create self-signed certificate for tls-only mount

* Tue Apr 7 2020 Yuan Gao <ygaochn@amazon.com> - 1.24.4
- Fix the malformed certificate info

* Fri Mar 27 2020 Yuan Gao <ygaochn@amazon.com> - 1.24.3
- Use IMDSv1 by default, and use IMDSv2 where required

* Tue Mar 10 2020 Yuan Gao <ygaochn@amazon.com> - 1.24.2
- List which as dependency

* Tue Mar 10 2020 Yuan Gao <ygaochn@amazon.com> - 1.24.1
- Enable efs-utils to source region from config file for sigv4 auth
- Fix the issue that stunnel bin exec cannot be found in certain linux distributions

* Tue Mar 03 2020 Yuan Gao <ygaochn@amazon.com> - 1.23.2
- Support new option: netns, enable file system to mount in given network namespace
- Support new option: awscredsuri, enable sourcing iam authorization from aws credentials relative uri
- List openssl and util-linux as package dependency for IAM/AP authorization and command nsenter to mount file system to given network namespace
