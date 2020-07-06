#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

%if 0%{?amzn1}
%global python_requires system-python

%else

%if 0%{?fedora} || 0%{?el8}
%global python_requires python3
%else
%global python_requires python2
%endif

%endif

%if 0%{?amzn1} || 0%{?rhel} == 6
%global with_systemd 0
%else
%global with_systemd 1
%endif

# Discard this when efs-utils gotes to semver
%global src_name efs-utils

Name      : amazon-efs-utils
Version   : 1.26.3
Release   : 0%{?dist}
Summary   : This package provides utilities for simplifying the use of EFS file systems

Group     : Amazon/Tools
License   : MIT
URL       : https://aws.amazon.com/efs

Packager  : Amazon.com, Inc. <http://aws.amazon.com>
Vendor    : Amazon.com

BuildArch : noarch

Requires  : nfs-utils
Requires  : stunnel >= 4.56
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

Source    : https://github.com/aws/efs-utils/archive/v%{version}.tar.gz

%description
This package provides utilities for simplifying the use of EFS file systems

%prep
%setup -n %{src_name}-%{version}

%install
mkdir -p %{buildroot}%{_sysconfdir}/amazon/efs
%if %{with_systemd}
mkdir -p %{buildroot}%{_unitdir}
install -p -m 644 %{_builddir}/%{src_name}-%{version}/dist/amazon-efs-mount-watchdog.service %{buildroot}%{_unitdir}
%else
mkdir -p %{buildroot}%{_sysconfdir}/init
install -p -m 644 %{_builddir}/%{src_name}-%{version}/dist/amazon-efs-mount-watchdog.conf %{buildroot}%{_sysconfdir}/init
%endif

mkdir -p %{buildroot}/sbin
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_localstatedir}/log/amazon/efs
mkdir -p  %{buildroot}%{_mandir}/man8

%global base_dir %{src_name}-%{version}

install -p -m 644 %{_builddir}/%{src_name}-%{version}/dist/efs-utils.conf %{buildroot}%{_sysconfdir}/amazon/efs
install -p -m 444 %{_builddir}/%{src_name}-%{version}/dist/efs-utils.crt %{buildroot}%{_sysconfdir}/amazon/efs
install -p -m 755 %{_builddir}/%{src_name}-%{version}/src/mount_efs/__init__.py %{buildroot}/sbin/mount.efs
install -p -m 755 %{_builddir}/%{src_name}-%{version}/src/watchdog/__init__.py %{buildroot}%{_bindir}/amazon-efs-mount-watchdog
install -p -m 644 %{_builddir}/%{src_name}-%{version}/man/mount.efs.8 %{buildroot}%{_mandir}/man8

%files
%defattr(-,root,root,-)
%if %{with_systemd}
%{_unitdir}/amazon-efs-mount-watchdog.service
%else
%config(noreplace) %{_sysconfdir}/init/amazon-efs-mount-watchdog.conf
%endif
%{_sysconfdir}/amazon/efs/efs-utils.crt
/sbin/mount.efs
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
* Mon Jul 6 3030 Nico Kadel-Garcia <nkadel@gmail.com> - 1.25.2=0
- Switch to semver package numbering
- Add download URL to Source

* Tue May 26 2020 Yuan Gao <ygaochn@amazon.com> - 1.25-3
- Fix an issue where subprocess was not killed successfully
- Stop emitting unrecognized init system supervisord if the watchdog daemon has already been launched by supervisor
- Support Fedora
- Check if mountpoint is already mounted beforehand for tls mount

* Tue May 05 2020 Yuan Gao <ygaochn@amazon.com> - 1.25-2
- Fix the issue that IAM role name format is not correctly encoded in python3
- Add optional override for stunnel debug log output location

* Mon Apr 20 2020 Yuan Gao <ygaochn@amazon.com> - 1.25-1
- Create self-signed certificate for tls-only mount

* Tue Apr 7 2020 Yuan Gao <ygaochn@amazon.com> - 1.24-4
- Fix the malformed certificate info

* Fri Mar 27 2020 Yuan Gao <ygaochn@amazon.com> - 1.24-3
- Use IMDSv1 by default, and use IMDSv2 where required

* Tue Mar 10 2020 Yuan Gao <ygaochn@amazon.com> - 1.24-2
- List which as dependency

* Tue Mar 10 2020 Yuan Gao <ygaochn@amazon.com> - 1.24-1
- Enable efs-utils to source region from config file for sigv4 auth
- Fix the issue that stunnel bin exec cannot be found in certain linux distributions

* Tue Mar 03 2020 Yuan Gao <ygaochn@amazon.com> - 1.23-2
- Support new option: netns, enable file system to mount in given network namespace
- Support new option: awscredsuri, enable sourcing iam authorization from aws credentials relative uri
- List openssl and util-linux as package dependency for IAM/AP authorization and command nsenter to mount file system to given network namespace
