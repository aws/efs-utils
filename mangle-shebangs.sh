#!/bin/bash

RPM_SYSTEM_RELEASE_PATH=/etc/system-release
RPM_OS_RELEASE_PATH=/etc/os-release
RHEL8_REGEX="Red Hat Enterprise Linux release 8"
FEDORA_REGEX="Fedora release"
CENTOS8_REGEX="CentOS Linux release 8"
SUSE15_REGEX="openSUSE Leap"

function correct_python_executable() {
    echo 'Correcting python executable'
    # Replace the first line in .py to "#!/usr/bin/env python3" no matter what it was before
    sed -i -e '1 s/^.*$/\#!\/usr\/bin\/env python3/' src/watchdog/__init__.py
    sed -i -e '1 s/^.*$/\#!\/usr\/bin\/env python3/' src/mount_efs/__init__.py
}

# RHEL8, Fedora30+ and CentOS8 treat shebangs of the form "#!/usr/bin/env python" as errors
if [ -f $RPM_SYSTEM_RELEASE_PATH ] && [[ "$(cat $RPM_SYSTEM_RELEASE_PATH)" =~ $RHEL8_REGEX|$FEDORA_REGEX|$CENTOS8_REGEX ]]; then
    correct_python_executable
fi

# OpenSUSE use python3 as default python version
if [ -f $RPM_OS_RELEASE_PATH ] && [[ $(grep PRETTY_NAME $RPM_OS_RELEASE_PATH) =~ $SUSE15_REGEX ]]; then
    correct_python_executable
fi
