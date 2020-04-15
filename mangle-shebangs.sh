#!/bin/bash

SYSTEM_RELEASE_PATH=/etc/system-release
RHEL8_REGEX="Red Hat Enterprise Linux release 8"
FEDORA_REGEX="Fedora release"
CENTOS8_REGEX="CentOS Linux release 8"

# RHEL8 and Fedora30+ both treat shebangs of the form "#!/usr/bin/env python" as errors
if [ -f $SYSTEM_RELEASE_PATH ] && [[ "$(cat $SYSTEM_RELEASE_PATH)" =~ $RHEL8_REGEX|$FEDORA_REGEX|$CENTOS8_REGEX ]]; then
    # Replace the first line in .py to "#!/usr/bin/env python2" no
    # matter what it was before
    sed -i -e '1 s/^.*$/\#!\/usr\/bin\/env python2/' src/watchdog/__init__.py
    sed -i -e '1 s/^.*$/\#!\/usr\/bin\/env python2/' src/mount_efs/__init__.py
fi
