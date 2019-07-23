#!/bin/bash

SYSTEM_RELEASE_PATH=/etc/system-release

if [ -f $SYSTEM_RELEASE_PATH ] && [[ "$(cat $SYSTEM_RELEASE_PATH)" =~ "Red Hat Enterprise Linux release 8" ]]; then
    # Replace the first line in .py to "#!/usr/bin/env python2" no matter what it was before
    sed -i -e '1 s/^.*$/\#!\/usr\/bin\/env python2/' src/watchdog/__init__.py
    sed -i -e '1 s/^.*$/\#!\/usr\/bin\/env python2/' src/mount_efs/__init__.py
fi
