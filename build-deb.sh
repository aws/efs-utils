#!/usr/bin/env sh
#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

set -ex

BASE_DIR=$(pwd)
BUILD_ROOT=${BASE_DIR}/build/debbuild

echo 'Cleaning deb build workspace'
rm -rf ${BUILD_ROOT}
mkdir -p ${BUILD_ROOT}

echo 'Creating application directories'
mkdir -p ${BUILD_ROOT}/etc/amazon/efs
mkdir -p ${BUILD_ROOT}/etc/init/
mkdir -p ${BUILD_ROOT}/etc/systemd/system
mkdir -p ${BUILD_ROOT}/sbin
mkdir -p ${BUILD_ROOT}/usr/bin
mkdir -p ${BUILD_ROOT}/var/log/amazon/efs

echo 'Copying application files'
install -p -m 644 dist/amazon-efs-mount-watchdog.conf ${BUILD_ROOT}/etc/init
install -p -m 644 dist/amazon-efs-mount-watchdog.service ${BUILD_ROOT}/etc/systemd/system
install -p -m 644 dist/efs-utils.conf ${BUILD_ROOT}/etc/amazon/efs
install -p -m 755 src/mount_efs/__init__.py ${BUILD_ROOT}/sbin/mount.efs
install -p -m 755 src/watchdog/__init__.py ${BUILD_ROOT}/usr/bin/amazon-efs-mount-watchdog

echo 'Copying install scripts'
install -p -m 755 dist/scriptlets/before-upgrade ${BUILD_ROOT}/preinst
install -p -m 755 dist/scriptlets/after-install-upgrade ${BUILD_ROOT}/postinst
install -p -m 755 dist/scriptlets/before-remove ${BUILD_ROOT}/prerm
install -p -m 755 dist/scriptlets/after-remove ${BUILD_ROOT}/postrm

echo 'Copying control file'
install -p -m 644 dist/amazon-efs-utils.control ${BUILD_ROOT}/control

echo 'Creating deb binary file'
echo '2.0'> ${BUILD_ROOT}/debian-binary

echo 'Setting permissions'
find ${BUILD_ROOT} -type d | xargs chmod 755;

echo 'Creating tar'
cd ${BUILD_ROOT}
tar czf control.tar.gz control preinst postinst prerm postrm --owner=0 --group=0
tar czf data.tar.gz etc sbin usr var --owner=0 --group=0
cd ${BASE_DIR}

echo 'Building deb'
DEB=${BUILD_ROOT}/amazon-efs-utils-1.0-1.deb
ar r ${DEB} ${BUILD_ROOT}/debian-binary
ar r ${DEB} ${BUILD_ROOT}/control.tar.gz
ar r ${DEB} ${BUILD_ROOT}/data.tar.gz

echo 'Copying deb to output directory'
cp ${BUILD_ROOT}/amazon-efs-utils*deb build/
