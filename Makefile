#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

PACKAGE_NAME = amazon-efs-utils
SOURCE_TARBALL = $(PACKAGE_NAME).tar.gz
BUILD_DIR = build
BUILD_DIR_RPM = $(BUILD_DIR)/rpmbuild
BUILD_DIR_DEB = $(BUILD_DIR)/debbuild
RPM_SPECFILE = $(PACKAGE_NAME).rpm.spec
DEB_SPECFILE = $(PACKAGE_NAME).deb.spec
RPM_BUILD_FLAGS ?= --with system_rust
export PYTHONPATH := $(shell pwd)/src

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
	rm -rf $(PACKAGE_NAME)
	rm -f $(SOURCE_TARBALL)

.PHONY: tarball
tarball: clean
	mkdir -p $(PACKAGE_NAME)

	mkdir -p $(PACKAGE_NAME)/dist
	cp -p dist/amazon-efs-mount-watchdog.conf $(PACKAGE_NAME)/dist
	cp -p dist/amazon-efs-mount-watchdog.service $(PACKAGE_NAME)/dist
	cp -p dist/efs-utils.conf $(PACKAGE_NAME)/dist
	cp -p dist/efs-utils.crt $(PACKAGE_NAME)/dist

	mkdir -p $(PACKAGE_NAME)/src
	cp -rp src/mount_efs $(PACKAGE_NAME)/src
	cp -rp src/watchdog $(PACKAGE_NAME)/src
	cp -rp src/proxy $(PACKAGE_NAME)/src

	mkdir -p ${PACKAGE_NAME}/man
	cp -rp man/mount.efs.8 ${PACKAGE_NAME}/man

	tar -czf $(SOURCE_TARBALL) $(PACKAGE_NAME)/*

.PHONY: sources
sources: tarball

.PHONY: rpm-only
rpm-only:
	mkdir -p $(BUILD_DIR_RPM)/{SPECS,COORD_SOURCES,DATA_SOURCES,BUILD,RPMS,SOURCES,SRPMS}
	cp $(RPM_SPECFILE) $(BUILD_DIR_RPM)/SPECS
	cp $(SOURCE_TARBALL) $(BUILD_DIR_RPM)/SOURCES
	cp config.toml $(BUILD_DIR_RPM)/SOURCES
	rpmbuild -ba --define "_topdir `pwd`/$(BUILD_DIR_RPM)" --define "include_vendor_tarball false" $(BUILD_DIR_RPM)/SPECS/$(RPM_SPECFILE) $(RPM_BUILD_FLAGS)
	cp $(BUILD_DIR_RPM)/RPMS/*/*rpm build

.PHONY: rpm
rpm: sources rpm-only

.PHONY: rpm-without-system-rust
rpm-without-system-rust: sources
	$(MAKE) rpm-only RPM_BUILD_FLAGS="--without system_rust"

.PHONY: deb
deb: clean
	$(eval BUILD_ARCH := $(shell dpkg --print-architecture))
	$(eval RELEASE := $(shell grep Version $(PACKAGE_NAME).deb.spec | cut -d : -f 2 | xargs))
	$(eval VERSION := $(shell grep Version $(PACKAGE_NAME).deb.spec | cut -d : -f 3 | xargs))

	# Build efs-proxy
	cargo build --release --manifest-path src/proxy/Cargo.toml

	# Setup package file tree
	mkdir -p $(BUILD_DIR_DEB)/DEBIAN
	mkdir -p ${BUILD_DIR_DEB}/etc/amazon/efs
	mkdir -p ${BUILD_DIR_DEB}/etc/init/
	mkdir -p ${BUILD_DIR_DEB}/etc/systemd/system
	mkdir -p ${BUILD_DIR_DEB}/sbin
	mkdir -p ${BUILD_DIR_DEB}/usr/bin
	mkdir -p ${BUILD_DIR_DEB}/usr/share/man/man8
	mkdir -p ${BUILD_DIR_DEB}/var/log/amazon/efs

	# Setup DEBIAN directory
	cp $(DEB_SPECFILE) $(BUILD_DIR_DEB)/DEBIAN/control
	sed -i "s/^Architecture: .*/Architecture: $(BUILD_ARCH)/" $(BUILD_DIR_DEB)/DEBIAN/control
	echo '/etc/amazon/efs/efs-utils.conf' > ${BUILD_DIR_DEB}/DEBIAN/conffiles
	install -p -m 755 dist/scriptlets/after-install-upgrade ${BUILD_DIR_DEB}/DEBIAN/postinst
	install -p -m 755 dist/scriptlets/before-remove ${BUILD_DIR_DEB}/DEBIAN/prerm
	install -p -m 755 dist/scriptlets/after-remove ${BUILD_DIR_DEB}/DEBIAN/postrm

	# Copy efs-utils files
	install -p -m 644 dist/amazon-efs-mount-watchdog.conf ${BUILD_DIR_DEB}/etc/init
	install -p -m 644 dist/amazon-efs-mount-watchdog.service ${BUILD_DIR_DEB}/etc/systemd/system
	install -p -m 444 dist/efs-utils.crt ${BUILD_DIR_DEB}/etc/amazon/efs
	install -p -m 644 dist/efs-utils.conf ${BUILD_DIR_DEB}/etc/amazon/efs
	install -p -m 755 src/mount_efs/__init__.py ${BUILD_DIR_DEB}/sbin/mount.efs
	install -p -m 755 src/proxy/target/release/efs-proxy ${BUILD_DIR_DEB}/usr/bin/efs-proxy
	install -p -m 755 src/watchdog/__init__.py ${BUILD_DIR_DEB}/usr/bin/amazon-efs-mount-watchdog
	install -p -m 644 man/mount.efs.8 ${BUILD_DIR_DEB}/usr/share/man/man8/mount.efs.8

	# Compress man page
	gzip ${BUILD_DIR_DEB}/usr/share/man/man8/mount.efs.8

	# Build DEB
	dpkg-deb --build $(BUILD_DIR_DEB) $(BUILD_DIR)/$(PACKAGE_NAME)_$(VERSION)_$(RELEASE).$(BUILD_ARCH).deb

.PHONY: test
test:
	pytest
	flake8
