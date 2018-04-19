#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

PACKAGE_NAME = amazon-efs-utils
SOURCE_TARBALL = $(PACKAGE_NAME).tar.gz
SPECFILE = $(PACKAGE_NAME).spec
BUILD_DIR = build/rpmbuild
export PYTHONPATH := $(shell pwd)/src

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
	rm -rf $(PACKAGE_NAME)
	rm -f $(SOURCE_TARBALL)
	rm -f $(SPECFILE)

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

	tar -czf $(SOURCE_TARBALL) $(PACKAGE_NAME)/*

.PHONY: specfile
specfile: clean
	ln -sf dist/$(SPECFILE) $(SPECFILE)

.PHONY: sources
sources: tarball specfile

.PHONY: rpm-only
rpm-only:
	mkdir -p $(BUILD_DIR)/{SPECS,COORD_SOURCES,DATA_SOURCES,BUILD,RPMS,SOURCES,SRPMS}
	cp $(SPECFILE) $(BUILD_DIR)/SPECS
	cp $(SOURCE_TARBALL) $(BUILD_DIR)/SOURCES
	rpmbuild -ba --define "_topdir `pwd`/$(BUILD_DIR)" $(BUILD_DIR)/SPECS/$(SPECFILE)
	cp $(BUILD_DIR)/RPMS/*/*rpm build

.PHONY: rpm
rpm: sources rpm-only

.PHONY: deb
deb:
	./build-deb.sh

.PHONY: test
test:
	pytest
	flake8