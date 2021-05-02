#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

PACKAGE_NAME = amazon-efs-utils
VERSION = 1.30.2
SOURCE_TARBALL = $(PACKAGE_NAME)-$(VERSION).tar.gz
SPECFILE = $(PACKAGE_NAME).spec
BUILD_DIR = build/rpmbuild
export PYTHONPATH := $(shell pwd)/src

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
	rm -rf $(PACKAGE_NAME)
	rm -f *.gz
	rm -f *.spec

.PHONY: tarball
tarball: clean
	mkdir -p $(PACKAGE_NAME)-$(VERSION)

	mkdir -p $(PACKAGE_NAME)-$(VERSION)/dist
	cp -p dist/amazon-efs-mount-watchdog.conf $(PACKAGE_NAME)-$(VERSION)/dist
	cp -p dist/amazon-efs-mount-watchdog.service $(PACKAGE_NAME)-$(VERSION)/dist
	cp -p dist/efs-utils.conf $(PACKAGE_NAME)-$(VERSION)/dist
	cp -p dist/efs-utils.crt $(PACKAGE_NAME)-$(VERSION)/dist

	mkdir -p $(PACKAGE_NAME)-$(VERSION)/src
	cp -rp src/mount_efs $(PACKAGE_NAME)-$(VERSION)/src
	cp -rp src/watchdog $(PACKAGE_NAME)-$(VERSION)/src

	mkdir -p ${PACKAGE_NAME}-$(VERSION)/man
	cp -rp man/mount.efs.8 ${PACKAGE_NAME}-$(VERSION)/man

	tar -czf $(SOURCE_TARBALL) $(PACKAGE_NAME)-$(VERSION)/*

.PHONY: sources
sources: tarball

.PHONLY: $(SPECFILE)
$(SPECFILE): $(SPECFILE).in
	sed 's/^Version:.*/Version:    $(VERSION)/g' $? > $@

.PHONY: rpm-only
rpm-only:: $(TARBALL)
rpm-only:: $(SPECFILE)
	mkdir -p $(BUILD_DIR)/{SPECS,COORD_SOURCES,DATA_SOURCES,BUILD,RPMS,SOURCES,SRPMS}
	rpmbuild -ba \
		--define "_topdir `pwd`/$(BUILD_DIR)" \
		--define '_sourcedir $(PWD)' \
		$(SPECFILE)
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
