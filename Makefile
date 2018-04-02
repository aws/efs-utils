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

clean:
	rm -rf $(BUILD_DIR)
	rm -f $(SOURCE_TARBALL)
	rm -f $(SPECFILE)

tarball: clean
	mkdir -p $(PACKAGE_NAME)
	cp -rp dist $(PACKAGE_NAME)
	cp -rp src $(PACKAGE_NAME)
	tar -czf $(SOURCE_TARBALL) $(PACKAGE_NAME)/*

specfile: clean
	ln -sf dist/$(SPECFILE) $(SPECFILE)

sources: tarball specfile

rpm-only:
	mkdir -p $(BUILD_DIR)/{SPECS,COORD_SOURCES,DATA_SOURCES,BUILD,RPMS,SOURCES,SRPMS}
	cp $(SPECFILE) $(BUILD_DIR)/SPECS
	cp $(SOURCE_TARBALL) $(BUILD_DIR)/SOURCES
	rpmbuild -ba --define "_topdir `pwd`/$(BUILD_DIR)" $(BUILD_DIR)/SPECS/$(SPECFILE)
	cp $(BUILD_DIR)/RPMS/*/*rpm build

rpm: sources rpm-only

.PHONY: test
test:
	pytest
	flake8