# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.

"""
Singleton that centralizes mount operation state. Calling mount
multiple times at once (eg if one mount is hanging) will happen
in different processes, so there is no risk of cross-contamination
between MountContexts in concurrent processes.
"""


class MountContext:
    _instance = None
    _initialized = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(MountContext, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if not self._initialized:
            self.cloudwatch_agent = None
            self.instance_identity = None
            self.instance_az_id_metadata = None
            self.unsupported_options = []
            self.proxy_mode = None
            self.service = None
            self.fqdn_regex_pattern = None
            self.mount_type = None
            self.config_file_path = None
            self._initialized = True

    # For testing
    def reset(self):
        self.cloudwatch_agent = None
        self.instance_identity = None
        self.instance_az_id_metadata = None
        self.unsupported_options = []
        self.proxy_mode = None
        self.service = None
        self.fqdn_regex_pattern = None
        self.mount_type = None
        self.config_file_path = None
        # _initialized should stay True since we're just resetting values
