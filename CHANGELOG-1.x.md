# v1.36.0
- Support new mount option: crossaccount, conduct cross account mounts via ip address. Use client AZ-ID to choose mount target.

# v1.35.2
- Revert "Add warning if using older Version"
- Support MacOS Sonoma

# v1.35.1
- Add 'fsap' to ignored mount option list
- Accept openssl 3.0 in rpm spec file
- Watchdog now prints a log message if efs-utils is on an old version
- Regenerate the private key if the file is empty

# v1.35.0
- Support MacOS Ventura, Oracle8 distribution
- Add debug statement for size of state file write
- Add parameters in mount options for assume web role with web identity

# v1.34.5
- Watchdog detect empty private key and regenerate
- Update man page
- Avoid redundant get_target_region call
- Handle invalid mount point name

# v1.34.4
- Fix potential tlsport selection collision by using state file as tlsport lock file.

# v1.34.3
- Fix potential tlsport selection race condition by closing socket right before establishing stunnel
- Fix stunnel constantly restart issue when upgrading from 1.32.1 and before version to latest version
- Speed up the way to check network availability by using systemctl is-active

# v1.34.2
- Fix potential issue on AL2 when watchdog trying to restart stunnel for the TLS mounts that existing before upgrade

# v1.34.1
- Update Amazon Linux 2 platform to use namespaced stunnel5

# v1.33.4
- Fix potential issue where watchdog sending signal to incorrect processes.
- Add support for enabling FIPS mode for both stunnel and AWS API calls.

# v1.33.3
- Fix potential stunnel hanging issue caused by full subprocess PIPE filled by stunnel log.

# v1.33.2
- Fix the incorrect path to generate read_ahead_kb config file.
- Bump the default tls port range from 400 to 1000.

# v1.33.1
- Enable mount process to retry on failed or timed out mount.nfs command.

# v1.32.2
- Fix potential race condition issue when stunnel creating pid file.

# v1.32.1
- Enable watchdog to check stunnel health periodically and restart hanging stunnel process when necessary.
- Fix potential race condition issue when removing lock files.
- Add efs-utils Support for MacOS Monterey EC2 instances.

# v1.31.3
- Add unmount_time and unmount_count to handle inconsistent mount reads
- Allow specifying fs_id in cloudwatch log group name

# v1.31.2
- Handle the fallback to IMDSv1 call when either HTTPError or unknown exception is thrown
- Cleanup private key lock file at watchdog startup

# v1.31.1
- Support new option: mounttargetip, enable mount file system to specific mount target ip address
- Support using botocore to retrieve and mount via file system mount target ip address when DNS resolution fails
- Use IMDSv2 by default to access instance metadata service

# v1.30.2
- Fix the throughput regression due to read_ahead configuration change on Linux distribution with kernel version 5.4.x and above

# v1.30.1
- Support new option: az, enable mount file system to specific availability zone mount target
- Merge PR #84 on Github. Fix to use regional AWS STS endpoints instead of the global endpoint to reduce latency

# v1.29.1
- Update the python dependency to python3
- Support SLES and OpenSUSE

# v1.28.2
- Fix an issue where fs cannot be mounted with iam using instance profile when IMDSv2 is enabled

# v1.28.1
- Introduce botocore to publish mount success/failure notification to cloudwatch log
- Revert stop emitting unrecognized init system supervisord if the watchdog daemon has already been launched by supervisor check

# v1.27.1
- Merge PR #60 on GitHub. Adds support for AssumeRoleWithWebIdentity

# v1.26.3
- Fix an issue where watchdog crashed during restart because stunnel was killed and pid key was removed from state file

# v1.26.2
- Clean up stunnel PIDs in state files persisted by previous efs-csi-driver to ensure watchdog spawns a new stunnel after driver restarts.
- Fix an issue where fs cannot be mounted with tls using systemd.automount-units due to mountpoint check

# v1.25.3
- Fix an issue where subprocess was not killed successfully
- Stop emitting unrecognized init system supervisord if the watchdog daemon has already been launched by supervisor
- Support Fedora
- Check if mountpoint is already mounted beforehand for tls mount

# v1.25.2
- Fix the issue that IAM role name format is not correctly encoded in python3
- Add optional override for stunnel debug log output location

# v1.25.1
- Create self-signed certificate for tls-only mount

# v1.24.4
- Fix the malformed certificate info

# v1.24.3
- Use IMDSv1 by default, and use IMDSv2 where required

# v1.24.2
- List which as dependency

# v1.24.1
- Enable efs-utils to source region from config file for sigv4 auth
- Fix the issue that stunnel bin exec cannot be found in certain linux distributions

# v1.23.2
- Support new option: netns, enable file system to mount in given network namespace
- Support new option: awscredsuri, enable sourcing iam authorization from aws credentials relative uri
- List openssl and util-linux as package dependency for IAM/AP authorization and command nsenter to mount file system to given network namespace