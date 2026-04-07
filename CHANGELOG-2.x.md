# v2.4.2
- Skip stunnel binary invocation when efs-proxy mode is enabled
- Retry "access denied" only for access point mounting
- Fix issue for missing PATH in env when check stunnel lib
- Fix EFS_FQDN_RE to support ADC DNS suffixes with hyphens
- Fix IPv6-only mount target FQDN resolution in match_device

# v2.4.1
- Add cafile override for eusc-de-east-1 in efs-utils.conf

# v2.4.0
- Upgrade s2n-tls version in efs-proxy to use AWS-LC
- Add ubuntu24 and macOS Tahoe support efs-utils

# v2.3.3
- Reset Cargo.lock version number to 3. Using version 4 caused issues for customers using older rust versions.
- Add environment variable support for AWS profiles and regions

# v2.3.2
- Fix package version numbering

# v2.3.0
- Add support for pod-identity credentials in the credentials chain
- Enable mounting with IPv6 when using with the 'stunnel' mount option

# v2.2.1
- Readme Updates
- Update log4rs to mitigate CVE-2020-35881

# v2.2.0
- Use region-specific domain suffixes for dns endpoints where missing
- Merge PR #211 - Amend Debian control to use binary architecture

# v2.1.0
- Add mount option for specifying region
- Add new ISO regions to config file

# v2.0.4
- Add retry logic to and increase timeout for EC2 metadata token retrieval requests

# v2.0.3
- Upgrade py version
- Replace deprecated usage of datetime

# v2.0.2
- Check for efs-proxy PIDs when cleaning tunnel state files
- Add PID to log entries

# v2.0.1
- Disable Nagle's algorithm for efs-proxy TLS mounts to improve latencies

# v2.0.0
- Replace stunnel, which provides TLS encryptions for mounts, with efs-proxy, a component built in-house at AWS. Efs-proxy lays the foundation for upcoming feature launches at EFS.