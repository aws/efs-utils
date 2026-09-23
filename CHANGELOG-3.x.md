# v3.3.2
- Improve watchdog handling of zombie proxy threads
- Fix read_ahead_kb being overwritten on certain distros
- Reject empty cafiles on mount

# v3.3.1
- Schedule TLS cert refresh from credential expiration
- Don't denylist file handles for transient S3 errors on readbypass path

# v3.3.0
- Eliminate unnecessary data copies on the readbypass path
- Consolidating dependencies
- Upgrade AWS-LC-FIPS module to 4.x

# v3.2.0
- Use partition-aware DNS suffix for S3 Files for aws-cn
- Add regex for region mount option

# v3.1.3
- Rollback DNS Query Change

# v3.1.2
- Fix channel init deadline establishment
- Update STS endpoint resolution
- Add RHEL10 support to efs-utils

# v3.1.1
- Update proxy connection scaling logic
- Fix IndexError in get_system_release_version on SUSE SLES 16

# v3.1.0
- Enable readahead caching in proxy for bypassed reads
- Clean up warnings in proxy

# v3.0.1
- Fix proxy crash on NFS error in READ_BYPASS response

# v3.0.0
- Add support for s3files
