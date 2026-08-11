/*
 * AWS FILE SERVICES PROGRAM
 */

#define INCLUDE_NFS4_PROGRAMS 0
#include "nfs4_prot.x"

const PROXY_ID_LENGTH = 16;
const PROXY_INCARNATION_LENGTH = 8;
const NFS_STATE_PARTITION_ID_LENGTH = 64;

enum OperationType {
    OP_BIND_CLIENT_TO_PARTITION = 2,
    OP_AWS_FILE_CHANNEL_INIT    = 3
};

enum AwsFileResponse {
         AWSFILE_OK                  = 0, /* succeeded */
         AWSFILE_ERR_RETRY_LATER     = 1, /* server busy, retry */
         AWSFILE_ERR_INVAL           = 2  /* invalid arguments or API unavailable */
};

typedef opaque NfsStatePartitionId[NFS_STATE_PARTITION_ID_LENGTH];

struct ProxyIdentifier {
        opaque identifier<PROXY_ID_LENGTH>;
        opaque incarnation<PROXY_INCARNATION_LENGTH>;
};

struct ScaleUpConfig {
        int max_multiplexed_connections;
        int scale_up_bytes_per_sec_threshold;
        int scale_up_threshold_breached_duration_sec;
        int scale_up_lookback_window_size_sec;
};

enum BindResponseType {
        RETRY = 0,
        RETRY_LATER = 1,
        PREFERRED = 2,
        READY = 3,
        ERROR = 4
};

union BindResponse switch (BindResponseType type) {
        case PREFERRED:
        case READY:
                NfsStatePartitionId partition_id;
        case RETRY:
        case RETRY_LATER:
                String retry_later_msg;
        case ERROR:
                String error_msg;
        default:
                void;
};

struct BindClientResponse {
        BindResponse bind_response;
        ScaleUpConfig scale_up_config;
};

enum AwsFileChannelConfigTypes {
        AWSFILE_READ_BYPASS             = 4,
        AWSFILE_READ_BYPASS_V2          = 5
};

/* v1 read bypass config */
struct AwsFileReadBypassConfigArgs {
        bool        enabled;
};

/* v2 read bypass config - adds efs_utils_version */
struct AwsFileReadBypassConfigArgsV2 {
        bool        enabled;
        opaque      efs_utils_version<>;
};

union ChannelConfigArgs switch (AwsFileChannelConfigTypes config_type) {
case AWSFILE_READ_BYPASS:
        AwsFileReadBypassConfigArgs     read_bypass_config;
case AWSFILE_READ_BYPASS_V2:
        AwsFileReadBypassConfigArgsV2   read_bypass_config_v2;
};

struct AwsFileChannelInitArgs {
        unsigned int                    minor_version;
        ChannelConfigArgs               configs<>;
};

/* v1 read bypass response */
struct AwsFileReadBypassConfigRes {
        bool                            enabled;
        opaque                          bucket_name<>;
        opaque                          prefix<>;
};

/* v2 read bypass response - adds readahead_cache_enabled */
struct AwsFileReadBypassConfigResV2 {
        bool                            enabled;
        opaque                          bucket_name<>;
        opaque                          prefix<>;
        bool                            readahead_cache_enabled;
};

union ChannelConfigRes switch (AwsFileChannelConfigTypes config_type) {
case AWSFILE_READ_BYPASS:
        AwsFileReadBypassConfigRes     read_bypass_config;
case AWSFILE_READ_BYPASS_V2:
        AwsFileReadBypassConfigResV2   read_bypass_config_v2;
};

struct AwsFileChannelInitResOK {
        ChannelConfigRes                configs<>;
};

union AwsFileChannelInitRes switch (AwsFileResponse init_status) {
case AWSFILE_OK:
        AwsFileChannelInitResOK         channel_init_resok;
default:
/* Other operations or error responses will return void response */
        void;
};

/* Definition of the AWSFILE_PROGRAM program.
 *
 * The program is an extension of NFS4 and extra features are introduced as new
 * procedures and NFS operations
 *
 * program AWSFILE_PROGRAM {
 *         version AWSFILE_V1 {
 *                 void
 *                         NFSPROC4_NULL(void) = 0;
 * 
 *                 COMPOUND4res
 *                         NFSPROC4_COMPOUND(COMPOUND4args) = 1;
 * 
 *                 BindClientResponse
 *                         bind_client_to_partition(ProxyIdentifier) = 2;
 * 
 *                 AwsFileChannelInitRes
 *                         awsfile_channel_init(AwsFileChannelInitArgs) = 3;
 *         } = 1;
 * } = 400123;
 * 
 * program AWSFILE_CALLBACK {
 *         version AWSFILE_CB_V1 {
 *                 void
 *                         CB_NULL(void) = 0;
 * 
 *                 CB_COMPOUND4res
 *                         CB_COMPOUND(CB_COMPOUND4args) = 1;
 *         } = 1;
 * } = 400124;
 */