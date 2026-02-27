/*
* EFS program V1
*/

const PROXY_ID_LENGTH = 16;
const PROXY_INCARNATION_LENGTH = 8;
const PARTITION_ID_LENGTH = 64;

enum OperationType {
    OP_BIND_CLIENT_TO_PARTITION = 1
};

typedef opaque PartitionId[PARTITION_ID_LENGTH];

struct ProxyIdentifier {
    opaque identifier<PROXY_ID_LENGTH>;
    opaque incarnation<PROXY_INCARNATION_LENGTH>;
};

struct ScaleUpConfig {
    int max_multiplexed_connections;
    int scale_up_bytes_per_sec_threshold;
    int scale_up_threshold_breached_duration_sec;
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
        PartitionId partition_id;
    case RETRY:
    case RETRY_LATER:
        String stop_msg;
    case ERROR:
        String error_msg;
    default:
        void;
};

struct BindClientResponse {
    BindResponse bind_response;
    ScaleUpConfig scale_up_config;
};
