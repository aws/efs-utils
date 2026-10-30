use super::CloudWatchClient;
use crate::config_parser::ProxyConfig;
use crate::sync::Arc;

pub async fn new_publisher(
    _proxy_config: &ProxyConfig,
    _namespace: &str,
) -> Option<Arc<dyn CloudWatchClient>> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aws::cw_publisher::CW_NAMESPACE_EFS;

    #[tokio::test]
    async fn test_new_publisher_builds_nothing() {
        assert!(new_publisher(&ProxyConfig::default(), CW_NAMESPACE_EFS)
            .await
            .is_none());
    }
}
