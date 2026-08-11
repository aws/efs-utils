//! AWS utility functions
//!

/// Get EC2 instance ID using IMDSv2
/// As recommended in <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html>
///
/// Uses `aws_config`'s IMDS client, which acquires and caches the IMDSv2 session
/// token, resolves the IMDS endpoint, and retries transient failures.
pub async fn get_ec2_instance_id() -> Result<String, Box<dyn std::error::Error>> {
    let client = aws_config::imds::Client::builder().build();
    let instance_id = client.get("/latest/meta-data/instance-id").await?;
    Ok(instance_id.into())
}
