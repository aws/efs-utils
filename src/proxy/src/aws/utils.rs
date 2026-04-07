//! AWS utility functions
//!

use hyper::client::HttpConnector;
use hyper::{Body, Client, Method, Request};

/// Get EC2 instance ID using IMDSv2
/// As recommended in <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html>
///
pub async fn get_ec2_instance_id() -> Result<String, Box<dyn std::error::Error>> {
    let client: Client<HttpConnector> = Client::new();

    // Get session token
    let token_request = Request::builder()
        .method(Method::PUT)
        .uri("http://169.254.169.254/latest/api/token")
        .header("X-aws-ec2-metadata-token-ttl-seconds", "21600")
        .body(Body::empty())?;

    let token_response = client.request(token_request).await?;
    let token_bytes = hyper::body::to_bytes(token_response.into_body()).await?;
    let token = String::from_utf8(token_bytes.to_vec())?;

    // Get instance ID
    let instance_id_request = Request::builder()
        .method(Method::GET)
        .uri("http://169.254.169.254/latest/meta-data/instance-id")
        .header("X-aws-ec2-metadata-token", &token)
        .body(Body::empty())?;

    let instance_id_response = client.request(instance_id_request).await?;
    let instance_id_bytes = hyper::body::to_bytes(instance_id_response.into_body()).await?;
    let instance_id = String::from_utf8(instance_id_bytes.to_vec())?;

    Ok(instance_id)
}
