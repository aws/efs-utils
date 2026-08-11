use uuid::Uuid;

use crate::awsfile_prot;
use crate::error::RpcError;

pub const INITIAL_INCARNATION: i64 = 0;

#[derive(Eq, PartialEq, Clone, Copy, Debug)]
pub struct ProxyIdentifier {
    pub uuid: Uuid,
    pub incarnation: i64,
}

impl Default for ProxyIdentifier {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxyIdentifier {
    pub fn new() -> Self {
        ProxyIdentifier {
            uuid: Uuid::new_v4(),
            incarnation: INITIAL_INCARNATION,
        }
    }

    pub fn increment(&mut self) {
        if self.incarnation == i64::MAX {
            self.incarnation = 0;
            return;
        }
        self.incarnation += 1;
    }
}

impl Into<awsfile_prot::ProxyIdentifier> for ProxyIdentifier {
    fn into(self) -> awsfile_prot::ProxyIdentifier {
        awsfile_prot::ProxyIdentifier {
            identifier: self.uuid.as_bytes().to_vec(),
            incarnation: self.incarnation.to_be_bytes().to_vec(),
        }
    }
}

impl TryFrom<awsfile_prot::ProxyIdentifier> for ProxyIdentifier {
    type Error = RpcError;

    fn try_from(raw_proxy_id: awsfile_prot::ProxyIdentifier) -> Result<Self, Self::Error> {
        Ok(ProxyIdentifier {
            uuid: uuid::Builder::from_bytes(
                raw_proxy_id
                    .identifier
                    .try_into()
                    .map_err(|_| RpcError::MalformedResponse)?,
            )
            .into_uuid(),
            incarnation: i64::from_be_bytes(
                raw_proxy_id
                    .incarnation
                    .try_into()
                    .map_err(|_| RpcError::MalformedResponse)?,
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::ProxyIdentifier;
    use super::INITIAL_INCARNATION;

    #[test]
    fn test_increment() {
        let mut proxy_id = ProxyIdentifier::default();
        let proxy_id_original = proxy_id;
        for i in 0..5 {
            assert_eq!(i, proxy_id.incarnation);
            proxy_id.increment();
        }
        assert_eq!(proxy_id_original.uuid, proxy_id.uuid);
        assert_eq!(INITIAL_INCARNATION, proxy_id_original.incarnation);
    }

    #[test]
    fn test_wrap_around() {
        let mut proxy_id = ProxyIdentifier::new();
        let proxy_id_original = proxy_id;
        proxy_id.incarnation = i64::MAX;
        proxy_id.increment();
        assert_eq!(proxy_id_original.uuid, proxy_id.uuid);
        assert_eq!(INITIAL_INCARNATION, proxy_id.incarnation);
    }
}
