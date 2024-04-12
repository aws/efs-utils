use uuid::Uuid;

pub const INITIAL_INCARNATION: i64 = 0;

#[derive(Eq, PartialEq, Clone, Copy, Debug)]
pub struct ProxyIdentifier {
    pub uuid: Uuid,
    pub incarnation: i64,
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

#[cfg(test)]
mod tests {
    use super::ProxyIdentifier;
    use super::INITIAL_INCARNATION;

    #[test]
    fn test_increment() {
        let mut proxy_id = ProxyIdentifier::new();
        let proxy_id_original = proxy_id.clone();
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
        let proxy_id_original = proxy_id.clone();
        proxy_id.incarnation = i64::MAX;
        proxy_id.increment();
        assert_eq!(proxy_id_original.uuid, proxy_id.uuid);
        assert_eq!(INITIAL_INCARNATION, proxy_id.incarnation);
    }
}
