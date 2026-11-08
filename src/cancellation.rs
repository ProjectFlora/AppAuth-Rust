use tokio_util::sync::CancellationToken;

#[derive(Clone, Default)]
pub struct CancellationHandle {
    token: CancellationToken,
}

impl CancellationHandle {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.token.cancel();
    }

    pub fn is_cancelled(&self) -> bool {
        self.token.is_cancelled()
    }

    pub async fn cancelled(&self) {
        self.token.cancelled().await;
    }
}
