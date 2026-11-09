use tokio_util::sync::CancellationToken;

#[derive(Clone, Default)]
/// A cloneable cancellation signal shared by an operation and its transport.
pub struct CancellationHandle {
    token: CancellationToken,
}

impl CancellationHandle {
    /// Creates a cancellation handle that is not cancelled.
    pub fn new() -> Self {
        Self::default()
    }

    /// Cancels the operation; repeated calls have no additional effect.
    pub fn cancel(&self) {
        self.token.cancel();
    }

    /// Returns whether cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.token.is_cancelled()
    }

    /// Waits until cancellation is requested.
    pub async fn cancelled(&self) {
        self.token.cancelled().await;
    }
}
