//! Usage tracking for metered APIs.
//!
//! This module provides utilities for tracking API usage, especially
//! for streaming responses where usage is recorded after completion.

use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use tokio::sync::mpsc;

use crate::context::AuthContext;
use argus_client::SharedArgusClient;
use argus_types::UserId;

/// Usage event to be recorded.
#[derive(Debug, Clone)]
pub struct UsageEvent {
    /// User ID for the usage.
    pub user_id: UserId,
    /// Metric name (e.g., "api_calls", "tokens").
    pub metric: String,
    /// Count to record.
    pub count: u64,
    /// Optional metadata.
    pub metadata: Option<std::collections::HashMap<String, String>>,
}

impl UsageEvent {
    /// Create a new usage event.
    #[must_use]
    pub fn new(user_id: UserId, metric: impl Into<String>, count: u64) -> Self {
        Self {
            user_id,
            metric: metric.into(),
            count,
            metadata: None,
        }
    }

    /// Add metadata to the event.
    #[must_use]
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata
            .get_or_insert_with(std::collections::HashMap::new)
            .insert(key.into(), value.into());
        self
    }
}

/// Background task for fire-and-forget usage recording.
///
/// This recorder accepts usage events via a channel and records them
/// asynchronously to avoid blocking request handlers.
#[derive(Clone, Debug)]
pub struct UsageRecorder {
    tx: mpsc::Sender<UsageEvent>,
}

impl UsageRecorder {
    /// Create a new usage recorder with the given Argus client.
    ///
    /// Returns the recorder and a handle to the background task.
    pub fn new(client: SharedArgusClient, buffer_size: usize) -> (Self, UsageRecorderHandle) {
        let (tx, rx) = mpsc::channel(buffer_size);

        let handle = UsageRecorderHandle {
            task: tokio::spawn(Self::run_background(client, rx)),
        };

        (Self { tx }, handle)
    }

    /// Record a usage event (fire-and-forget).
    ///
    /// This method does not block; events are queued for background processing.
    pub fn record(&self, event: UsageEvent) {
        // Try to send, but don't block if buffer is full
        let _ = self.tx.try_send(event);
    }

    /// Record a simple usage count.
    pub fn record_count(&self, user_id: UserId, metric: impl Into<String>, count: u64) {
        self.record(UsageEvent::new(user_id, metric, count));
    }

    async fn run_background(client: SharedArgusClient, mut rx: mpsc::Receiver<UsageEvent>) {
        while let Some(event) = rx.recv().await {
            // Record usage to Argus (fire-and-forget)
            let client_guard = client.read().await;
            let mut billing = client_guard.billing();

            // Record usage with individual parameters
            if let Err(e) = billing
                .record_usage(&event.user_id, &event.metric, event.count, event.metadata)
                .await
            {
                tracing::warn!(
                    error = %e,
                    metric = %event.metric,
                    count = event.count,
                    "Failed to record usage"
                );
            }
        }
    }
}

/// Handle for the background usage recorder task.
pub struct UsageRecorderHandle {
    task: tokio::task::JoinHandle<()>,
}

impl UsageRecorderHandle {
    /// Wait for the recorder to finish processing.
    pub async fn shutdown(self) {
        let _ = self.task.await;
    }
}

/// Usage tracker for accumulating usage during a request.
///
/// This is useful for streaming responses where the final usage
/// count isn't known until the stream completes.
#[derive(Debug, Clone)]
pub struct UsageTracker {
    user_id: UserId,
    metric: String,
    count: Arc<AtomicU64>,
    recorder: Option<UsageRecorder>,
}

impl UsageTracker {
    /// Create a new usage tracker.
    #[must_use]
    pub fn new(user_id: UserId, metric: impl Into<String>) -> Self {
        Self {
            user_id,
            metric: metric.into(),
            count: Arc::new(AtomicU64::new(0)),
            recorder: None,
        }
    }

    /// Set the recorder to use when flushing.
    #[must_use]
    pub fn with_recorder(mut self, recorder: UsageRecorder) -> Self {
        self.recorder = Some(recorder);
        self
    }

    /// Add to the usage count.
    pub fn add(&self, count: u64) {
        self.count
            .fetch_add(count, std::sync::atomic::Ordering::Relaxed);
    }

    /// Get the current usage count.
    #[must_use]
    pub fn count(&self) -> u64 {
        self.count.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Flush the accumulated usage to the recorder.
    pub fn flush(&self) {
        let count = self.count.swap(0, std::sync::atomic::Ordering::Relaxed);
        if count > 0 {
            if let Some(recorder) = &self.recorder {
                recorder.record_count(self.user_id, &self.metric, count);
            }
        }
    }
}

/// Auth guard for streaming responses.
///
/// This struct holds both the auth context and a usage tracker.
/// When dropped, it automatically flushes accumulated usage.
///
/// # Example
///
/// ```ignore
/// async fn stream_handler(auth: RequireAuth) -> impl IntoResponse {
///     let guard = StreamingAuthGuard::new(auth.0, recorder);
///
///     let stream = async_stream::stream! {
///         for i in 0..100 {
///             guard.tracker().add(1);
///             yield Ok::<_, Error>(format!("chunk {i}"));
///         }
///     };
///
///     // Usage is recorded when guard is dropped
///     Body::from_stream(stream)
/// }
/// ```
#[derive(Debug)]
pub struct StreamingAuthGuard {
    /// The authentication context.
    pub auth: AuthContext,
    /// The usage tracker.
    tracker: UsageTracker,
    /// Whether to flush on drop.
    flush_on_drop: bool,
}

impl StreamingAuthGuard {
    /// Create a new streaming auth guard.
    #[must_use]
    pub fn new(auth: AuthContext, recorder: UsageRecorder, metric: impl Into<String>) -> Self {
        let tracker = UsageTracker::new(auth.user_id, metric).with_recorder(recorder);
        Self {
            auth,
            tracker,
            flush_on_drop: true,
        }
    }

    /// Create without automatic flush on drop.
    #[must_use]
    pub fn without_auto_flush(mut self) -> Self {
        self.flush_on_drop = false;
        self
    }

    /// Get the usage tracker.
    #[must_use]
    pub fn tracker(&self) -> &UsageTracker {
        &self.tracker
    }

    /// Manually flush usage.
    pub fn flush(&self) {
        self.tracker.flush();
    }
}

impl Drop for StreamingAuthGuard {
    fn drop(&mut self) {
        if self.flush_on_drop {
            self.tracker.flush();
        }
    }
}

impl std::ops::Deref for StreamingAuthGuard {
    type Target = AuthContext;

    fn deref(&self) -> &Self::Target {
        &self.auth
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argus_types::Tier;

    #[test]
    fn test_usage_event_builder() {
        let event = UsageEvent::new(UserId::new(), "tokens", 100)
            .with_metadata("model", "gpt-4")
            .with_metadata("provider", "openai");

        assert_eq!(event.metric, "tokens");
        assert_eq!(event.count, 100);

        let meta = event.metadata.unwrap();
        assert_eq!(meta.get("model"), Some(&"gpt-4".to_string()));
    }

    #[test]
    fn test_usage_tracker() {
        let tracker = UsageTracker::new(UserId::new(), "api_calls");

        tracker.add(5);
        tracker.add(10);
        assert_eq!(tracker.count(), 15);
    }

    #[test]
    fn test_streaming_guard_deref() {
        let auth = AuthContext::new(UserId::new(), Tier::Professional);
        let tracker = UsageTracker::new(auth.user_id, "tokens");

        // Create guard without recorder for testing
        let guard = StreamingAuthGuard {
            auth: auth.clone(),
            tracker,
            flush_on_drop: false,
        };

        // Test deref to AuthContext
        assert_eq!(guard.user_id, auth.user_id);
    }
}
