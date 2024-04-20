#![allow(dead_code)]
use anyhow::Result;
use core::time;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::{collections::BinaryHeap, sync::Mutex};
extern crate serde;
use tokio::sync::mpsc::{Receiver, Sender};

use crate::key_value_storage::KeyValueStorage;
use crate::server::SignedUserProfileUpdate;
use common::utils::time::get_current_timestamp_ms;

pub struct PriorityDelayQueueRunner<S: KeyValueStorage + std::marker::Send> {
    rx: Receiver<SignedUserProfileUpdate>,
    queue: Arc<PriorityDelayQueue<S>>,
}
impl<S: KeyValueStorage + std::marker::Send + std::marker::Sync + 'static>
    PriorityDelayQueueRunner<S>
{
    pub fn new(rx: Receiver<SignedUserProfileUpdate>, queue: Arc<PriorityDelayQueue<S>>) -> Self {
        Self { rx, queue }
    }
    pub async fn run(&mut self) {
        while let Some(update) = self.rx.recv().await {
            Arc::clone(&self.queue).push(update).await;
        }
    }
}
/// a queue that stores SignedUserProfileUpdate and sorts
/// them by timestamp and serves
/// the earliest one after a delay
pub struct PriorityDelayQueue<S: KeyValueStorage + std::marker::Send> {
    queue: Mutex<BinaryHeap<SignedUserProfileUpdate>>,
    persistent_storage: S,
    delay_ms: u64,
    result_tx: Sender<SignedUserProfileUpdate>,
    len: AtomicUsize,
}

impl Ord for SignedUserProfileUpdate {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.timestamp_ms().cmp(&other.timestamp_ms()).reverse()
    }
}
impl PartialOrd for SignedUserProfileUpdate {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl PartialEq for SignedUserProfileUpdate {
    fn eq(&self, other: &Self) -> bool {
        self.timestamp_ms() == other.timestamp_ms()
    }
}
impl Eq for SignedUserProfileUpdate {}

impl<S: KeyValueStorage + std::marker::Send + std::marker::Sync + 'static> PriorityDelayQueue<S> {
    // TODO NikZak: add loading from persistent storage
    pub fn new(delay_ms: u64, storage: S, result_tx: Sender<SignedUserProfileUpdate>) -> Self {
        Self {
            queue: Mutex::new(BinaryHeap::new()),
            persistent_storage: storage,
            delay_ms,
            result_tx,
            len: AtomicUsize::new(0),
        }
    }

    async fn push(self: Arc<Self>, update: SignedUserProfileUpdate) {
        let timestamp_ms = update.timestamp_ms();
        let update_str = serde_json::to_string(&update).unwrap();
        self.persistent_storage.set(&update_str, "");
        let mut queue = self.queue.lock().unwrap();
        queue.push(update);
        self.len.fetch_add(1, Ordering::Relaxed);
        drop(queue);
        // serve the update after the delay
        let delay_ms = self.delay_ms;
        let self_clone: Arc<PriorityDelayQueue<S>> = Arc::clone(&self);
        tokio::spawn(async move {
            let now = get_current_timestamp_ms();
            let cur_delay = (timestamp_ms + delay_ms) as i64 - now as i64;
            if cur_delay > 0 {
                tokio::time::sleep(time::Duration::from_millis(cur_delay as u64)).await;
            }
            self_clone.serve().await.unwrap();
        });
    }
    async fn serve(self: Arc<Self>) -> Result<()> {
        // pop
        let item = self
            .queue
            .lock()
            .unwrap()
            .pop()
            .ok_or(anyhow::anyhow!("queue is empty"))?;
        self.len.fetch_sub(1, Ordering::Relaxed);
        self.persistent_storage.del(&serde_json::to_string(&item)?);
        self.result_tx.send(item).await?;
        Ok(())
    }
    fn len(&self) -> usize {
        self.len.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;
    use tokio::sync::mpsc;

    use super::*;
    use crate::{key_value_storage::LocalStorage, server::UserProfileUpdate};

    use tokio::time::sleep;
    fn make_queue() -> (
        Receiver<SignedUserProfileUpdate>,
        Arc<PriorityDelayQueue<LocalStorage>>,
    ) {
        let delay_ms = 200;
        let storage = LocalStorage::new();
        let (result_tx, result_rx) = mpsc::channel(100);
        (
            result_rx,
            Arc::new(PriorityDelayQueue::new(delay_ms, storage, result_tx)),
        )
    }

    #[tokio::test]
    async fn test_priority_delay_queue() -> Result<()> {
        let (mut result_rx, queue) = make_queue();

        let now = get_current_timestamp_ms();
        let timestamps = [now, now + 100, now + 200];
        let updates = timestamps
            .iter()
            .map(|&timestamp_ms| UserProfileUpdate {
                timestamp_ms,
                ..Default::default()
            })
            .map(|update| SignedUserProfileUpdate::from_profile_update(update, "".to_string()))
            .collect::<Vec<_>>();

        for update in &updates {
            queue.clone().push(update.clone()).await;
        }
        // check that none of the updates are ready yet

        assert_eq!(queue.len(), 3);

        // check updates are not received early (before the delay)
        // so channel is empty
        assert_eq!(
            result_rx.try_recv().err(),
            Some(mpsc::error::TryRecvError::Empty)
        );

        // Wait for the items to be processed after the delay
        sleep(Duration::from_millis(200 + 10)).await;

        if let Ok(received_update) = result_rx.try_recv() {
            assert_eq!(received_update, updates[0]);
        } else {
            panic!("No update was received")
        }

        Ok(())
    }
    #[tokio::test]
    async fn test_priority_delay_queue_runner() {
        let (mut result_rx, queue) = make_queue();
        let (tx, rx) = mpsc::channel(100);
        let mut runner = PriorityDelayQueueRunner::new(rx, queue);
        let now = get_current_timestamp_ms();
        let timestamps = [now, now + 100, now + 200];
        let updates = timestamps
            .iter()
            .map(|&timestamp_ms| UserProfileUpdate {
                timestamp_ms,
                ..Default::default()
            })
            .map(|update| SignedUserProfileUpdate::from_profile_update(update, "".to_string()))
            .collect::<Vec<_>>();

        tokio::spawn(async move {
            runner.run().await;
        });

        for update in &updates {
            let _ = tx.send(update.clone()).await;
        }

        // get the updates from the queue

        for update in &updates {
            if let Some(received_update) = result_rx.recv().await {
                assert_eq!(received_update, *update);
            } else {
                panic!("No update was received")
            }
        }
    }
}
