#![allow(dead_code)]
use std::sync::{Arc, Mutex};

use redis::Commands;
pub trait KeyValueStorage {
    fn get(&self, key: &str) -> Option<String>;
    fn set(&self, key: &str, value: &str);
    fn del(&self, key: &str);
}
pub struct RedisStorage {
    client: redis::Client,
}
impl KeyValueStorage for RedisStorage {
    fn get(&self, key: &str) -> Option<String> {
        let mut con = self.client.get_connection().unwrap();
        let value: Option<String> = con.get(key).unwrap();
        value
    }
    fn set(&self, key: &str, value: &str) {
        let mut con = self.client.get_connection().unwrap();
        let _: () = con.set(key, value).unwrap();
    }
    fn del(&self, key: &str) {
        let mut con = self.client.get_connection().unwrap();
        let _: () = con.del(key).unwrap();
    }
}

pub struct LocalStorage {
    data: Arc<Mutex<std::collections::HashMap<String, String>>>,
}
impl LocalStorage {
    pub fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }
}

impl KeyValueStorage for LocalStorage {
    fn get(&self, key: &str) -> Option<String> {
        self.data.lock().unwrap().get(key).cloned()
    }
    fn set(&self, key: &str, value: &str) {
        self.data
            .lock()
            .unwrap()
            .insert(key.to_string(), value.to_string());
    }
    fn del(&self, key: &str) {
        self.data.lock().unwrap().remove(key);
    }
}
