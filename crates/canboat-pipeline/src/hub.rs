//! Lazy broadcast hub for the read-only TCP outputs.
//!
//! `canboat-pipeline` exposes three read streams a TCP client can
//! subscribe to: PLAIN/FAST CSV (also accepting writes — see
//! [`crate::tcp`]), NMEA 0183 incl. AIVDM, and analyzer JSON. All
//! three share this `Hub` structure: clients subscribe, the pipeline
//! calls [`Hub::broadcast`] per produced line, dead subscribers are
//! pruned on the next broadcast.
//!
//! The point of the abstraction is the [`Hub::has_subscribers`]
//! gate: the pipeline checks it *before* invoking the formatter
//! (PLAIN/FAST, NMEA 0183, JSON). When no one is connected, the
//! steady-state cost per frame is a single relaxed atomic load.

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Sender};

pub struct Hub {
    subscribers: Mutex<Vec<Sender<String>>>,
    count: AtomicUsize,
}

impl Hub {
    pub fn new() -> Self {
        Self {
            subscribers: Mutex::new(Vec::new()),
            count: AtomicUsize::new(0),
        }
    }

    #[inline]
    pub fn has_subscribers(&self) -> bool {
        self.count.load(Ordering::Relaxed) > 0
    }

    pub fn subscribe(&self) -> mpsc::Receiver<String> {
        let (tx, rx) = mpsc::channel::<String>();
        let mut subs = self.subscribers.lock().expect("hub poisoned");
        subs.push(tx);
        self.count.store(subs.len(), Ordering::Relaxed);
        rx
    }

    /// Broadcast `line` (caller's responsibility to include trailing
    /// `\n` if expected). Dead subscribers are pruned in place.
    pub fn broadcast(&self, line: &str) {
        let mut subs = self.subscribers.lock().expect("hub poisoned");
        subs.retain(|tx| tx.send(line.to_string()).is_ok());
        self.count.store(subs.len(), Ordering::Relaxed);
    }
}

impl Default for Hub {
    fn default() -> Self {
        Self::new()
    }
}
