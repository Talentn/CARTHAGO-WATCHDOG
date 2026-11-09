//! Global allocator that attributes heap usage to threads that opt in (the scheduler worker),
//! so the report can separate scheduler memory from the simulated game's.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicIsize, AtomicU64, Ordering::Relaxed};

pub struct Counting;

thread_local! {
    static TAGGED: Cell<bool> = const { Cell::new(false) };
}

static LIVE: AtomicIsize = AtomicIsize::new(0);
static PEAK: AtomicIsize = AtomicIsize::new(0);
static ALLOCS: AtomicU64 = AtomicU64::new(0);

fn tagged() -> bool {
    TAGGED.try_with(|t| t.get()).unwrap_or(false)
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(l) };
        if !p.is_null() && tagged() {
            let live = LIVE.fetch_add(l.size() as isize, Relaxed) + l.size() as isize;
            PEAK.fetch_max(live, Relaxed);
            ALLOCS.fetch_add(1, Relaxed);
        }
        p
    }

    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        if tagged() {
            LIVE.fetch_sub(l.size() as isize, Relaxed);
        }
        unsafe { System.dealloc(p, l) }
    }
}

pub fn tag_current_thread() {
    TAGGED.with(|t| t.set(true));
}

pub fn with_tag<R>(f: impl FnOnce() -> R) -> R {
    TAGGED.with(|t| t.set(true));
    let r = f();
    TAGGED.with(|t| t.set(false));
    r
}

pub fn reset() {
    LIVE.store(0, Relaxed);
    PEAK.store(0, Relaxed);
    ALLOCS.store(0, Relaxed);
}

/// (peak live bytes, allocation count) for tagged threads since `reset()`.
pub fn snapshot() -> (usize, u64) {
    (PEAK.load(Relaxed).max(0) as usize, ALLOCS.load(Relaxed))
}
