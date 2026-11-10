//! Injected-input statistics (plan §6.1): a `WH_MOUSE_LL` hook counts mouse events flagged
//! `LLMHF_INJECTED` / `LLMHF_LOWER_IL_INJECTED` (what `SendInput` aimbots and macro tools
//! produce). The hook is installed only while a window of the game process has focus and
//! removed otherwise. Its callback only bumps counters, so it adds no measurable latency;
//! it never reads positions or keys.
//!
//! The hook needs a thread that pumps messages, so this is the SDK's one thread besides the
//! scheduler worker and the network thread. It sleeps in `GetMessageW` between events and
//! runs above normal priority, because Windows silently drops a low-level hook whose thread
//! answers late (and every mouse event on the desktop waits for it meanwhile).

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering::Relaxed};
use std::sync::Arc;
use std::thread::JoinHandle;

use windows_sys::Win32::Foundation::{LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Threading::{GetCurrentProcessId, GetCurrentThread, GetCurrentThreadId, SetThreadPriority, THREAD_PRIORITY_ABOVE_NORMAL};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CallNextHookEx, GetForegroundWindow, GetMessageW, GetWindowThreadProcessId, KillTimer, PeekMessageW, PostThreadMessageW, SetTimer,
    SetWindowsHookExW, UnhookWindowsHookEx, HHOOK, HC_ACTION, LLMHF_INJECTED, LLMHF_LOWER_IL_INJECTED, MSG, MSLLHOOKSTRUCT, PM_NOREMOVE,
    WH_MOUSE_LL, WM_QUIT, WM_TIMER,
};

static EVENTS: AtomicU64 = AtomicU64::new(0);
static INJECTED: AtomicU64 = AtomicU64::new(0);
static LOWER_IL: AtomicU64 = AtomicU64::new(0);
static FOCUSED_MS: AtomicU64 = AtomicU64::new(0);
static THREAD_CPU_NS: AtomicU64 = AtomicU64::new(0);
static RUNNING: AtomicBool = AtomicBool::new(false);

const POLL_MS: u32 = 250;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InputCounters {
    pub mouse_events: u64,
    pub injected: u64,
    pub lower_il_injected: u64,
    pub focused_ms: u64,
}

pub fn counters() -> InputCounters {
    InputCounters {
        mouse_events: EVENTS.load(Relaxed),
        injected: INJECTED.load(Relaxed),
        lower_il_injected: LOWER_IL.load(Relaxed),
        focused_ms: FOCUSED_MS.load(Relaxed),
    }
}

pub fn thread_cpu_ns() -> u64 {
    THREAD_CPU_NS.load(Relaxed)
}

unsafe extern "system" fn mouse_proc(code: i32, w: WPARAM, l: LPARAM) -> LRESULT {
    if code == HC_ACTION as i32 && l != 0 {
        let ev = unsafe { &*(l as *const MSLLHOOKSTRUCT) };
        EVENTS.fetch_add(1, Relaxed);
        if ev.flags & LLMHF_INJECTED != 0 {
            INJECTED.fetch_add(1, Relaxed);
        }
        if ev.flags & LLMHF_LOWER_IL_INJECTED != 0 {
            LOWER_IL.fetch_add(1, Relaxed);
        }
    }
    unsafe { CallNextHookEx(std::ptr::null_mut(), code, w, l) }
}

fn game_focused(pid: u32) -> bool {
    let fg = unsafe { GetForegroundWindow() };
    if fg.is_null() {
        return false;
    }
    let mut owner = 0u32;
    unsafe { GetWindowThreadProcessId(fg, &mut owner) };
    owner == pid
}

fn run(tid_out: Arc<AtomicU32>) {
    unsafe { SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL) };
    let mut msg: MSG = unsafe { std::mem::zeroed() };
    // Creates this thread's message queue before the id is published, so a WM_QUIT posted
    // right after start is not lost.
    unsafe { PeekMessageW(&mut msg, std::ptr::null_mut(), 0, 0, PM_NOREMOVE) };
    tid_out.store(unsafe { GetCurrentThreadId() }, Relaxed);
    let pid = unsafe { GetCurrentProcessId() };
    let timer = unsafe { SetTimer(std::ptr::null_mut(), 0, POLL_MS, None) };
    let module = unsafe { GetModuleHandleW(std::ptr::null()) };
    let mut hook: HHOOK = std::ptr::null_mut();
    while unsafe { GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) } > 0 {
        if msg.message != WM_TIMER {
            continue;
        }
        let focused = game_focused(pid);
        if focused {
            FOCUSED_MS.fetch_add(POLL_MS as u64, Relaxed);
            if hook.is_null() {
                hook = unsafe { SetWindowsHookExW(WH_MOUSE_LL, Some(mouse_proc), module, 0) };
            }
        } else if !hook.is_null() {
            unsafe { UnhookWindowsHookEx(hook) };
            hook = std::ptr::null_mut();
        }
        THREAD_CPU_NS.store(carthago_sched::clock::cycles_to_ns(carthago_sched::clock::thread_cycles()), Relaxed);
    }
    if !hook.is_null() {
        unsafe { UnhookWindowsHookEx(hook) };
    }
    unsafe { KillTimer(std::ptr::null_mut(), timer) };
}

/// The hook thread; dropped (or [`InputMonitor::stop`]) unhooks and joins it. One per process.
pub struct InputMonitor {
    tid: Arc<AtomicU32>,
    thread: Option<JoinHandle<()>>,
}

impl InputMonitor {
    pub fn start() -> std::io::Result<Self> {
        if RUNNING.swap(true, Relaxed) {
            return Err(std::io::Error::other("input monitor already running"));
        }
        let tid = Arc::new(AtomicU32::new(0));
        let t = tid.clone();
        match std::thread::Builder::new().name("carthago-input".into()).stack_size(64 * 1024).spawn(move || run(t)) {
            Ok(thread) => Ok(Self { tid, thread: Some(thread) }),
            Err(e) => {
                RUNNING.store(false, Relaxed);
                Err(e)
            }
        }
    }

    pub fn stop(&mut self) {
        let Some(t) = self.thread.take() else { return };
        loop {
            let tid = self.tid.load(Relaxed);
            if tid != 0 && unsafe { PostThreadMessageW(tid, WM_QUIT, 0, 0) } != 0 {
                break;
            }
            if t.is_finished() {
                break;
            }
            std::thread::yield_now();
        }
        let _ = t.join();
        RUNNING.store(false, Relaxed);
    }
}

impl Drop for InputMonitor {
    fn drop(&mut self) {
        self.stop();
    }
}
