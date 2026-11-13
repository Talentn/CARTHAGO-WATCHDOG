//! The alert screen: a full-screen, topmost window of this companion process, drawn with
//! GDI. It is an ordinary window on the desktop. Nothing is drawn inside the game, nothing is
//! sent to the game, and the game's window is only looked up to pick the monitor it is on.

use std::cell::RefCell;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use carthago_cs16_companion::AlertText;
use windows_sys::Win32::Foundation::{COLORREF, HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{
    BeginPaint, BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, CreateFontW, CreatePen, CreateSolidBrush, DeleteDC, DeleteObject, DrawTextW, EndPaint, FillRect,
    GetMonitorInfoW, GetTextExtentPoint32W, GetTextFaceW, InvalidateRect, LineTo, MonitorFromPoint, MonitorFromWindow, MoveToEx, Polygon, SelectObject, SetBkMode,
    SetTextCharacterExtra, SetTextColor, TextOutW, HDC, HFONT, MONITORINFO, PAINTSTRUCT, SRCCOPY,
};
use windows_sys::Win32::System::Diagnostics::Debug::MessageBeep;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, EnumWindows, GetClientRect, GetMessageW, GetWindowThreadProcessId, IsWindowVisible, KillTimer, LoadCursorW,
    PostMessageW, PostQuitMessage, RegisterClassW, SetForegroundWindow, SetProcessDPIAware, SetTimer, SetWindowPos, ShowWindow, TranslateMessage, MSG, WNDCLASSW,
};

const WM_DESTROY: u32 = 0x0002;
const WM_PAINT: u32 = 0x000F;
const WM_CLOSE: u32 = 0x0010;
const WM_ERASEBKGND: u32 = 0x0014;
const WM_KEYDOWN: u32 = 0x0100;
const WM_TIMER: u32 = 0x0113;
const WM_LBUTTONUP: u32 = 0x0202;
const WS_POPUP: u32 = 0x8000_0000;
const WS_EX_TOPMOST: u32 = 0x0000_0008;
const SW_SHOW: i32 = 5;
const HWND_TOPMOST: HWND = -1isize as HWND;
const SWP_NOSIZE: u32 = 0x0001;
const SWP_NOMOVE: u32 = 0x0002;
const SWP_NOACTIVATE: u32 = 0x0010;
const SWP_SHOWWINDOW: u32 = 0x0040;
const MONITOR_DEFAULTTOPRIMARY: u32 = 1;
const MB_ICONHAND: u32 = 0x10;
const TRANSPARENT: i32 = 1;
const DT_CENTER: u32 = 0x1;
const DT_WORDBREAK: u32 = 0x10;
const VK_RETURN: usize = 0x0D;
const VK_ESCAPE: usize = 0x1B;
const VK_SPACE: usize = 0x20;
const IDC_ARROW: *const u16 = 32512 as *const u16;
const TIMER: usize = 1;

/// A click or key within this time of the screen appearing was meant for the game.
const INPUT_GRACE: Duration = Duration::from_millis(1500);

pub struct Alert {
    pub text: AlertText,
    /// Seconds until the screen closes by itself; 0 keeps it until it is closed.
    pub seconds: u32,
    /// The game's process, to show the screen on the monitor the game is on.
    pub game_pid: Option<u32>,
}

struct Shown {
    text: AlertText,
    since: Instant,
    seconds: u32,
}

thread_local! {
    static SHOWN: RefCell<Option<Shown>> = const { RefCell::new(None) };
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

const fn rgb(r: u8, g: u8, b: u8) -> COLORREF {
    r as u32 | (g as u32) << 8 | (b as u32) << 16
}

const WHITE: COLORREF = rgb(255, 255, 255);
const PALE: COLORREF = rgb(255, 205, 208);
const STRIPE: COLORREF = rgb(38, 4, 8);
const YELLOW: COLORREF = rgb(255, 214, 10);
const BLACK: COLORREF = rgb(16, 16, 16);

/// Shows the alert on its own thread and returns at once. The thread ends when the screen
/// is closed.
pub fn show(alert: Alert) -> JoinHandle<()> {
    std::thread::spawn(move || run(alert))
}

/// Top-level visible windows of a process.
pub fn windows_of(pid: u32) -> Vec<HWND> {
    struct Find {
        pid: u32,
        found: Vec<HWND>,
    }
    unsafe extern "system" fn each(hwnd: HWND, lparam: LPARAM) -> i32 {
        let find = unsafe { &mut *(lparam as *mut Find) };
        let mut owner = 0u32;
        unsafe { GetWindowThreadProcessId(hwnd, &mut owner) };
        if owner == find.pid && unsafe { IsWindowVisible(hwnd) } != 0 {
            find.found.push(hwnd);
        }
        1
    }
    let mut find = Find { pid, found: Vec::new() };
    unsafe { EnumWindows(Some(each), &mut find as *mut Find as LPARAM) };
    find.found
}

/// Asks a process to close the way its window's close button does. Returns how many
/// windows were asked.
pub fn ask_to_close(pid: u32) -> usize {
    let windows = windows_of(pid);
    for &w in &windows {
        unsafe { PostMessageW(w, WM_CLOSE, 0, 0) };
    }
    windows.len()
}

fn monitor_rect(game_pid: Option<u32>) -> RECT {
    let game = game_pid.and_then(|pid| windows_of(pid).into_iter().next());
    let monitor = match game {
        Some(w) => unsafe { MonitorFromWindow(w, MONITOR_DEFAULTTOPRIMARY) },
        None => unsafe { MonitorFromPoint(POINT { x: 0, y: 0 }, MONITOR_DEFAULTTOPRIMARY) },
    };
    let mut info: MONITORINFO = unsafe { std::mem::zeroed() };
    info.cbSize = size_of::<MONITORINFO>() as u32;
    if unsafe { GetMonitorInfoW(monitor, &mut info) } == 0 || info.rcMonitor.right <= info.rcMonitor.left {
        return RECT { left: 0, top: 0, right: 1280, bottom: 720 };
    }
    info.rcMonitor
}

fn run(alert: Alert) {
    unsafe { SetProcessDPIAware() };
    let instance = unsafe { GetModuleHandleW(std::ptr::null()) };
    let class = wide("CarthagoWatchdogAlert");
    let wc = WNDCLASSW {
        style: 0,
        lpfnWndProc: Some(wndproc),
        cbClsExtra: 0,
        cbWndExtra: 0,
        hInstance: instance,
        hIcon: std::ptr::null_mut(),
        hCursor: unsafe { LoadCursorW(std::ptr::null_mut(), IDC_ARROW) },
        hbrBackground: std::ptr::null_mut(),
        lpszMenuName: std::ptr::null(),
        lpszClassName: class.as_ptr(),
    };
    // Registering twice (a second alert) fails harmlessly; the class is already there.
    unsafe { RegisterClassW(&wc) };
    let r = monitor_rect(alert.game_pid);
    SHOWN.with(|s| *s.borrow_mut() = Some(Shown { text: alert.text, since: Instant::now(), seconds: alert.seconds }));
    let title = wide("Carthago Watchdog");
    let hwnd = unsafe {
        CreateWindowExW(
            WS_EX_TOPMOST,
            class.as_ptr(),
            title.as_ptr(),
            WS_POPUP,
            r.left,
            r.top,
            r.right - r.left,
            r.bottom - r.top,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            instance,
            std::ptr::null(),
        )
    };
    if hwnd.is_null() {
        return;
    }
    unsafe {
        ShowWindow(hwnd, SW_SHOW);
        SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
        // Windows decides whether a background program may take the keyboard. If it may
        // not, the screen is still on top and closes on a click or by itself.
        SetForegroundWindow(hwnd);
        MessageBeep(MB_ICONHAND);
        SetTimer(hwnd, TIMER, 500, None);
    }
    let mut msg: MSG = unsafe { std::mem::zeroed() };
    while unsafe { GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) } > 0 {
        unsafe {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    SHOWN.with(|s| *s.borrow_mut() = None);
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    let (elapsed, seconds) = SHOWN.with(|s| s.borrow().as_ref().map_or((Duration::ZERO, 0), |s| (s.since.elapsed(), s.seconds)));
    match msg {
        WM_ERASEBKGND => 1,
        WM_PAINT => {
            let mut ps: PAINTSTRUCT = unsafe { std::mem::zeroed() };
            let dc = unsafe { BeginPaint(hwnd, &mut ps) };
            let mut rc: RECT = unsafe { std::mem::zeroed() };
            unsafe { GetClientRect(hwnd, &mut rc) };
            let (w, h) = (rc.right.max(1), rc.bottom.max(1));
            // Drawn off screen and copied in one step, so the countdown does not flicker.
            unsafe {
                let mem = CreateCompatibleDC(dc);
                let bmp = CreateCompatibleBitmap(dc, w, h);
                let old = SelectObject(mem, bmp);
                SHOWN.with(|s| {
                    if let Some(s) = s.borrow().as_ref() {
                        paint(mem, w, h, s);
                    }
                });
                BitBlt(dc, 0, 0, w, h, mem, 0, 0, SRCCOPY);
                SelectObject(mem, old);
                DeleteObject(bmp);
                DeleteDC(mem);
                EndPaint(hwnd, &ps);
            }
            0
        }
        WM_TIMER => {
            if seconds != 0 && elapsed >= Duration::from_secs(seconds as u64) {
                unsafe { DestroyWindow(hwnd) };
            } else {
                // A full-screen game may put itself back on top; stay above it without
                // taking the keyboard again.
                unsafe {
                    SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
                    InvalidateRect(hwnd, std::ptr::null(), 0);
                }
            }
            0
        }
        WM_KEYDOWN if matches!(wparam, VK_ESCAPE | VK_RETURN | VK_SPACE) && elapsed >= INPUT_GRACE => {
            unsafe { DestroyWindow(hwnd) };
            0
        }
        WM_LBUTTONUP if elapsed >= INPUT_GRACE => {
            unsafe { DestroyWindow(hwnd) };
            0
        }
        WM_CLOSE => {
            unsafe { DestroyWindow(hwnd) };
            0
        }
        WM_DESTROY => {
            unsafe {
                KillTimer(hwnd, TIMER);
                PostQuitMessage(0);
            }
            0
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}

/// A font of `face` if that face is installed.
unsafe fn installed(dc: HDC, height: i32, weight: i32, face: &str) -> Option<HFONT> {
    let name = wide(face);
    let f = unsafe { CreateFontW(-height, 0, 0, 0, weight, 0, 0, 0, 0, 0, 0, 4, 0, name.as_ptr()) };
    let old = unsafe { SelectObject(dc, f) };
    let mut got = [0u16; 64];
    let n = unsafe { GetTextFaceW(dc, got.len() as i32, got.as_mut_ptr()) }.max(1) as usize - 1;
    unsafe { SelectObject(dc, old) };
    if String::from_utf16_lossy(&got[..n.min(63)]).eq_ignore_ascii_case(face) {
        return Some(f);
    }
    unsafe { DeleteObject(f) };
    None
}

/// A font of the first face in `faces` that is installed, else of the last one, which
/// Windows replaces with its default face if it is missing too.
unsafe fn font(dc: HDC, height: i32, weight: i32, faces: &[&str]) -> HFONT {
    for face in faces {
        if let Some(f) = unsafe { installed(dc, height, weight, face) } {
            return f;
        }
    }
    let name = wide(faces.last().copied().unwrap_or("Arial"));
    unsafe { CreateFontW(-height, 0, 0, 0, weight, 0, 0, 0, 0, 0, 0, 4, 0, name.as_ptr()) }
}

/// The title's face: tall, narrow and heavy. Where no such face is installed, a bold one
/// is drawn narrower to the same proportions.
unsafe fn title_font(dc: HDC, height: i32) -> HFONT {
    for face in ["Bahnschrift Condensed", "Impact"] {
        if let Some(f) = unsafe { installed(dc, height, 700, face) } {
            return f;
        }
    }
    let name = wide("Arial");
    unsafe { CreateFontW(-height, height * 30 / 100, 0, 0, 700, 0, 0, 0, 0, 0, 0, 4, 0, name.as_ptr()) }
}

unsafe fn fill(dc: HDC, r: RECT, color: COLORREF) {
    unsafe {
        let b = CreateSolidBrush(color);
        FillRect(dc, &r, b);
        DeleteObject(b);
    }
}

unsafe fn width_of(dc: HDC, text: &[u16]) -> i32 {
    let mut size = unsafe { std::mem::zeroed() };
    unsafe { GetTextExtentPoint32W(dc, text.as_ptr(), text.len() as i32, &mut size) };
    size.cx
}

/// One centred line; returns its width.
unsafe fn centred(dc: HDC, w: i32, y: i32, text: &str, f: HFONT, color: COLORREF, spacing: i32) -> i32 {
    let t: Vec<u16> = text.encode_utf16().collect();
    unsafe {
        let old = SelectObject(dc, f);
        SetTextColor(dc, color);
        SetTextCharacterExtra(dc, spacing);
        let tw = width_of(dc, &t) - spacing;
        TextOutW(dc, (w - tw) / 2, y, t.as_ptr(), t.len() as i32);
        SetTextCharacterExtra(dc, 0);
        SelectObject(dc, old);
        tw
    }
}

/// A band of diagonal stripes across the screen.
unsafe fn stripes(dc: HDC, w: i32, top: i32, height: i32) {
    unsafe {
        let brush = CreateSolidBrush(STRIPE);
        let pen = CreatePen(0, 1, STRIPE);
        let (old_brush, old_pen) = (SelectObject(dc, brush), SelectObject(dc, pen));
        let step = height * 2;
        let mut x = -step;
        while x < w + step {
            let p = [
                POINT { x, y: top + height },
                POINT { x: x + height, y: top },
                POINT { x: x + height + step / 2, y: top },
                POINT { x: x + step / 2, y: top + height },
            ];
            Polygon(dc, p.as_ptr(), 4);
            x += step;
        }
        SelectObject(dc, old_brush);
        SelectObject(dc, old_pen);
        DeleteObject(brush);
        DeleteObject(pen);
    }
}

/// The shield mark beside the product name.
unsafe fn shield(dc: HDC, x: i32, y: i32, size: i32, color: COLORREF, inner: COLORREF) {
    let shape = |cx: i32, cy: i32, s: i32| {
        [
            POINT { x: cx - s / 2, y: cy - s / 2 },
            POINT { x: cx + s / 2, y: cy - s / 2 },
            POINT { x: cx + s / 2, y: cy + s / 10 },
            POINT { x: cx, y: cy + s / 2 },
            POINT { x: cx - s / 2, y: cy + s / 10 },
        ]
    };
    unsafe {
        for (s, c) in [(size, color), (size * 6 / 10, inner)] {
            let brush = CreateSolidBrush(c);
            let pen = CreatePen(0, 1, c);
            let (ob, op) = (SelectObject(dc, brush), SelectObject(dc, pen));
            let p = shape(x + size / 2, y + size / 2, s);
            Polygon(dc, p.as_ptr(), 5);
            SelectObject(dc, ob);
            SelectObject(dc, op);
            DeleteObject(brush);
            DeleteObject(pen);
        }
    }
}

unsafe fn paint(dc: HDC, w: i32, h: i32, shown: &Shown) {
    let t = &shown.text;
    unsafe {
        // Red, darker towards the edges of the screen.
        let bands: i32 = 48;
        for i in 0..bands {
            let d = ((i * 2 - bands + 1).abs() as f32) / bands as f32;
            let k = 1.0 - 0.55 * d * d;
            let c = rgb((196.0 * k) as u8, (14.0 * k) as u8, (30.0 * k) as u8);
            fill(dc, RECT { left: 0, top: h * i / bands, right: w, bottom: h * (i + 1) / bands }, c);
        }
        let band = (h / 22).max(12);
        stripes(dc, w, 0, band);
        stripes(dc, w, h - band, band);
        SetBkMode(dc, TRANSPARENT);

        let unit = (h / 100).max(4);
        // The title is as tall as the screen allows and never wider than it.
        let mut title_h = (h / 5).max(28);
        let spacing = |height: i32| height / 20;
        let mut title_f = title_font(dc, title_h);
        let title: Vec<u16> = t.title.encode_utf16().collect();
        let old = SelectObject(dc, title_f);
        SetTextCharacterExtra(dc, spacing(title_h));
        let natural = width_of(dc, &title);
        SetTextCharacterExtra(dc, 0);
        SelectObject(dc, old);
        if natural > w * 80 / 100 {
            DeleteObject(title_f);
            title_h = (title_h as i64 * (w as i64 * 80 / 100) / natural as i64) as i32;
            title_f = title_font(dc, title_h);
        }
        let caps = font(dc, unit * 3, 700, &["Bahnschrift", "Segoe UI", "Arial"]);
        let sub = font(dc, unit * 5, 700, &["Bahnschrift Condensed", "Bahnschrift", "Segoe UI", "Arial"]);
        let body = font(dc, unit * 3, 400, &["Segoe UI", "Arial"]);
        let small = font(dc, unit * 2, 400, &["Segoe UI", "Arial"]);
        let mono = font(dc, unit * 5 / 2, 400, &["Consolas", "Lucida Console", "Courier New"]);

        let mut y = band + unit * 3;
        if let Some(tag) = &t.tag {
            let text: Vec<u16> = tag.encode_utf16().collect();
            let old = SelectObject(dc, caps);
            SetTextCharacterExtra(dc, unit / 3);
            let tw = width_of(dc, &text);
            SetTextCharacterExtra(dc, 0);
            SelectObject(dc, old);
            fill(dc, RECT { left: (w - tw) / 2 - unit * 3, top: y, right: (w + tw) / 2 + unit * 3, bottom: y + unit * 5 }, YELLOW);
            centred(dc, w, y + unit, tag, caps, BLACK, unit / 3);
        }

        // The block from the product name to the details, centred on the screen.
        let block = unit * 4 + unit * 3 + title_h + unit * 3 + unit * 5 + unit * 5 + unit * 4 + unit * 4 + unit * 3 * t.details.len() as i32;
        y = ((h - block) / 2).max(y + unit * 8);

        let brand: Vec<u16> = t.brand.encode_utf16().collect();
        let old = SelectObject(dc, caps);
        SetTextCharacterExtra(dc, unit);
        let bw = width_of(dc, &brand) - unit;
        SetTextCharacterExtra(dc, 0);
        SelectObject(dc, old);
        let mark = unit * 4;
        let left = (w - bw - mark - unit * 2) / 2;
        shield(dc, left, y - unit / 2, mark, WHITE, rgb(170, 12, 26));
        let old = SelectObject(dc, caps);
        SetTextColor(dc, WHITE);
        SetTextCharacterExtra(dc, unit);
        TextOutW(dc, left + mark + unit * 2, y, brand.as_ptr(), brand.len() as i32);
        SetTextCharacterExtra(dc, 0);
        SelectObject(dc, old);
        y += unit * 4 + unit * 3;

        let tw = centred(dc, w, y, &t.title, title_f, WHITE, spacing(title_h));
        let rule = (tw / 2 + unit * 4).min(w / 2 - unit * 2);
        let pen = CreatePen(0, (unit / 3).max(2), WHITE);
        let old_pen = SelectObject(dc, pen);
        for ry in [y - unit, y + title_h + unit * 2] {
            MoveToEx(dc, w / 2 - rule, ry, std::ptr::null_mut());
            LineTo(dc, w / 2 + rule, ry);
        }
        SelectObject(dc, old_pen);
        DeleteObject(pen);
        y += title_h + unit * 3 + unit;

        centred(dc, w, y, &t.subtitle, sub, WHITE, unit / 2);
        y += unit * 5 + unit * 2;
        centred(dc, w, y, &t.reason, body, WHITE, 0);
        y += unit * 4 + unit * 3;
        // Two columns, centred as one block: labels right-aligned, values left-aligned.
        let old = SelectObject(dc, mono);
        let cells: Vec<(Vec<u16>, Vec<u16>)> = t.details.iter().map(|(l, v)| (l.encode_utf16().collect(), v.encode_utf16().collect())).collect();
        let label_w = cells.iter().map(|(l, _)| width_of(dc, l)).max().unwrap_or(0);
        let value_w = cells.iter().map(|(_, v)| width_of(dc, v)).max().unwrap_or(0);
        let gap = unit * 2;
        let x0 = (w - label_w - gap - value_w) / 2;
        for (label, value) in &cells {
            SetTextColor(dc, PALE);
            TextOutW(dc, x0 + label_w - width_of(dc, label), y, label.as_ptr(), label.len() as i32);
            SetTextColor(dc, WHITE);
            TextOutW(dc, x0 + label_w + gap, y, value.as_ptr(), value.len() as i32);
            y += unit * 3;
        }
        SelectObject(dc, old);

        let closing = match shown.seconds {
            0 => String::new(),
            s => format!("  Closes by itself in {} s.", (s as u64).saturating_sub(shown.since.elapsed().as_secs()).max(1)),
        };
        let footer = wide(&format!("{}{closing}", t.footer));
        let mut fr = RECT { left: w / 8, top: h - band - unit * 7, right: w - w / 8, bottom: h - band - unit };
        let old = SelectObject(dc, small);
        SetTextColor(dc, PALE);
        DrawTextW(dc, footer.as_ptr(), -1, &mut fr, DT_CENTER | DT_WORDBREAK);
        SelectObject(dc, old);

        for f in [title_f, caps, sub, body, small, mono] {
            DeleteObject(f);
        }
    }
}
