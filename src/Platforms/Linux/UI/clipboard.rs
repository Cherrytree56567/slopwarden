//! Copying secrets: kept out of clipboard history where the platform allows, and cleared
//! after the vault's clipboard delay if the clipboard still holds what we put there.

use std::sync::Mutex;
use std::time::Duration;

use arboard::Clipboard;
use zeroize::Zeroize;

/// One clipboard for the app's lifetime: on X11 and Wayland the copied text is only
/// available while its owner is alive.
static CLIPBOARD: Mutex<Option<Clipboard>> = Mutex::new(None);

/// Bumped on every copy, so an older copy's timer doesn't clear a newer one.
static GENERATION: Mutex<u64> = Mutex::new(0);

fn with_clipboard<T>(f: impl FnOnce(&mut Clipboard) -> T) -> Option<T> {
    let mut guard = CLIPBOARD.lock().ok()?;
    if guard.is_none() {
        *guard = Clipboard::new().ok();
    }
    guard.as_mut().map(f)
}

fn set_text(clipboard: &mut Clipboard, text: &str) -> bool {
    let set = clipboard.set();
    #[cfg(target_os = "linux")]
    let set = {
        use arboard::SetExtLinux;
        set.exclude_from_history()
    };
    #[cfg(target_os = "windows")]
    let set = {
        use arboard::SetExtWindows;
        set.exclude_from_history().exclude_from_cloud().exclude_from_monitoring()
    };
    #[cfg(target_os = "macos")]
    let set = {
        use arboard::SetExtApple;
        set.exclude_from_history()
    };
    set.text(text.to_string()).is_ok()
}

/// Copies text; clears it after `clear_after_seconds` (0 = never).
pub fn copy(text: &str, clear_after_seconds: u64) -> bool {
    if with_clipboard(|clipboard| set_text(clipboard, text)) != Some(true) {
        return false;
    }
    let generation = {
        let mut guard = GENERATION.lock().unwrap_or_else(|e| e.into_inner());
        *guard += 1;
        *guard
    };
    if clear_after_seconds == 0 {
        return true;
    }

    let mut copied = text.to_string();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(clear_after_seconds));
        let current = *GENERATION.lock().unwrap_or_else(|e| e.into_inner());
        if current == generation {
            with_clipboard(|clipboard| {
                let mut held = clipboard.get_text().unwrap_or_default();
                if held == copied {
                    let _ = clipboard.clear();
                }
                held.zeroize();
            });
        }
        copied.zeroize();
    });
    true
}
