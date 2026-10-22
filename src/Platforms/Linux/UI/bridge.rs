//! The vault core, through its C API (src/Platforms/Shared/CApi/cw_api.h).
//!
//! Every call is JSON in, JSON out. Calls block (some reach the network), so the UI runs
//! them on a background thread with [`request`]; they're serialised so the core sees one
//! at a time, like the other front ends.

use std::ffi::{CStr, CString, c_char, c_void};
use std::path::Path;
use std::sync::Mutex;

use iced::futures::channel::{mpsc, oneshot};
use iced::futures::{SinkExt, Stream, StreamExt};
use serde_json::Value;
use zeroize::Zeroize;

unsafe extern "C" {
    fn cw_init(data_dir: *const c_char, resource_dir: *const c_char);
    fn cw_call(method: *const c_char, args: *const c_char) -> *mut c_char;
    fn cw_free(response: *mut c_char);
    fn cw_on_event(
        callback: Option<extern "C" fn(*const c_char, *mut c_void)>,
        context: *mut c_void,
    );
}

/// One call into the core at a time.
static CALL_LOCK: Mutex<()> = Mutex::new(());

/// Where core events go once the UI subscribes.
static EVENTS: Mutex<Option<mpsc::UnboundedSender<String>>> = Mutex::new(None);

/// Points the core at the app's folders. Call once at startup.
pub fn init(data_dir: &Path, resource_dir: &Path) {
    let data = CString::new(data_dir.to_string_lossy().as_bytes()).unwrap_or_default();
    let resources = CString::new(resource_dir.to_string_lossy().as_bytes()).unwrap_or_default();
    unsafe {
        cw_init(data.as_ptr(), resources.as_ptr());
        cw_on_event(Some(on_event), std::ptr::null_mut());
    }
}

extern "C" fn on_event(event: *const c_char, _context: *mut c_void) {
    if event.is_null() {
        return;
    }
    let text = unsafe { CStr::from_ptr(event) }.to_string_lossy().into_owned();
    if let Ok(guard) = EVENTS.lock() {
        if let Some(sender) = guard.as_ref() {
            let _ = sender.unbounded_send(text);
        }
    }
}

/// Runs a method on the calling thread. The argument and response text are wiped after use.
pub fn call(method: &str, args: Value) -> Result<Value, String> {
    let mut args_text = args.to_string();
    drop_value(args);
    let name = CString::new(method).map_err(|_| "bad method name".to_string())?;
    let encoded = CString::new(std::mem::take(&mut args_text));
    args_text.zeroize();
    let encoded = encoded.map_err(|_| "arguments contain a NUL".to_string())?;

    let mut response = {
        let _guard = CALL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let raw = cw_call(name.as_ptr(), encoded.as_ptr());
            let text = CStr::from_ptr(raw).to_string_lossy().into_owned();
            cw_free(raw);
            text
        }
    };
    wipe_cstring(encoded);

    let parsed: Result<Value, _> = serde_json::from_str(&response);
    response.zeroize();
    let mut envelope = parsed.map_err(|_| "unexpected response from the vault".to_string())?;
    if envelope.get("ok").and_then(Value::as_bool) == Some(true) {
        Ok(envelope.get_mut("result").map(Value::take).unwrap_or(Value::Null))
    } else {
        let error = envelope
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("something went wrong")
            .to_string();
        wipe(&mut envelope);
        Err(error)
    }
}

/// Runs a method on a background thread.
pub async fn request(method: &'static str, args: Value) -> Result<Value, String> {
    let (sender, receiver) = oneshot::channel();
    std::thread::spawn(move || {
        let _ = sender.send(call(method, args));
    });
    receiver
        .await
        .unwrap_or_else(|_| Err("the vault stopped responding".to_string()))
}

/// Events the core raises by itself (auto-lock, logout), as JSON text.
pub fn events() -> impl Stream<Item = String> {
    iced::stream::channel(16, async |mut output| {
        let (sender, mut receiver) = mpsc::unbounded();
        if let Ok(mut guard) = EVENTS.lock() {
            *guard = Some(sender);
        }
        while let Some(event) = receiver.next().await {
            let _ = output.send(event).await;
        }
    })
}

/// Zeroes every string inside a JSON value.
pub fn wipe(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(wipe),
        Value::Object(map) => {
            for (_, item) in map.iter_mut() {
                wipe(item);
            }
        }
        _ => {}
    }
}

fn drop_value(mut value: Value) {
    wipe(&mut value);
}

fn wipe_cstring(text: CString) {
    let mut bytes = text.into_bytes();
    bytes.zeroize();
}
