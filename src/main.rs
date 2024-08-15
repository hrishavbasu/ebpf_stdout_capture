use anyhow::Result;
use libbpf_rs::RingBufferBuilder;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::process;

// Uncomment the next line if you added the users crate to your Cargo.toml
use users::get_user_by_uid;

mod bpf {
    include!(concat!(env!("OUT_DIR"), "/bpf_bindings.rs"));
}

use bpf::*;

#[repr(C)]
#[derive(Copy, Clone)]
struct Event {
    pid: u32,
    uid: u32,
    fd: u32,
    len: u64,
    buf: [u8; 64],
}

fn handle_event(data: &[u8]) -> i32 {
    let event = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const Event) };
    
    // If you're using the users crate, uncomment the next lines and comment out the simple version
    let username = get_user_by_uid(event.uid)
         .map(|user| user.name().to_string_lossy().into_owned())
         .unwrap_or_else(|| format!("UID:{}", event.uid));
    
    // Simple version without resolving usernames
    //let username = format!("UID:{}", event.uid);
    
    println!(
        "User '{}' (PID {}): FD {} wrote {} bytes: {}",
        username,
        event.pid,
        event.fd,
        event.len,
        std::str::from_utf8(&event.buf[..event.len.min(64) as usize]).unwrap_or("Invalid UTF-8")
    );
    0
}

fn main() -> Result<()> {
    let skel_builder = StdoutCaptureSkelBuilder::default();
    let open_skel = skel_builder.open()?;
    let mut skel = open_skel.load()?;

    // Set our PID in the map
    let my_pid = process::id();
    let mut maps = skel.maps_mut();
    let my_pid_map = maps.my_pid();
    let key = 0u32.to_ne_bytes();
    let value = my_pid.to_ne_bytes();
    my_pid_map.update(&key, &value, libbpf_rs::MapFlags::ANY)?;

    skel.attach()?;

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    let mut builder = RingBufferBuilder::new();
    builder.add(skel.maps().rb(), handle_event)?;
    let ring_buffer = builder.build()?;

    while running.load(Ordering::SeqCst) {
        ring_buffer.poll(Duration::from_millis(100))?;
    }

    println!("Exiting...");
    Ok(())
}