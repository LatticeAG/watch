//! watchd — the single-writer Watch daemon. Loads config/trust, runs
//! startup gates, opens the store, recovers, serves the control socket.

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use watch::config::{load_config, load_signer, load_trust};
use watch::daemon::Daemon;
use watch::monitor::WorkerPool;
use watch::objects::ObjectStore;
use watch::store::Store;

fn usage() -> ! {
    eprintln!("usage: watchd --config PATH [--lab]");
    std::process::exit(2);
}

fn main() {
    let mut config: Option<String> = None;
    let mut lab = false;
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--config" => config = it.next(),
            "--lab" => lab = true,
            _ => usage(),
        }
    }
    let config = config.unwrap_or_else(|| "/etc/lattice-watch/config.json".into());
    let cfg = match load_config(PathBuf::from(&config).as_path()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config: {}", e.message);
            std::process::exit(2);
        }
    };
    if lab && cfg.deployment != "lab" {
        eprintln!("--lab requires deployment=lab");
        std::process::exit(2);
    }
    let trust = match load_trust(PathBuf::from(&cfg.trust_file).as_path()) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("trust: {}", e.message);
            std::process::exit(2);
        }
    };
    let sk_bytes = match std::fs::read(&cfg.signer_key_file) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("signer key: {e}");
            std::process::exit(5);
        }
    };
    let _ = load_signer(PathBuf::from(&cfg.signer_key_file).as_path());
    let data_dir = PathBuf::from(&cfg.data_dir);
    std::fs::create_dir_all(data_dir.join("objects")).ok();
    std::fs::create_dir_all(data_dir.join("exports")).ok();
    let store = match Store::open(&data_dir.join("watch.db")) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("store: {}", e.message);
            std::process::exit(7);
        }
    };
    let object_key = std::fs::read(&cfg.object_key_file).unwrap_or_else(|_| vec![0u8; 32]);
    let objects = if object_key.len() == 32 {
        let mut k = [0u8; 32];
        k.copy_from_slice(&object_key);
        Some(ObjectStore::new(
            data_dir.join("objects"),
            &cfg.object_key_id,
            k,
        ))
    } else {
        None
    };
    let boot =
        watch::clock::boot_id().unwrap_or_else(|_| "00000000-0000-4000-8000-000000000000".into());
    let workers = WorkerPool::new(5, true);
    let d = match Daemon::start(
        store,
        cfg.clone(),
        trust,
        objects,
        workers,
        watch::clock::boottime_ms(),
        &boot,
        &sk_bytes,
    ) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("startup: {}", e.message);
            std::process::exit(5);
        }
    };
    let d = Arc::new(Mutex::new(d));
    let stop = Arc::new(AtomicBool::new(false));
    // SIGTERM/SIGINT: first signal → DRAINING; second → stop loop.
    {
        static DRAIN: AtomicBool = AtomicBool::new(false);
        let d2 = d.clone();
        let stop2 = stop.clone();
        extern "C" fn handler(_sig: libc::c_int) {
            if DRAIN.swap(true, std::sync::atomic::Ordering::Relaxed) {
                unsafe { libc::_exit(0) };
            }
        }
        unsafe {
            libc::signal(libc::SIGTERM, handler as *const () as usize);
            libc::signal(libc::SIGINT, handler as *const () as usize);
        }
        std::thread::spawn(move || loop {
            if DRAIN.load(std::sync::atomic::Ordering::Relaxed) {
                if let Ok(mut g) = d2.lock() {
                    if g.host.state == watch::schema::HostState::Ready {
                        g.host.state = watch::schema::HostState::Draining;
                        g.tick();
                    }
                }
                stop2.store(true, std::sync::atomic::Ordering::Relaxed);
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        });
    }
    let sock = PathBuf::from(&cfg.socket);
    if let Err(e) = watch::server::serve(d.clone(), &sock, stop.clone()) {
        eprintln!("serve: {e}");
        std::process::exit(5);
    }
}
