use log::debug;
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use ttl_cache::TtlCache;

const MIN_TWAIT: u64 = 25;
const MAX_TWAIT: u64 = 10 * 60 * 1000;
const TSTAMP_GRACE: u64 = 1000;
const MAX_TSCALE: f64 = 1000.0;
const MIN_TSCALE: f64 = 0.01;

#[derive(Debug, Hash, Eq, PartialEq, Clone)]
pub struct Connection {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

pub struct SynData {
    ts1: u32,
    recv_ms: u64,
}

pub struct ObservableUptime {
    pub days: u32,
    pub hours: u32,
    pub min: u32,
    pub up_mod_days: u32,
    pub freq: u32,
}

fn get_unix_time_ms() -> u64 {
    let now = SystemTime::now();
    now.duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis() as u64
}

pub fn check_ts_tcp(
    cache: &mut TtlCache<Connection, SynData>,
    connection: &Connection,
    from_client: bool,
    ts_val: u32,
) -> Option<ObservableUptime> {
    let syn_data: Option<SynData> = if !from_client {
        let client_connection = Connection {
            src_ip: connection.dst_ip,
            src_port: connection.dst_port,
            dst_ip: connection.src_ip,
            dst_port: connection.src_port,
        };
        cache.remove(&client_connection)
    } else {
        cache.insert(
            connection.clone(),
            SynData {
                ts1: ts_val,
                recv_ms: get_unix_time_ms(),
            },
            Duration::new(60, 0),
        );
        None
    };

    // If there's no valid SYN data yet, return early
    let last_syn_data = syn_data?;
    let ms_diff = get_unix_time_ms().saturating_sub(last_syn_data.recv_ms);
    // TODO: check if ts_diff is in nanoseconds
    let ts_diff = (ts_val.saturating_sub(last_syn_data.ts1) / 1000000) as u64;

    // Check if the time differences are valid
    if !(MIN_TWAIT..=MAX_TWAIT).contains(&ms_diff) {
        return None;
    }

    if ts_diff < 5
        || (ms_diff < TSTAMP_GRACE
            && ts_diff.wrapping_neg() / 1000 < (MAX_TSCALE as u64 / TSTAMP_GRACE))
    {
        return None;
    }

    // Calculate the timestamp frequency
    let ffreq: f64 = if ts_diff > ts_diff.wrapping_neg() {
        ts_diff.wrapping_neg() as f64 * -1000.0 / ms_diff as f64
    } else {
        ts_diff as f64 * 1000.0 / ms_diff as f64
    };

    // Check if the frequency is within acceptable bounds
    if !(MIN_TSCALE..=MAX_TSCALE).contains(&ffreq) {
        debug!(
            "Invalid frequency: ffreq={}, ts_diff={}, ms_diff={}",
            ffreq, ts_diff, ms_diff
        );
        return None;
    }

    // Round the frequency to the nearest valid value
    let freq = match ffreq.round() as u32 {
        0 => 1,
        1..=10 => ffreq.round() as u32,
        11..=50 => ((ffreq.round() + 3.0) / 5.0).round() as u32 * 5,
        51..=100 => ((ffreq.round() + 7.0) / 10.0).round() as u32 * 10,
        101..=500 => ((ffreq.round() + 33.0) / 50.0).round() as u32 * 50,
        _ => ((ffreq.round() + 67.0) / 100.0).round() as u32 * 100,
    };

    // Calculate uptime in minutes and modulo days
    let up_min = ts_val / freq / 60;
    let up_mod_days = 0xFFFFFFFF / (freq * 60 * 60 * 24);

    Some(ObservableUptime {
        days: up_min / 60 / 24,
        hours: (up_min / 60) % 24,
        min: up_min % 60,
        up_mod_days,
        freq,
    })
}
