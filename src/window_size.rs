use crate::tcp::{IpVersion, WindowSize, WindowSizeType};

/// Detects window size patterns following p0f's logic
pub fn detect_win_multiplicator(
    window_size: u16,
    mss: u16,
    total_header: u16,
    has_ts: bool,
    ip_ver: &IpVersion,
) -> WindowSize {
    const MIN_TCP4: u16 = 40; // 20 IP + 20 TCP
    const MIN_TCP6: u16 = 60; // 40 IP + 20 TCP
    const ETH_MTU: u16 = 1500; // Standard Ethernet MTU
    const TS_SIZE: u16 = 12; // TCP Timestamp option size in bytes (8 bytes for timestamps + 2 for kind/length + 2 padding)
    const MAX_MULTIPLIER: u16 = 255; // Maximum value for u8 multiplier (used in Mss and Mtu variants)

    // If there's no window or MSS is too small, return direct value
    if window_size == 0 || mss < 100 {
        return WindowSize {
            raw: Some(window_size),
            ty: WindowSizeType::Value(window_size),
        };
    }

    // 1. First check MSS multiples
    macro_rules! check_mss_div {
        ($div:expr) => {
            if $div != 0 && window_size % $div == 0 {
                let multiplier = window_size / $div;
                if multiplier <= MAX_MULTIPLIER {
                    return WindowSize {
                        raw: Some(window_size),
                        ty: WindowSizeType::Mss(multiplier as u8),
                    };
                }
            }
        };
    }

    // Check basic MSS and timestamp-adjusted MSS
    check_mss_div!(mss);
    if has_ts {
        check_mss_div!(mss - TS_SIZE);
    }

    // 2. Check common modulo patterns first
    // These are typical values used by different operating systems
    // Iterate in reverse order to find the largest modulo that divides window_size
    let modulos = [256, 512, 1024, 2048, 4096];
    for &modulo in modulos.iter().rev() {
        if window_size % modulo == 0 {
            return WindowSize {
                raw: Some(window_size),
                ty: WindowSizeType::Mod(modulo),
            };
        }
    }

    // 3. Check MTU multiples
    macro_rules! check_mtu_div {
        ($div:expr) => {
            if $div != 0 && window_size % $div == 0 {
                let multiplier = window_size / $div;
                if multiplier <= MAX_MULTIPLIER {
                    return WindowSize {
                        raw: Some(window_size),
                        ty: WindowSizeType::Mtu(multiplier as u8),
                    };
                }
            }
        };
    }

    // Standard Ethernet MTU
    check_mtu_div!(ETH_MTU);

    // MTU adjusted for IPv4/IPv6
    match ip_ver {
        IpVersion::V4 => {
            check_mtu_div!(ETH_MTU - MIN_TCP4);
            if has_ts {
                check_mtu_div!(ETH_MTU - MIN_TCP4 - TS_SIZE);
            }
        }
        IpVersion::V6 => {
            check_mtu_div!(ETH_MTU - MIN_TCP6);
            if has_ts {
                check_mtu_div!(ETH_MTU - MIN_TCP6 - TS_SIZE);
            }
        }
        IpVersion::Any => {}
    }

    // 4. Check special MTU cases
    check_mtu_div!(mss + total_header);
    match ip_ver {
        IpVersion::V4 => check_mtu_div!(mss + MIN_TCP4),
        IpVersion::V6 => check_mtu_div!(mss + MIN_TCP6),
        IpVersion::Any => {}
    }

    // If no pattern is found, return direct value
    WindowSize {
        raw: Some(window_size),
        ty: WindowSizeType::Value(window_size),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mss_multiple() {
        let mss = 1000;
        let multiplier = 40;
        let window = mss * multiplier; // 1000 * 40 = 40000 (within u16)
        let result = detect_win_multiplicator(window, mss, 40, false, &IpVersion::V4);
        assert!(matches!(
            result,
            WindowSize {
                ty: WindowSizeType::Mss(40),
                ..
            }
        ));
    }

    #[test]
    fn test_mtu_multiple() {
        let window = 4500; // 1500 * 3
        let result = detect_win_multiplicator(window, 1460, 40, false, &IpVersion::V4);
        assert!(matches!(
            result,
            WindowSize {
                ty: WindowSizeType::Mtu(3),
                ..
            }
        ));
    }

    #[test]
    fn test_modulo_pattern() {
        let window = 8192; // Power of 2, should match largest modulo (4096)
        let mss = 1337; // Prime number MSS to avoid any accidental divisions
        let result = detect_win_multiplicator(window, mss, 40, false, &IpVersion::V4);
        println!("Result for window {}: {:?}", window, result);
        assert!(matches!(
            result,
            WindowSize {
                ty: WindowSizeType::Mod(4096),
                ..
            }
        ));
    }

    #[test]
    fn test_timestamp_adjustment() {
        let window = 43800; // (1460 - 12) * 30
        let result = detect_win_multiplicator(window, 1460, 40, true, &IpVersion::V4);
        assert!(matches!(
            result,
            WindowSize {
                ty: WindowSizeType::Mss(30),
                ..
            }
        ));
    }

    #[test]
    fn test_direct_value() {
        let window = 12345; // Arbitrary value
        let result = detect_win_multiplicator(window, 1460, 40, false, &IpVersion::V4);
        assert!(matches!(
            result,
            WindowSize {
                ty: WindowSizeType::Value(12345),
                ..
            }
        ));
    }
}
