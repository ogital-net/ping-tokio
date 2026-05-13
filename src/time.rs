use std::time::Duration;

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub(crate) struct Timestamp {
    sec: u32,
    nsec: u32,
}

impl Timestamp {
    /// Get the current monotonic time as a Timestamp.
    /// Uses `CLOCK_MONOTONIC` which is not affected by system clock adjustments.
    pub(crate) fn now() -> Self {
        let mut ts = std::mem::MaybeUninit::<libc::timespec>::uninit();

        let result = unsafe {
            #[cfg(target_vendor = "apple")]
            let clock_id = libc::CLOCK_UPTIME_RAW;
            #[cfg(not(target_vendor = "apple"))]
            let clock_id = libc::CLOCK_MONOTONIC;

            libc::clock_gettime(clock_id, ts.as_mut_ptr())
        };

        assert_eq!(
            result,
            0,
            "clock_gettime failed: {}",
            std::io::Error::last_os_error()
        );

        let ts = unsafe { ts.assume_init() };

        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        Timestamp {
            sec: ts.tv_sec as u32,
            nsec: ts.tv_nsec as u32,
        }
    }

    /// Serialise the timestamp to an 8-byte buffer in network (big-endian) byte order.
    pub(crate) fn as_bytes(self) -> [u8; 8] {
        let mut buf = [0u8; 8];
        buf[..4].copy_from_slice(&self.sec.to_be_bytes());
        buf[4..].copy_from_slice(&self.nsec.to_be_bytes());
        buf
    }

    /// Return the size of the Timestamp struct in bytes.
    pub(crate) fn len() -> usize {
        std::mem::size_of::<Timestamp>()
    }
}

impl From<[u8; 8]> for Timestamp {
    fn from(bytes: [u8; 8]) -> Self {
        Timestamp {
            sec: u32::from_be_bytes(bytes[..4].try_into().unwrap()),
            nsec: u32::from_be_bytes(bytes[4..].try_into().unwrap()),
        }
    }
}

impl std::ops::Sub for Timestamp {
    type Output = Duration;

    fn sub(self, rhs: Timestamp) -> Duration {
        let self_total_nsec = u64::from(self.sec) * 1_000_000_000 + u64::from(self.nsec);
        let rhs_total_nsec = u64::from(rhs.sec) * 1_000_000_000 + u64::from(rhs.nsec);

        if self_total_nsec >= rhs_total_nsec {
            Duration::from_nanos(self_total_nsec - rhs_total_nsec)
        } else {
            Duration::from_secs(0)
        }
    }
}
