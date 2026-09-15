use std::{io, os::fd::AsRawFd};

use super::{cmsg, imp::set_socket_option};

// TODO: Add opt-in ICMP error-queue support once callers can drain it
// before I/O and associate entries with transmitted datagrams.

pub(super) mod gso {
    use super::*;
    use std::{ffi::CStr, mem, str::FromStr, sync::OnceLock};

    // Support for UDP GSO has been added to linux kernel in version 4.18
    // https://github.com/torvalds/linux/commit/cb586c63e3fc5b227c51fd8c4cb40b34d3750645
    const SUPPORTED_SINCE: KernelVersion = KernelVersion {
        version: 4,
        major_revision: 18,
    };

    /// Checks whether GSO support is available
    ///
    /// Checks the kernel version followed by setting the UDP_SEGMENT option on a socket.
    pub(crate) fn max_gso_segments(socket: &impl AsRawFd) -> usize {
        const GSO_SIZE: libc::c_int = 1500;

        if !SUPPORTED_BY_CURRENT_KERNEL.get_or_init(supported_by_current_kernel) {
            return 1;
        }

        // As defined in linux/udp.h
        // #define UDP_MAX_SEGMENTS        (1 << 6UL)
        match set_socket_option(socket, libc::SOL_UDP, libc::UDP_SEGMENT, GSO_SIZE) {
            Ok(()) => {
                // Disable GSO again globally to ensure we can selectively enable it via cmsg.
                // See:
                // - https://github.com/quinn-rs/quinn/issues/2575
                // - https://man7.org/linux/man-pages/man7/udp.7.html
                drop(set_socket_option(
                    socket,
                    libc::SOL_UDP,
                    libc::UDP_SEGMENT,
                    0,
                ));

                64
            }
            Err(_e) => {
                crate::log::debug!(
                    "failed to set `UDP_SEGMENT` socket option ({_e}); setting `max_gso_segments = 1`"
                );

                1
            }
        }
    }

    pub(crate) fn set_segment_size(
        encoder: &mut cmsg::Encoder<'_, libc::msghdr>,
        segment_size: u16,
    ) -> io::Result<()> {
        encoder.push(libc::SOL_UDP, libc::UDP_SEGMENT, segment_size)
    }

    // Avoid calling `supported_by_current_kernel` for each socket by using `OnceLock`.
    static SUPPORTED_BY_CURRENT_KERNEL: OnceLock<bool> = OnceLock::new();

    fn supported_by_current_kernel() -> bool {
        match kernel_version_string() {
            Ok(release) => supported_by_kernel_release(&release),
            Err(_e) => {
                crate::log::warn!("GSO disabled: uname returned {_e}");
                false
            }
        }
    }

    /// Whether `release`, as `uname` reports it, is at or past the kernel that
    /// added UDP GSO.
    ///
    /// Separate from [`supported_by_current_kernel`] so the boundary is decided
    /// by a release string a test can choose, rather than by whichever kernel
    /// the tests happen to run on.
    fn supported_by_kernel_release(release: &str) -> bool {
        let Some(kernel_version) = KernelVersion::from_str(release) else {
            crate::log::warn!("GSO disabled: failed to parse kernel version ({release})");
            return false;
        };

        if kernel_version < SUPPORTED_SINCE {
            crate::log::info!("GSO disabled: kernel too old ({release}); need 4.18+");
            return false;
        }

        true
    }

    fn kernel_version_string() -> io::Result<String> {
        // SAFETY: all-zero is a valid initial state for `utsname`, whose fields
        // are filled by `uname`.
        let mut n = unsafe { mem::zeroed() };
        // SAFETY: `n` is valid writable storage for one `utsname` value.
        let r = unsafe { libc::uname(&mut n) };
        if r != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a successful `uname` call writes NUL-terminated arrays into
        // every textual field, including `release`.
        Ok(unsafe {
            CStr::from_ptr(n.release[..].as_ptr())
                .to_string_lossy()
                .into_owned()
        })
    }

    // https://www.linfo.org/kernel_version_numbering.html
    #[derive(Eq, PartialEq, Ord, PartialOrd, Debug)]
    struct KernelVersion {
        version: u8,
        major_revision: u8,
    }

    impl KernelVersion {
        fn from_str(release: &str) -> Option<Self> {
            let mut split = release
                .split_once('-')
                .map(|pair| pair.0)
                .unwrap_or(release)
                .split('.');

            let version = u8::from_str(split.next()?).ok()?;
            let major_revision = u8::from_str(split.next()?).ok()?;

            Some(Self {
                version,
                major_revision,
            })
        }
    }

    #[cfg(test)]
    mod test {
        use super::*;

        /// The kernel that introduced UDP GSO is the boundary itself: the
        /// release before it is refused and that release is already accepted.
        /// Getting this off by one either loses segmentation offload on every
        /// 4.18 kernel or asks a 4.17 one for an option it does not have.
        #[test]
        fn gso_support_starts_at_the_kernel_release_that_added_it() {
            assert!(!supported_by_kernel_release("3.19.8"));
            assert!(!supported_by_kernel_release("4.17.19-generic"));
            assert!(supported_by_kernel_release("4.18.0-generic"));
            assert!(supported_by_kernel_release("6.8.0-59-generic"));
        }

        /// A release no version can be read from disables the feature rather
        /// than assuming it is there, which would push the failure out to a
        /// `sendmsg` the kernel cannot honour.
        #[test]
        fn a_kernel_release_that_cannot_be_read_disables_gso() {
            for release in ["", "linux", "6", "6.x", "-generic"] {
                assert!(
                    !supported_by_kernel_release(release),
                    "unreadable release {release:?}"
                );
            }
        }

        #[test]
        fn parse_current_kernel_version_release_string() {
            let release = kernel_version_string().unwrap();
            KernelVersion::from_str(&release).unwrap();
        }

        #[test]
        fn parse_kernel_version_release_string() {
            // These are made up for the test
            assert_eq!(
                KernelVersion::from_str("4.14"),
                Some(KernelVersion {
                    version: 4,
                    major_revision: 14
                })
            );
            assert_eq!(
                KernelVersion::from_str("4.18"),
                Some(KernelVersion {
                    version: 4,
                    major_revision: 18
                })
            );
            // These were seen in the wild
            assert_eq!(
                KernelVersion::from_str("4.14.186-27095505"),
                Some(KernelVersion {
                    version: 4,
                    major_revision: 14
                })
            );
            assert_eq!(
                KernelVersion::from_str("6.8.0-59-generic"),
                Some(KernelVersion {
                    version: 6,
                    major_revision: 8
                })
            );
        }
    }
}
