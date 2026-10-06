use tracing_subscriber::fmt::{format::Writer, time::FormatTime};

// copied from https://github.com/tokio-rs/tracing/pull/3493
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct TokioUptime {
    epoch: tokio::time::Instant,
}

impl Default for TokioUptime {
    fn default() -> Self {
        TokioUptime {
            epoch: tokio::time::Instant::now(),
        }
    }
}

impl From<tokio::time::Instant> for TokioUptime {
    fn from(epoch: tokio::time::Instant) -> Self {
        TokioUptime { epoch }
    }
}

impl FormatTime for TokioUptime {
    fn format_time(&self, w: &mut Writer<'_>) -> std::fmt::Result {
        let e = self.epoch.elapsed();
        write!(w, "{:>8.2?}", e)
    }
}

pub fn tokio_uptime() -> TokioUptime {
    TokioUptime::default()
}
