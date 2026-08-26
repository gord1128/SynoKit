import Foundation
import OSLog

/// Unified-log entry points shared by every SynoKit host app.
///
/// **Why a logger at all.** Until now this stack logged nothing — a deliberate
/// choice while the only user was the developer, and a dead end the moment
/// someone else runs it: "안 돼요" arrives with no way to ask back. `os.Logger`
/// costs nothing when nobody is listening, survives a crash, and needs no
/// third-party SDK or network permission.
///
/// **Subsystem is derived, never hardcoded.** SynoKit is shared by
/// SynologyPhotosManager and SynologyMonitor; taking the host's bundle id keeps
/// each app's log stream separate and lets the host filter its own logs with
/// `subsystem == Bundle.main.bundleIdentifier` (that's how the diagnostics
/// export finds them).
///
/// **Privacy is the caller's job.** Anything identifying the user's NAS or
/// library — host, username, filenames, paths — MUST be interpolated as
/// `privacy: .private`. Counts, error codes, API names and type names are
/// `.public` so a log a user hands over is actually readable.
public enum SynoLog {
    public static let subsystem = Bundle.main.bundleIdentifier ?? "com.synokit"

    /// Transport: requests, timeouts, TLS trust decisions.
    public static let net = Logger(subsystem: subsystem, category: "network")
    /// Login, OTP, session expiry and silent renewal.
    public static let auth = Logger(subsystem: subsystem, category: "auth")
    /// The encrypted local store and the API-info cache.
    public static let store = Logger(subsystem: subsystem, category: "store")
    /// Response decoding, including rows dropped for schema mismatch.
    public static let decoding = Logger(subsystem: subsystem, category: "decoding")
    /// App-level lifecycle: connect, reconnect, user-visible failures.
    public static let app = Logger(subsystem: subsystem, category: "app")

    /// A logger for a host-specific area (e.g. FotoKit's service layer), on the
    /// same subsystem so one filter catches everything.
    public static func category(_ name: String) -> Logger {
        Logger(subsystem: subsystem, category: name)
    }
}
