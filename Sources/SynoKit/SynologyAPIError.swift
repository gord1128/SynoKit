import Foundation

/// Transport/auth-level errors that are meaningful for any DSM API. App-specific
/// numeric error codes (e.g. SYNO.DownloadStation.Task's 400–408, which collide
/// with the auth API's meanings) must be mapped by the host app, NOT here.
public enum SynologyAPIError: Error, LocalizedError {
    case invalidCredentials
    /// Account has 2FA enabled and no (or missing) OTP code was supplied.
    case otpRequired
    /// The supplied 2FA OTP code was wrong/expired.
    case otpIncorrect
    case sessionExpired
    case hostUnreachable(underlying: Error)
    case apiUnavailable(apiName: String)
    case apiVersionMismatch(apiName: String, requested: Int, maxSupported: Int)
    case certificateUntrusted(host: String, port: Int, fingerprint: String, leafCertData: Data)
    case certificateChanged(host: String, port: Int, oldFingerprint: String, newFingerprint: String, newCertificateData: Data)
    case decodingError(Error)
    case dsmError(code: Int)
    case actionFailed(message: String)
    case invalidResponse

    public var errorDescription: String? {
        switch self {
        case .invalidCredentials:
            return "아이디 또는 비밀번호가 올바르지 않습니다."
        case .otpRequired:
            return "2단계 인증 코드가 필요합니다."
        case .otpIncorrect:
            return "2단계 인증 코드가 올바르지 않습니다."
        case .sessionExpired:
            return "세션이 만료되었습니다. 다시 로그인해주세요."
        case .hostUnreachable(let underlying):
            return "NAS에 연결할 수 없습니다: \(underlying.localizedDescription)"
        case .apiUnavailable(let apiName):
            return "이 NAS에서 \(apiName) 기능을 지원하지 않습니다."
        case .apiVersionMismatch(let apiName, let requested, let maxSupported):
            return "\(apiName) API 버전 불일치 (요청: \(requested), 지원: \(maxSupported))"
        case .certificateUntrusted(let host, let port, _, _):
            return "\(host):\(port)의 인증서를 신뢰할 수 없습니다."
        case .certificateChanged(let host, let port, _, _, _):
            return "\(host):\(port)의 인증서가 이전에 신뢰했던 것과 다릅니다."
        case .decodingError(let underlying):
            return "응답을 해석할 수 없습니다: \(underlying.localizedDescription)"
        case .dsmError(let code):
            return "NAS 오류 (코드: \(code))"
        case .actionFailed(let message):
            return message
        case .invalidResponse:
            return "잘못된 응답입니다."
        }
    }

    /// SYNO.API.Auth error codes indicating the session needs re-authentication.
    public static let sessionErrorCodes: Set<Int> = [105, 106, 107, 119]

    /// Maps a SYNO.API.Auth error code to a typed error. Only valid for the auth
    /// API — other APIs reuse these numbers with unrelated meanings.
    ///
    /// 400/401/402 → bad credentials, 403 → OTP required, 404 → OTP incorrect,
    /// 406 → 2FA enforcement (treated as OTP required). Session codes map to
    /// `.sessionExpired`; everything else to `.dsmError`.
    public static func fromAuthErrorCode(_ code: Int) -> SynologyAPIError {
        switch code {
        case 400, 401, 402:
            return .invalidCredentials
        case 403, 406:
            return .otpRequired
        case 404:
            return .otpIncorrect
        default:
            if sessionErrorCodes.contains(code) { return .sessionExpired }
            return .dsmError(code: code)
        }
    }

    /// For non-auth APIs: only session codes get special handling; the rest are
    /// surfaced as raw `.dsmError` for the host app to interpret in context.
    public static func fromDataErrorCode(_ code: Int) -> SynologyAPIError {
        if sessionErrorCodes.contains(code) { return .sessionExpired }
        return .dsmError(code: code)
    }
}
