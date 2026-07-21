import Foundation

/// A `URLProtocol` that serves canned responses so client logic can be checked
/// entirely offline (no NAS, no TLS). Install by putting it in a session
/// configuration's `protocolClasses`; set `requestHandler` per scenario.
final class StubURLProtocol: URLProtocol {
    nonisolated(unsafe) private static var _handler: ((URLRequest) -> (Int, Data))?
    private static let lock = NSLock()

    static func setHandler(_ handler: ((URLRequest) -> (Int, Data))?) {
        lock.lock(); defer { lock.unlock() }
        _handler = handler
    }

    private static func handler() -> ((URLRequest) -> (Int, Data))? {
        lock.lock(); defer { lock.unlock() }
        return _handler
    }

    static func makeSession() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [StubURLProtocol.self]
        return URLSession(configuration: config)
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let handler = Self.handler() else {
            client?.urlProtocol(self, didFailWithError: URLError(.unknown))
            return
        }
        let (status, data) = handler(request)
        let response = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: "HTTP/1.1", headerFields: ["Content-Type": "application/json"])!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: data)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}
