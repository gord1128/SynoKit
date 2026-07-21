import Foundation

/// Minimal dependency-free test harness. Works under a bare Command Line Tools
/// toolchain where XCTest / swift-testing can't be loaded by `swift test`.
final class Checks {
    private(set) var total = 0
    private(set) var failed = 0
    private var currentSection = ""

    func section(_ name: String) {
        currentSection = name
        print("▶ \(name)")
    }

    func expect(_ condition: Bool, _ message: String, file: StaticString = #file, line: UInt = #line) {
        total += 1
        if condition {
            print("  ✓ \(message)")
        } else {
            failed += 1
            print("  ✘ \(message)  (\(file):\(line))")
        }
    }

    func expectEqual<T: Equatable>(_ a: T, _ b: T, _ message: String, file: StaticString = #file, line: UInt = #line) {
        expect(a == b, "\(message) — expected \(b), got \(a)", file: file, line: line)
    }

    /// Runs `body`, returning the thrown error (or nil). Never rethrows.
    func captureError(_ body: () async throws -> Void) async -> Error? {
        do { try await body(); return nil } catch { return error }
    }

    func finish() -> Never {
        print(String(repeating: "─", count: 40))
        if failed == 0 {
            print("✅ All \(total) checks passed")
            exit(0)
        } else {
            print("❌ \(failed)/\(total) checks failed")
            exit(1)
        }
    }
}
