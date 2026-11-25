import Foundation
import NetworkExtension

@MainActor private final class HealthReply {
    var continuation: CheckedContinuation<TunnelHealth?, Never>?
    init(_ continuation: CheckedContinuation<TunnelHealth?, Never>) { self.continuation = continuation }
    func finish(_ health: TunnelHealth?) {
        let pending = continuation
        continuation = nil
        pending?.resume(returning: health)
    }
}

@MainActor enum HealthClient {
    static func read(_ connection: NEVPNConnection) async -> TunnelHealth? {
        guard connection.status == .connected, let session = connection as? NETunnelProviderSession else { return nil }
        return await withCheckedContinuation { continuation in
            let reply = HealthReply(continuation)
            Task { @MainActor in
                try? await Task.sleep(nanoseconds: 3_000_000_000)
                reply.finish(nil)
            }
            do {
                try session.sendProviderMessage(Data("health-v1".utf8)) { data in
                    let decoded = data.flatMap { try? JSONDecoder().decode(TunnelHealth.self, from: $0) }
                    Task { @MainActor in reply.finish(decoded) }
                }
            } catch { reply.finish(nil) }
        }
    }
}
