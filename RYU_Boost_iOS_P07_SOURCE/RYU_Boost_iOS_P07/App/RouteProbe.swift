import Foundation

// Fresh ephemeral HTTPS requests; includes connection setup, TLS and server response.
// This is a proxy metric, never game ping or packet loss.
enum RouteProbe {
    static let target = URL(string: "https://www.google.com/generate_204")!
    static func measure() async -> Double? {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 4
        config.timeoutIntervalForResource = 5
        config.urlCache = nil
        let session = URLSession(configuration: config)
        defer { session.invalidateAndCancel() }
        var request = URLRequest(url: target, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 4)
        request.httpMethod = "GET"
        let start = ProcessInfo.processInfo.systemUptime
        do {
            let (_, response) = try await session.data(for: request)
            guard (response as? HTTPURLResponse)?.statusCode == 204, response.url == target else { return nil }
            return (ProcessInfo.processInfo.systemUptime - start) * 1000
        } catch { return nil }
    }
}
