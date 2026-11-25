import Foundation

// Application-level timing, not ICMP or game RTT. nil means failed request.
struct RouteScore: Codable, Equatable {
    let mtu: Int
    let samples: [Double?]
    var valid: [Double] { samples.compactMap { $0 }.filter { $0.isFinite && $0 >= 0 }.sorted() }
    var successes: Int { valid.count }
    var failureRate: Double { samples.isEmpty ? 1 : Double(samples.count - successes) / Double(samples.count) }
    func percentile(_ p: Double) -> Double? {
        let a = valid
        guard !a.isEmpty else { return nil }
        let index = Double(a.count - 1) * min(1, max(0, p))
        let lo = Int(index.rounded(.down)), hi = Int(index.rounded(.up))
        return a[lo] + (a[hi] - a[lo]) * (index - Double(lo))
    }
    var median: Double? { percentile(0.5) }
    var p95: Double? { percentile(0.95) }
    var eligible: Bool { samples.count >= 6 && failureRate <= 0.0 && p95 != nil }
    // Prefer reliable trials, then tail latency. Require meaningful improvement over original.
    static func recommendation(_ scores: [RouteScore]) -> Int? {
        guard let original = scores.first(where: { $0.mtu == 0 }), original.eligible,
              let baseline = original.p95, let baselineMedian = original.median else { return nil }
        let better = scores.filter { s in
            guard s.mtu != 0, s.eligible, let p = s.p95, let m = s.median else { return false }
            return baseline - p >= max(10, baseline * 0.15) && m <= baselineMedian
        }
        return better.min { ($0.p95 ?? .infinity) < ($1.p95 ?? .infinity) }?.mtu
    }
}
