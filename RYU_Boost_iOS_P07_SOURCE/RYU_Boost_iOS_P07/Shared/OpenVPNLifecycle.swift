import Foundation

// Pure reducer. Driver serializes all SDK callbacks on one queue.
struct OpenVPNLifecycle {
    enum Phase: Equatable { case idle, starting, connected, closing, closed }
    enum Event { case start, connected, disconnected, failure, reconnecting, startTimeout, stop, stopTimeout }
    enum Effect: Equatable { case startOK, startFailed, disconnect, cancelTunnel, finishStops }
    private(set) var phase: Phase = .idle
    private(set) var stopping = false
    mutating func receive(_ event: Event) -> [Effect] {
        switch (phase, event) {
        case (.idle, .start): phase = .starting; return []
        case (.starting, .connected): phase = .connected; return [.startOK]
        case (.starting, .failure), (.starting, .startTimeout):
            phase = .closing; return [.startFailed, .disconnect]
        case (.starting, .disconnected): phase = .closed; return [.startFailed]
        case (.connected, .failure), (.connected, .reconnecting):
            phase = .closing; return [.disconnect, .cancelTunnel]
        case (.connected, .disconnected): phase = .closed; return [.cancelTunnel]
        case (.idle, .stop), (.closed, .stop): phase = .closed; return [.finishStops]
        case (.starting, .stop): stopping = true; phase = .closing; return [.startFailed, .disconnect]
        case (.connected, .stop): stopping = true; phase = .closing; return [.disconnect]
        case (.closing, .stop): stopping = true; return []
        case (.closing, .disconnected): phase = .closed; return stopping ? [.finishStops] : []
        case (.closing, .stopTimeout) where stopping: phase = .closed; return [.finishStops]
        default: return []
        }
    }
}
