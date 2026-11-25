#if RYU_OPENVPN && canImport(OpenVPNAdapter)
import Foundation
import NetworkExtension
import OpenVPNAdapter

// Experimental integration, not yet compiled with the iOS SDK.
extension NEPacketTunnelFlow: OpenVPNAdapterPacketFlow {}

final class OpenVPNDriver: NSObject, OpenVPNAdapterDelegate {
    private weak var provider: NEPacketTunnelProvider?
    private let adapter = OpenVPNAdapter()
    private let queue = DispatchQueue(label: "ryu.openvpn.lifecycle")
    private var onStart: ((Error?) -> Void)?
    private var stops: [() -> Void] = []
    private var lifecycle = OpenVPNLifecycle()
    init(provider: NEPacketTunnelProvider) { self.provider = provider; super.init(); adapter.delegate = self }
    func start(stored: StoredProfile, completion: @escaping (Error?) -> Void) {
        queue.async {
            guard let provider = self.provider, self.lifecycle.phase == .idle else { completion(ProfileError("OpenVPN chưa sẵn sàng")); return }
            self.onStart = completion
            _ = self.lifecycle.receive(.start)
            do {
                let profile = try OVPNProfile.parse(stored.text)
                _ = try stored.kind()
                let config = OpenVPNConfiguration()
                config.fileContent = Data(stored.text.utf8)
                config.connectionTimeout = 20
                config.disableClientCert = !profile.hasClientCertificate
                config.tunPersist = false
                guard let evaluation = try self.adapter.applyConfiguration(config), !evaluation.externalPKI, !evaluation.privateKeyPasswordRequired, evaluation.autologin == !profile.requiresCredentials else { throw ProfileError("Kiểu xác thực OpenVPN chưa hỗ trợ hoặc không khớp") }
                if let auth = stored.credentials {
                    let credentials = OpenVPNCredentials()
                    credentials.username = auth.username
                    credentials.password = auth.password
                    try self.adapter.provideCredentials(credentials)
                }
                self.adapter.connect(using: provider.packetFlow)
                self.queue.asyncAfter(deadline: .now() + 30) {
                    self.handle(.startTimeout)
                }
            } catch { self.handle(.failure) }
        }
    }
    private func finishStart(_ error: Error?) { let callback = onStart; onStart = nil; callback?(error) }
    private func handle(_ event: OpenVPNLifecycle.Event) {
        let error = ProfileError("OpenVPN không kết nối được hoặc đã ngắt")
        for effect in lifecycle.receive(event) {
            switch effect {
            case .startOK: finishStart(nil)
            case .startFailed: finishStart(error)
            case .disconnect: adapter.disconnect()
            case .cancelTunnel: provider?.cancelTunnelWithError(error)
            case .finishStops:
                let callbacks = stops; stops.removeAll(); callbacks.forEach { $0() }
            }
        }
    }
    func stop(completion: @escaping () -> Void) {
        queue.async {
            self.stops.append(completion)
            self.handle(.stop)
            self.queue.asyncAfter(deadline: .now() + 8) { self.handle(.stopTimeout) }
        }
    }
    func openVPNAdapter(_ adapter: OpenVPNAdapter, configureTunnelWith settings: NEPacketTunnelNetworkSettings?, completionHandler: @escaping (Error?) -> Void) {
        queue.async {
            guard (self.lifecycle.phase == .starting || self.lifecycle.phase == .connected), let provider = self.provider, let settings = settings else { completionHandler(ProfileError("Không có network settings hợp lệ")); return }
            provider.setTunnelNetworkSettings(settings, completionHandler: completionHandler)
        }
    }
    func openVPNAdapter(_ adapter: OpenVPNAdapter, handleEvent event: OpenVPNAdapterEvent, message: String?) {
        queue.async {
            switch event {
            case .connected: self.handle(.connected)
            case .disconnected: self.handle(.disconnected)
            case .reconnecting: self.handle(.reconnecting)
            default: break
            }
        }
    }
    func openVPNAdapter(_ adapter: OpenVPNAdapter, handleError error: Error) {
        queue.async { self.handle(.failure) }
    }
}
#endif
