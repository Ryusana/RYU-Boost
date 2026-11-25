import Foundation
import NetworkExtension
import WireGuardKit

final class PacketTunnelProvider: NEPacketTunnelProvider {
    #if RYU_OPENVPN && canImport(OpenVPNAdapter)
    private var openVPN: OpenVPNDriver?
    #endif
    private lazy var adapter = WireGuardAdapter(with: self, logHandler: { _,_ in })
    override func startTunnel(options: [String:NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        do {
            guard let p = protocolConfiguration as? NETunnelProviderProtocol, let ref = p.passwordReference else { throw ProfileError("Thiếu cấu hình") }
            let stored = try StoredProfile.decode(KeyStore.read(ref))
            let text = stored.text
            let kind = try stored.kind()
            if let declared = p.providerConfiguration?["kind"] as? String, declared != kind.rawValue { throw ProfileError("Giao thức profile không khớp") }
            if kind == .openvpn {
                #if RYU_OPENVPN && canImport(OpenVPNAdapter)
                let driver = OpenVPNDriver(provider: self)
                openVPN = driver; driver.start(stored: stored, completion: completionHandler); return
                #else
                throw ProfileError("OpenVPN cần bản build thử nghiệm")
                #endif
            }
            let profile = try WGProfile.parse(text)
            let a = profile.interface, b = profile.peer
            guard let privateKey = PrivateKey(base64Key: a["privatekey"] ?? ""), let publicKey = PublicKey(base64Key: b["publickey"] ?? ""), let endpoint = Endpoint(from: b["endpoint"] ?? "") else { throw ProfileError("Khóa hoặc endpoint không hợp lệ") }
            var i = InterfaceConfiguration(privateKey: privateKey)
            let addresses = profile.list(a["address"])
            i.addresses = addresses.compactMap { IPAddressRange(from: $0) }
            guard !i.addresses.isEmpty, addresses.count == i.addresses.count else { throw ProfileError("Address không hợp lệ") }
            let dns = profile.list(a["dns"])
            i.dns = dns.compactMap { DNSServer(from: $0) }
            guard i.dns.count == dns.count else { throw ProfileError("P0 chỉ hỗ trợ DNS dạng IP") }
            i.listenPort = a["listenport"].flatMap { UInt16($0) }
            let override = p.providerConfiguration?["mtu"] as? Int ?? 0
            i.mtu = override == 0 ? a["mtu"].flatMap { UInt16($0) } : UInt16(exactly: override)
            var peer = PeerConfiguration(publicKey: publicKey)
            peer.endpoint = endpoint
            let allowed = profile.list(b["allowedips"])
            peer.allowedIPs = allowed.compactMap { IPAddressRange(from: $0) }
            guard !peer.allowedIPs.isEmpty, allowed.count == peer.allowedIPs.count else { throw ProfileError("AllowedIPs không hợp lệ") }
            if let key = b["presharedkey"] { guard let k = PreSharedKey(base64Key: key) else { throw ProfileError("PSK không hợp lệ") }; peer.preSharedKey = k }
            peer.persistentKeepAlive = b["persistentkeepalive"].flatMap { UInt16($0) }
            let config = TunnelConfiguration(name: "RYU Boost", interface: i, peers: [peer])
            adapter.start(tunnelConfiguration: config) { error in completionHandler(error) }
        } catch { completionHandler(error) }
    }
    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        #if RYU_OPENVPN && canImport(OpenVPNAdapter)
        if openVPN != nil { completionHandler?(nil); return }
        #endif
        guard messageData == Data("health-v1".utf8) else { completionHandler?(nil); return }
        adapter.getRuntimeConfiguration { raw in
            guard let raw = raw, let health = TunnelHealth.parse(raw) else { completionHandler?(nil); return }
            completionHandler?(try? JSONEncoder().encode(health))
        }
    }
    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        #if RYU_OPENVPN && canImport(OpenVPNAdapter)
        if let driver = openVPN { driver.stop { self.openVPN = nil; completionHandler() }; return }
        #endif
        adapter.stop { _ in completionHandler() }
    }
}
