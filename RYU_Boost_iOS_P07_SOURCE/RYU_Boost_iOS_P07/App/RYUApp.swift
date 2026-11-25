import SwiftUI
import NetworkExtension
import UniformTypeIdentifiers

@main struct RYUApp: App { var body: some Scene { WindowGroup { MainView() } } }

@MainActor final class Booster: ObservableObject {
    @Published var state = "Chưa kết nối"
    @Published var message = "Nhập cấu hình VPN được cấp cho bạn để bắt đầu."
    @Published var ready = false
    @Published var active = false
    @Published var busy = false
    @Published var mtu = 0
    @Published var scores: [RouteScore] = []
    @Published var suggestedMTU: Int?
    @Published var testing = false
    @Published private(set) var catalog = NodeCatalog()
    @Published private(set) var selectedID: UUID?
    @Published private(set) var nodeTrials: [NodeTrial] = []
    @Published private(set) var suggestedNode: UUID?
    @Published var needsCredentials = false
    private var pendingProfile: String?
    private var catalogOK = false
    var nodeReport: String {
        (["RYU Boost P0.6 — HTTPS proxy, không phải ping game"] + nodeTrials.map { t in
            let name = catalog.nodes.first { $0.id == t.id }?.name ?? "Node"
            let s = t.score
            return "\(name): \(s.successes)/8; median \(s.median.map { String(format: "%.1f", $0) } ?? "---") ms; P95 \(s.p95.map { String(format: "%.1f", $0) } ?? "---") ms"
        } + ["Đề xuất: \(catalog.nodes.first { $0.id == suggestedNode }?.name ?? "giữ tuyến hiện tại / chưa đủ bằng chứng")"]).joined(separator: "\n")
    }
    @Published private(set) var health: TunnelHealth?
    @Published private(set) var healthText = "Chưa có dữ liệu tunnel"
    private var polling = false
    private var needsRefresh = false
    private var stopRequested = false
    var report: String {
        let rows = scores.map { s in
            "MTU \(s.mtu == 0 ? "gốc" : String(s.mtu)): \(s.successes)/\(s.samples.count) thành công; median \(s.median.map { String(format: "%.1f", $0) } ?? "---") ms; P95 \(s.p95.map { String(format: "%.1f", $0) } ?? "---") ms"
        }
        return (["RYU Boost P0.6 — HTTPS Google generate_204, không phải ping game"] + rows + ["MTU đề xuất: \(suggestedMTU.map { String($0) } ?? "không đủ bằng chứng / giữ gốc")"]).joined(separator: "\n")
    }
    private var manager: NETunnelProviderManager?
    private let providerID = Bundle.main.bundleIdentifier! + ".tunnel"
    func refresh() async {
        guard !busy else { return }
        busy = true; defer { busy = false; sync() }
        do {
            let all = try await NETunnelProviderManager.loadAllFromPreferences()
            let ours = all.filter { ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == providerID }
            guard ours.count <= 1 else { throw ProfileError("Có nhiều cấu hình RYU trong iOS; kiểm tra trong Cài đặt trước khi tiếp tục") }
            manager = ours.first
            catalogOK = false
            var c = try CatalogStorage.load()
            mtu = (manager?.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration?["mtu"] as? Int ?? 0
            if let ref = currentRef {
                let kind = try inspectStored(ref)
                let n = try c.adopt(ref, mtu: mtu, kind: kind)
                guard n.protocolKind == kind else { throw ProfileError("Metadata giao thức không khớp") }
                c.setMTU(mtu, for: ref)
                selectedID = n.id
                ready = (try? KeyStore.read(ref)) != nil
            } else { selectedID = nil; ready = false }
            try CatalogStorage.save(c); catalog = c; catalogOK = true
            needsRefresh = false
            sync()
        } catch { ready = false; needsRefresh = true; catalogOK = false; sync(); message = "Không đọc được cấu hình VPN: \(error.localizedDescription)" }
    }
    var selectedKind: VPNKind { catalog.nodes.first { $0.id == selectedID }?.protocolKind ?? .wireguard }
    var supportsWGTests: Bool { selectedKind == .wireguard }
    private func inspectStored(_ ref: Data) throws -> VPNKind {
        let kind = try StoredProfile.decode(KeyStore.read(ref)).kind()
        #if !RYU_OPENVPN
        guard kind == .wireguard else { throw ProfileError("OpenVPN cần bản build thử nghiệm") }
        #endif
        return kind
    }
    private var currentRef: Data? { (manager?.protocolConfiguration as? NETunnelProviderProtocol)?.passwordReference }
    private func clearResults() { scores = []; suggestedMTU = nil; nodeTrials = []; suggestedNode = nil }
    private func configure(_ m: NETunnelProviderManager, ref: Data, mtu: Int) async throws {
        guard m.connection.status == .disconnected || m.connection.status == .invalid else { throw ProfileError("VPN chưa ngắt") }
        let p = NETunnelProviderProtocol()
        let kind = try inspectStored(ref)
        let chosenMTU = kind == .wireguard ? mtu : 0
        p.providerBundleIdentifier = providerID; p.serverAddress = "RYU " + kind.rawValue; p.passwordReference = ref
        p.providerConfiguration = ["mtu": chosenMTU, "kind": kind.rawValue]
        m.protocolConfiguration = p; m.localizedDescription = "RYU Boost"; m.isEnabled = true; m.isOnDemandEnabled = false
        try await m.saveToPreferences(); try await m.loadFromPreferences()
        guard (m.protocolConfiguration as? NETunnelProviderProtocol)?.passwordReference == ref,
              (m.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration?["mtu"] as? Int == chosenMTU,
              (m.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration?["kind"] as? String == kind.rawValue else { throw ProfileError("Không xác minh được profile đã lưu") }
    }
    func pollHealth() async {
        guard !busy, !polling, let m = manager, m.connection.status == .connected else { return }
        guard selectedKind == .wireguard else { health = nil; healthText = "OpenVPN: trạng thái iOS, chưa có bộ đếm được xác minh"; return }
        polling = true; defer { polling = false }
        let data = await HealthClient.read(m.connection)
        guard !busy, m.connection.status == .connected, manager === m else { return }
        health = data
        healthText = data?.status(now: Date().timeIntervalSince1970) ?? "Không đọc được bộ đếm tunnel"
    }
    func sync() {
        let s = manager?.connection.status ?? .invalid
        active = s == .connected || s == .connecting || s == .reasserting || s == .disconnecting
        if s != .connected { health = nil; healthText = "Chưa có dữ liệu tunnel" }
        switch s {
        case .connected: state = "Tunnel đã bật (chưa xác minh game)"
        case .connecting: state = "Đang kết nối"
        case .reasserting: state = "Đang khôi phục"
        case .disconnecting: state = "Đang ngắt"
        default: state = "Chưa kết nối"
        }
    }
    func importProfile(_ url: URL) async {
        guard !busy, !active, catalogOK, !needsRefresh else { return }
        busy = true; defer { busy = false; sync() }
        let scoped = url.startAccessingSecurityScopedResource(); defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        do {
            guard catalog.nodes.count < NodeCatalog.limit else { throw ProfileError("Tối đa 6 profile") }
            let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
            guard size <= 65536 else { throw ProfileError("Profile quá lớn") }
            let data = try Data(contentsOf: url)
            guard let text = String(data: data, encoding: .utf8) else { throw ProfileError("File không phải UTF-8") }
            let kind = try ProfileKind.inspect(text)
            #if !RYU_OPENVPN
            guard kind == .wireguard else { throw ProfileError("Cần build thử nghiệm OpenVPN") }
            #endif
            if kind == .openvpn, try OVPNProfile.parse(text).requiresCredentials {
                pendingProfile = text; needsCredentials = true
                return
            }
            try await saveImported(StoredProfile(text: text, credentials: nil))
        } catch { message = "Không nhập được profile: \(error.localizedDescription)" }
    }
    func cancelCredentials() { pendingProfile = nil; needsCredentials = false }
    func submitCredentials(_ auth: VPNCredentials) async {
        guard !busy, !active, catalogOK, !needsRefresh, let text = pendingProfile else { cancelCredentials(); return }
        busy = true; defer { busy = false; sync() }
        do {
            try auth.validate()
            try await saveImported(StoredProfile(text: text, credentials: auth))
            cancelCredentials()
        } catch { message = "Không lưu được profile OpenVPN"; cancelCredentials() }
    }
    private func saveImported(_ stored: StoredProfile) async throws {
        guard catalog.nodes.count < NodeCatalog.limit, !active else { throw ProfileError("Thư viện đầy hoặc VPN đang bật") }
        let kind = try stored.kind()
        let ref = try KeyStore.add(stored.encodeForKeychain())
        var c = catalog
        let n: NodeRecord
        do { n = try c.adopt(ref, mtu: 0, kind: kind); try CatalogStorage.save(c) }
        catch { KeyStore.remove(ref); throw error }
        catalog = c; clearResults()
        if currentRef == nil {
            let m = manager ?? NETunnelProviderManager()
            manager = m
            do { try await configure(m, ref: ref, mtu: 0); selectedID = n.id; mtu = 0; ready = true }
            catch { needsRefresh = true; ready = false; throw error }
        }
        message = "Đã thêm \(n.name). Chọn node hoặc bấm BOOST."
    }
    // Save a separate, inactive candidate. Original provider profile stays intact.
    func createSelective(_ input: String) {
        guard supportsWGTests, !busy, !active, !needsRefresh, catalogOK, ready,
              let ref = currentRef, catalog.nodes.count < NodeCatalog.limit else { return }
        do {
            guard let text = String(data: try KeyStore.read(ref), encoding: .utf8) else { throw ProfileError("Profile không đọc được") }
            let source = try WGProfile.parse(text)
            let plan = try SelectiveRoutes.plan(source, input: input)
            let data = try plan.derivedProfile(source)
            let newRef = try KeyStore.add(data)
            var c = catalog
            let node: NodeRecord
            do {
                node = try c.adopt(newRef, mtu: mtu, selectiveCount: plan.gameCount)
                try CatalogStorage.save(c)
            } catch { KeyStore.remove(newRef); throw error }
            catalog = c; clearResults()
            message = "Đã tạo \(node.name) Selective: \(plan.gameCount) tuyến game, \(plan.routes.count) tuyến cả DNS. Chọn node mới trước trận; node gốc vẫn giữ nguyên."
        } catch { message = "Không tạo được tuyến chọn lọc: \(error.localizedDescription)" }
    }
    func selectNode(_ id: UUID) async {
        guard !busy, !active, !needsRefresh, catalogOK, let n = catalog.nodes.first(where: {$0.id == id}) else { return }
        busy = true; defer { busy = false; sync() }
        do {
            _ = try KeyStore.read(n.ref)
            var c = catalog
            if let ref = currentRef { c.setMTU(mtu, for: ref) }
            try CatalogStorage.save(c); catalog = c
            let m = manager ?? NETunnelProviderManager(); manager = m
            try await configure(m, ref: n.ref, mtu: n.mtu)
            selectedID = n.id; mtu = n.mtu; ready = true
            clearResults(); message = "Đã chọn \(n.name). VPN vẫn ngắt."
        } catch { needsRefresh = true; ready = false; message = "Không xác nhận được cấu hình. Bấm đọc lại trạng thái VPN." }
    }
    func removeNode(_ id: UUID) {
        guard !busy, !active, !needsRefresh, catalogOK else { return }
        var c = catalog
        guard let n = c.remove(id, current: currentRef) else { return }
        do { try CatalogStorage.save(c); catalog = c; KeyStore.remove(n.ref); clearResults(); message = "Đã xóa profile khỏi thư viện." }
        catch { message = "Không lưu được thư viện." }
    }
    func toggle() async {
        guard !busy, let m = manager else { return }
        if active { m.connection.stopVPNTunnel(); sync(); return }
        guard !needsRefresh, ready else { return }
        busy = true; defer { busy = false }
        do {
            guard let p = m.protocolConfiguration as? NETunnelProviderProtocol else { throw ProfileError("Thiếu cấu hình") }
            let kind = try inspectStored(p.passwordReference ?? Data())
            p.providerConfiguration = ["mtu": kind == .wireguard ? mtu : 0, "kind": kind.rawValue]
            m.protocolConfiguration = p; m.isEnabled = true; m.isOnDemandEnabled = false
            try await m.saveToPreferences(); try await m.loadFromPreferences()
            if let ref = currentRef { var c = catalog; c.setMTU(mtu, for: ref); try CatalogStorage.save(c); catalog = c }
            try m.connection.startVPNTunnel()
            message = "Đã yêu cầu kết nối. Chờ trạng thái tunnel; vào game để kiểm tra ping."
        } catch { needsRefresh = true; ready = false; message = "Không kết nối được: \(error.localizedDescription). Đọc lại trạng thái VPN." }
        sync()
    }

    private func waitStatus(_ m: NETunnelProviderManager, connected: Bool, timeout: Double) async -> Bool {
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        repeat {
            let s = m.connection.status
            if connected && s == .connected { return true }
            if !connected && (s == .disconnected || s == .invalid) { return true }
            if connected && stopRequested { return false }
            try? await Task.sleep(nanoseconds: 250_000_000)
        } while ProcessInfo.processInfo.systemUptime < deadline
        return false
    }
    func requestStopTest() { stopRequested = true; message = "Đang dừng và khôi phục cấu hình…" }
    func testMTU() async {
        guard supportsWGTests, !busy, !needsRefresh, !active, ready, let m = manager else { return }
        guard let p = m.protocolConfiguration as? NETunnelProviderProtocol,
              let ref = p.passwordReference,
              let raw = try? KeyStore.read(ref), let text = String(data: raw, encoding: .utf8),
              let profile = try? WGProfile.parse(text) else { message = "Thiếu profile hợp lệ"; return }
        // Avoid recommending based on a probe that is obviously outside split tunnel routes.
        let routes = Set(profile.list(profile.peer["allowedips"]))
        guard routes.contains("0.0.0.0/0"), routes.contains("::/0") else {
            message = "Tự thử MTU hiện yêu cầu profile full tunnel IPv4 + IPv6. Profile khác vẫn dùng BOOST bình thường."; return
        }
        busy = true; testing = true; stopRequested = false; scores = []; suggestedMTU = nil
        let oldMTU = mtu
        var restoreOK = false
        var complete = true
        for variant in [0, 1420, 1380, 1280] {
            if stopRequested { complete = false; break }
            message = "Đang thử MTU \(variant == 0 ? "gốc" : String(variant))…"
            var samples: [Double?] = []
            do {
                guard let config = m.protocolConfiguration as? NETunnelProviderProtocol else { throw ProfileError("Thiếu cấu hình") }
                config.providerConfiguration = ["mtu": variant]
                m.protocolConfiguration = config
                m.isOnDemandEnabled = false
                try await m.saveToPreferences(); try await m.loadFromPreferences()
                try m.connection.startVPNTunnel()
                if await waitStatus(m, connected: true, timeout: 15) {
                    for n in 0..<6 {
                        if stopRequested { break }
                        guard m.connection.status == .connected else { break }
                        message = "MTU \(variant == 0 ? "gốc" : String(variant)) — mẫu \(n + 1)/6"
                        let before = await HealthClient.read(m.connection)
                        if stopRequested { break }
                        let value = await RouteProbe.measure()
                        let after = await HealthClient.read(m.connection)
                        // Evidence of an active peer, not proof that this particular HTTPS request was tunneled.
                        if let before = before, let after = after,
                           after.recent(now: Date().timeIntervalSince1970), after.exchanged(since: before),
                           m.connection.status == .connected { samples.append(value) }
                        else { samples.append(nil) }
                    }
                }
            } catch { message = "Thử cấu hình thất bại; sẽ ngắt và khôi phục." }
            if samples.count < 6 { samples += Array(repeating: nil, count: 6 - samples.count) }
            scores.append(RouteScore(mtu: variant, samples: samples))
            m.connection.stopVPNTunnel()
            if !(await waitStatus(m, connected: false, timeout: 15)) { complete = false; break }
        }
        m.connection.stopVPNTunnel()
        if await waitStatus(m, connected: false, timeout: 15) {
            do {
                guard let config = m.protocolConfiguration as? NETunnelProviderProtocol else { throw ProfileError("Thiếu cấu hình") }
                config.providerConfiguration = ["mtu": oldMTU]
                m.protocolConfiguration = config
                try await m.saveToPreferences(); try await m.loadFromPreferences()
                restoreOK = true
            } catch { restoreOK = false }
        }
        mtu = oldMTU
        needsRefresh = !restoreOK
        if needsRefresh { ready = false }
        if complete && !stopRequested && restoreOK { suggestedMTU = RouteScore.recommendation(scores) }
        message = !restoreOK ? "Không xác nhận được khôi phục cấu hình. Kiểm tra VPN trong Cài đặt iOS trước khi BOOST." :
            (stopRequested ? "Đã dừng, giữ MTU cũ." : "Đã kết thúc thử nghiệm. VPN đã ngắt; chỉ áp dụng đề xuất sau khi xem kết quả. HTTPS không phải ping game.")
        testing = false; busy = false; sync()
    }

    func compareNodes() async {
        guard supportsWGTests, !busy, !active, !needsRefresh, catalogOK, ready, let m = manager,
              let original = currentRef, let baseline = selectedID, catalog.nodes.count >= 2 else { return }
        let candidates = catalog.nodes.filter { n in
            guard let data = try? KeyStore.read(n.ref), let text = String(data:data,encoding:.utf8), let p = try? WGProfile.parse(text) else {return false}
            let routes = Set(p.list(p.peer["allowedips"]))
            return routes.contains("0.0.0.0/0") && routes.contains("::/0")
        }
        guard candidates.count >= 2, candidates.contains(where: {$0.id == baseline}) else { message = "Cần ít nhất 2 profile full tunnel IPv4 + IPv6, gồm node đang chọn."; return }
        busy = true; testing = true; stopRequested = false; clearResults()
        let originalMTU = mtu
        var sampleMap: [UUID:[Double?]] = [:]
        var complete = true
        for pass in 0..<2 {
            let order = pass == 0 ? candidates : Array(candidates.reversed())
            for n in order {
                if stopRequested { complete = false; break }
                var samples: [Double?] = []
                do {
                    message = "So sánh \(n.name) — vòng \(pass+1)/2"
                    try await configure(m, ref: n.ref, mtu: n.id == baseline ? originalMTU : n.mtu)
                    if !stopRequested {
                        try m.connection.startVPNTunnel()
                        if await waitStatus(m, connected: true, timeout: 15) {
                            for _ in 0..<4 {
                                if stopRequested || m.connection.status != .connected {break}
                                let before = await HealthClient.read(m.connection)
                                if stopRequested {break}
                                let value = await RouteProbe.measure()
                                let after = await HealthClient.read(m.connection)
                                if let before = before, let after = after, after.recent(now: Date().timeIntervalSince1970), after.exchanged(since: before), m.connection.status == .connected { samples.append(value) }
                                else { samples.append(nil) }
                            }
                        }
                    }
                } catch { message = "Node không vượt qua bước kết nối; ghi mẫu lỗi." }
                samples += Array(repeating: nil, count: 4 - samples.count)
                sampleMap[n.id, default: []].append(contentsOf: samples)
                nodeTrials = candidates.compactMap { c in sampleMap[c.id].map { NodeTrial(id:c.id,samples:$0) } }
                m.connection.stopVPNTunnel()
                if !(await waitStatus(m, connected:false,timeout:15)) {complete = false; break}
            }
            if !complete || stopRequested {break}
        }
        m.connection.stopVPNTunnel()
        var restored = false
        if await waitStatus(m, connected:false,timeout:15) {
            do { try await configure(m, ref:original,mtu:originalMTU); restored = true } catch {}
        }
        needsRefresh = !restored; ready = restored; mtu = originalMTU
        if complete && !stopRequested && restored { suggestedNode = NodeRanker.recommend(nodeTrials, baseline:baseline, expected:Set(candidates.map(\.id))) }
        message = !restored ? "Không khôi phục được profile. Kiểm tra VPN iOS, đọc lại trạng thái." : (stopRequested ? "Đã dừng và khôi phục node cũ." : "Đã so sánh và khôi phục node cũ. Kết quả HTTPS chỉ là gợi ý; thử trong game trước khi chọn.")
        testing = false; busy = false; sync()
    }

}

struct MainView: View {
    @StateObject private var booster = Booster()
    @State private var importing = false
    @State private var vpnUsername = ""
    @State private var vpnPassword = ""
    @State private var confirmTest = false
    @State private var confirmNodes = false
    @State private var selectiveInput = ""
    @State private var confirmSelective = false
    @Environment(\.openURL) private var openURL
    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 22) {
                    Text("RYU BOOST").font(.largeTitle.bold())
                    Text(booster.state).font(.headline)
                    Text(booster.selectedKind.rawValue.uppercased()).font(.caption)
                    Text(booster.healthText).font(.caption)
                    if let h = booster.health {
                        Text("RX: \(h.rx) B  •  TX: \(h.tx) B").font(.caption).monospacedDigit()
                    }
                    Button("Đọc lại trạng thái VPN") { Task { await booster.refresh(); await booster.pollHealth() } }.disabled(booster.busy)
                    Button { Task { await booster.toggle() } } label: {
                        Text(booster.active ? "DỪNG" : "BOOST").font(.title.bold()).frame(maxWidth: .infinity).padding(28)
                    }.buttonStyle(.borderedProminent).disabled((!booster.ready && !booster.active) || booster.busy)
                    Button("Thêm profile VPN (.conf / .ovpn)") { importing = true }.disabled(booster.active || booster.busy || booster.catalog.nodes.count >= NodeCatalog.limit)
                    ForEach(booster.catalog.nodes) { n in
                        HStack {
                            Button(n.name + " • " + n.protocolKind.rawValue + (n.selectiveCount == nil ? "" : " • Selective") + (n.id == booster.selectedID ? " • Đang chọn" : "")) { Task { await booster.selectNode(n.id) } }
                                .disabled(booster.active || booster.busy || n.id == booster.selectedID)
                            Spacer()
                            if n.id != booster.selectedID { Button("Xóa", role:.destructive) { booster.removeNode(n.id) }.disabled(booster.active || booster.busy) }
                        }
                    }
                    DisclosureGroup("GAME ROUTES — thử nghiệm") {
                        Text("Nhập IP/CIDR game đã xác minh. Tạo bản sao profile, chỉ đưa các đích này và DNS cần thiết qua VPN. Các đích khác có thể đi trực tiếp. Không dùng cho game yêu cầu IP nước ngoài nếu chưa xác minh mọi tuyến.").font(.footnote)
                        TextEditor(text: $selectiveInput).frame(minHeight: 90).font(.system(.body, design: .monospaced)).autocorrectionDisabled()
                            .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.secondary.opacity(0.4)))
                        Button("TẠO PROFILE GAME") { confirmSelective = true }.buttonStyle(.bordered)
                            .disabled(!booster.supportsWGTests || !booster.ready || booster.active || booster.busy || booster.catalog.nodes.count >= NodeCatalog.limit || selectiveInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                        Text("Không tự nhận diện app; không phải QoS. Benchmark HTTPS không áp dụng cho profile chọn lọc.").font(.caption).foregroundStyle(.secondary)
                    }
                    Button("SO SÁNH NODE") { confirmNodes = true }.buttonStyle(.bordered)
                        .disabled(!booster.supportsWGTests || !booster.ready || booster.active || booster.busy || booster.catalog.nodes.count < 2)
                    if !booster.nodeTrials.isEmpty {
                        Text(booster.nodeReport).font(.footnote).monospacedDigit()
                        ShareLink(item: booster.nodeReport) { Text("Chia sẻ báo cáo node") }
                        if let id = booster.suggestedNode { Button("Chọn node đề xuất") { Task { await booster.selectNode(id) } }.disabled(booster.active || booster.busy) }
                    }
                    Picker("MTU", selection: $booster.mtu) { Text("Gốc").tag(0); Text("1420").tag(1420); Text("1380").tag(1380); Text("1280").tag(1280) }.pickerStyle(.segmented).disabled(!booster.supportsWGTests || booster.active || booster.busy)
                    Text("Chỉ đổi MTU trước trận. Không tự đổi node, không cam kết giảm ping.").font(.footnote).foregroundStyle(.secondary)
                    Text(booster.message).font(.callout)
                    Button("TỰ THỬ MTU") { confirmTest = true }
                        .buttonStyle(.bordered).disabled(!booster.supportsWGTests || !booster.ready || booster.active || booster.busy)
                    if booster.testing { Button("Dừng thử nghiệm") { booster.requestStopTest() } }
                    if !booster.scores.isEmpty {
                        Text(booster.report).font(.footnote).monospacedDigit()
                        ShareLink(item: booster.report) { Text("Chia sẻ kết quả (không có khóa VPN)") }
                        if let mtu = booster.suggestedMTU {
                            Button("Áp dụng MTU \(mtu)") { booster.mtu = mtu }.disabled(booster.busy || booster.active)
                        }
                    }
                    Divider()
                    Link("Nguồn WireGuard miễn phí Việt Nam", destination: URL(string: "https://www.vpnjantit.com/free-wireguard-vietnam")!)
                    Link("Tuyến thay thế: Cloudflare WARP", destination: URL(string: "https://apps.apple.com/vn/app/id1423538627")!)
                    Text("Không gửi khóa hoặc profile ra ngoài. Chỉ nhập cấu hình được cấp cho bạn. Không cần USB khi tunnel đã hoạt động.").font(.footnote).foregroundStyle(.secondary)
                }.padding(24)
            }
        }.confirmationDialog("Chỉ thử trước trận; tắt VPN khác. App sẽ kết nối/ngắt nhiều lần và gửi 24 yêu cầu HTTPS tới Google.", isPresented: $confirmTest, titleVisibility: .visible) {
            Button("Bắt đầu thử MTU") { Task { await booster.testMTU() } }
            Button("Hủy", role: .cancel) { }
        }.confirmationDialog("Chỉ thử trước trận, tắt VPN khác. So sánh tối đa 6 profile đủ điều kiện, 8 yêu cầu HTTPS mỗi node, tự ngắt và khôi phục node cũ.", isPresented:$confirmNodes,titleVisibility:.visible) {
            Button("Bắt đầu so sánh") { Task { await booster.compareNodes() } }
            Button("Hủy",role:.cancel) {}
        }.confirmationDialog("Tạo bản sao tuyến chọn lọc? Lưu lượng ngoài danh sách có thể đi trực tiếp; DNS của VPN vẫn có thể áp dụng toàn hệ thống. Chỉ dùng IP đã xác minh.", isPresented: $confirmSelective, titleVisibility: .visible) {
            Button("Tạo bản sao") { booster.createSelective(selectiveInput) }
            Button("Hủy", role: .cancel) {}
        }.task {
            await booster.refresh()
            while !Task.isCancelled {
                await booster.pollHealth()
                do { try await Task.sleep(nanoseconds: 5_000_000_000) } catch { break }
            }
        }
        .onReceive(NotificationCenter.default.publisher(for: .NEVPNStatusDidChange)) { _ in booster.sync() }
        .sheet(isPresented: $booster.needsCredentials, onDismiss: {
            vpnUsername = ""; vpnPassword = ""; booster.cancelCredentials()
        }) {
            NavigationStack {
                Form {
                    Text("Nhập tài khoản VPN được nhà cung cấp cấp cho bạn. Lưu trong Keychain, không gửi vào báo cáo.")
                    TextField("VPN username", text: $vpnUsername).textInputAutocapitalization(.never).autocorrectionDisabled()
                    SecureField("VPN password", text: $vpnPassword)
                    Button("Lưu profile") {
                        let auth = VPNCredentials(username: vpnUsername, password: vpnPassword)
                        vpnUsername = ""; vpnPassword = ""
                        Task { await booster.submitCredentials(auth) }
                    }.disabled(vpnUsername.isEmpty || vpnPassword.isEmpty || booster.busy)
                    Button("Hủy", role: .cancel) { booster.cancelCredentials() }.disabled(booster.busy)
                }.navigationTitle("Xác thực OpenVPN")
            }.interactiveDismissDisabled(booster.busy)
        }
        .fileImporter(isPresented: $importing, allowedContentTypes: [.data], allowsMultipleSelection: false) { result in
            if case .success(let urls) = result, let url = urls.first { Task { await booster.importProfile(url) } }
        }
    }
}
