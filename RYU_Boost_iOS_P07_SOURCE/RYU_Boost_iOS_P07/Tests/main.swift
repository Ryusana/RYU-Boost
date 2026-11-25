import Foundation
let k = Data(repeating: 1, count: 32).base64EncodedString()
let good = """
[Interface]
PrivateKey = \(k)
Address = 10.1.2.3/32
DNS = 1.1.1.1
[Peer]
PublicKey = \(k)
AllowedIPs = 0.0.0.0/0
Endpoint = example.invalid:51820
"""
let p = try WGProfile.parse(good)
assert(p.peer["endpoint"] == "example.invalid:51820")
for bad in [good + "\nJc = 5", good + "\n[Peer]", good.replacingOccurrences(of: "PrivateKey", with: "PostUp"), good.replacingOccurrences(of: k, with: "bad"), good.replacingOccurrences(of: "DNS = 1.1.1.1", with: "MTU = 1000")] {
    do { _ = try WGProfile.parse(bad); fatalError("accepted invalid") } catch { }
}
print("6 parser cases PASS; no live network used")
let original = RouteScore(mtu: 0, samples: [100, 100, 100, 100, 100, 100])
let faster = RouteScore(mtu: 1380, samples: [70, 70, 70, 70, 70, 70])
let unreliable = RouteScore(mtu: 1280, samples: [10, 10, 10, 10, 10, nil])
let tiny = RouteScore(mtu: 1420, samples: [96, 96, 96, 96, 96, 96])
assert(RouteScore.recommendation([original, faster, unreliable, tiny]) == 1380)
assert(RouteScore.recommendation([original, unreliable, tiny]) == nil)
assert(RouteScore.recommendation([unreliable, faster]) == nil)
assert(RouteScore(mtu: 0, samples: []).failureRate == 1)
assert(RouteScore(mtu: 0, samples: [1, 3]).median == 2)
assert(RouteScore(mtu: 0, samples: [1, 2, 3, 4, 5, 6]).p95 == 5.75)
assert(!RouteScore(mtu: 0, samples: [1, 2, 3, 4, 5, .nan]).eligible)
print("7 scoring cases PASS; HTTPS timing simulation only")
let runtime = "private_key=secret\npublic_key=secret2\nrx_bytes=200\ntx_bytes=150\nlast_handshake_time_sec=1000\nerrno=0"
let h = TunnelHealth.parse(runtime)!
assert(h == TunnelHealth(rx: 200, tx: 150, handshake: 1000))
assert(h.recent(now: 1100))
assert(!h.recent(now: 1300))
assert(!h.recent(now: 900))
assert(!TunnelHealth(rx: 0, tx: 0, handshake: 0).recent(now: 1))
assert(h.exchanged(since: TunnelHealth(rx: 100, tx: 100, handshake: 1000)))
assert(!h.exchanged(since: h))
assert(!h.exchanged(since: TunnelHealth(rx: 300, tx: 100, handshake: 1000)))
assert(TunnelHealth.parse(runtime + "\nrx_bytes=3") == nil)
assert(TunnelHealth.parse(runtime.replacingOccurrences(of: "200", with: "-1")) == nil)
assert(TunnelHealth.parse("rx_bytes=1\ntx_bytes=1") == nil)
let encoded = String(data: try JSONEncoder().encode(h), encoding: .utf8)!
assert(!encoded.contains("secret") && !encoded.contains("key"))
print("12 health cases PASS; simulated runtime counters, no live network")
var catalog = NodeCatalog()
let a = try catalog.adopt(Data([1]), mtu: 0)
let b = try catalog.adopt(Data([2]), mtu: 1380)
let same = try catalog.adopt(Data([1]), mtu: 1280)
assert(a == same && catalog.nodes.count == 2)
catalog.setMTU(1420, for: a.ref)
assert(catalog.nodes.first?.mtu == 1420)
catalog.setMTU(900, for: a.ref)
assert(catalog.nodes.first?.mtu == 1420)
assert(catalog.remove(a.id, current:a.ref) == nil)
let roundtrip = try JSONDecoder().decode(NodeCatalog.self,from:JSONEncoder().encode(catalog))
assert(roundtrip.nodes == catalog.nodes)
for i in 3...6 { _ = try catalog.adopt(Data([UInt8(i)]), mtu: 0) }
assert(catalog.nodes.count == 6)
do { _ = try catalog.adopt(Data([7]), mtu: 0); fatalError("over capacity") } catch {}
assert(catalog.remove(b.id, current:a.ref) == b)
let replacement = try catalog.adopt(Data([7]), mtu:0)
assert(replacement.name == b.name && replacement.id != b.id)
print("9 catalog cases PASS; simulated keychain refs only")
let expected:Set<UUID> = [a.id,b.id]
let slowNode = NodeTrial(id:a.id,samples:Array(repeating:100.0,count:8))
let fastNode = NodeTrial(id:b.id,samples:Array(repeating:60.0,count:8))
let failNode = NodeTrial(id:b.id,samples:[1,1,1,1,1,1,1,nil])
let partialNode = NodeTrial(id:b.id,samples:Array(repeating:5.0,count:4))
let tinyNode = NodeTrial(id:b.id,samples:Array(repeating:95.0,count:8))
assert(NodeRanker.recommend([slowNode,fastNode],baseline:a.id,expected:expected) == b.id)
assert(NodeRanker.recommend([slowNode,failNode],baseline:a.id,expected:expected) == nil)
assert(NodeRanker.recommend([slowNode,partialNode],baseline:a.id,expected:expected) == nil)
assert(NodeRanker.recommend([slowNode,tinyNode],baseline:a.id,expected:expected) == nil)
assert(NodeRanker.recommend([slowNode],baseline:a.id,expected:expected) == nil)
assert(NodeRanker.recommend([slowNode,fastNode,fastNode],baseline:a.id,expected:expected) == nil)
assert(NodeRanker.recommend([slowNode,fastNode],baseline:b.id,expected:expected) == nil)
assert(NodeRanker.recommend([NodeTrial(id:a.id,samples:[1,1,1,1,1,1,1,nil]),fastNode],baseline:a.id,expected:expected) == nil)
assert(NodeRanker.recommend([slowNode,NodeTrial(id:b.id,samples:[1,1,1,1,1,1,1,.infinity])],baseline:a.id,expected:expected) == nil)
print("9 node ranking cases PASS; simulated HTTPS, not game latency")
// P0.4: synthetic addresses only, no provider connection.
let v4 = try RoutePrefix("192.0.2.129/24")
assert(v4.canonical == "192.0.2.0/24")
let inside = try RoutePrefix("192.0.2.4")
let outside = try RoutePrefix("192.0.3.4")
assert(v4.contains(inside))
assert(!v4.contains(outside))
let v6 = try RoutePrefix("2001:db8::/48")
let v6host = try RoutePrefix("2001:db8:0:1::7")
assert(v6.contains(v6host) && !v6.contains(inside))
let split = try SelectiveRoutes.plan(p, input: "192.0.2.7, 192.0.2.7\n198.51.100.0/24")
assert(split.gameCount == 2 && split.routes.count == 3)
let derived = try WGProfile.parse(String(data: try split.derivedProfile(p), encoding: .utf8)!)
assert(derived.interface == p.interface && derived.peer["endpoint"] == p.peer["endpoint"] && derived.peer["publickey"] == p.peer["publickey"])
assert(derived.peer["allowedips"] == "192.0.2.7/32, 198.51.100.0/24, 1.1.1.1/32")
assert(p.peer["allowedips"] == "0.0.0.0/0")
for input in ["", "0.0.0.0/0", "192.0.2.0/23", "bad.example", "2001:db8::1", "192.0.2.9/33", "192.0.2.9/-1"] {
    do { _ = try SelectiveRoutes.plan(p, input: input); fatalError("accepted bad route") } catch {}
}
var restricted = p; restricted.peer["allowedips"] = "192.0.2.0/24"
do { _ = try SelectiveRoutes.plan(restricted, input: "198.51.100.5"); fatalError("expanded routes") } catch {}
do { _ = try SelectiveRoutes.plan(restricted, input: "192.0.2.5"); fatalError("DNS unreachable") } catch {}
var dual = p; dual.interface["address"] = "10.1.2.3/32, fd00::2/128"; dual.peer["allowedips"] = "0.0.0.0/0, ::/0"
let both = try SelectiveRoutes.plan(dual, input: "2001:db8::7, 192.0.2.5")
assert(both.routes.count == 3 && both.routes[0].canonical == "2001:db8::7/128")
var next = NodeCatalog(); let sn = try next.adopt(Data([11]), mtu: 1380, selectiveCount: 2)
let restored = try JSONDecoder().decode(NodeCatalog.self, from: JSONEncoder().encode(next))
assert(restored.nodes.first == sn && sn.selectiveCount == 2)
let oldJSON = try JSONEncoder().encode(a)
let oldRoundtrip = try JSONDecoder().decode(NodeRecord.self, from: oldJSON)
assert(oldRoundtrip.selectiveCount == nil)
print("20 selective route cases PASS; simulated addresses, no iOS route verification")
// P0.5: fake PEM placeholders for structural tests only; never connect.
let ovpn = """
client
dev tun
proto udp
remote example.invalid 1194
remote-cert-tls server
<ca>
FAKE CA
</ca>
<cert>
FAKE CERT
</cert>
<key>
FAKE KEY
</key>
"""
let ovParsed = try OVPNProfile.parse(ovpn); assert(ovParsed.text == ovpn)
let ovKind = try ProfileKind.inspect(ovpn); assert(ovKind == .openvpn)
for extra in ["up /tmp/script", "auth-user-pass credentials.txt", "compress lz4", "ca external.pem", "remote other.invalid 443", "proto tcp", "<connection>\nremote evil.invalid 1\n</connection>", "verify-x509-name \"quoted\" name", "tun-mtu 900", "script-security 2", "plugin test.so", "tls-crypt /tmp/key"] {
    do { _ = try OVPNProfile.parse(ovpn + "\n" + extra); fatalError("unsupported directive accepted") } catch {}
}
for bad in [ovpn.replacingOccurrences(of: "remote-cert-tls server", with: ""), ovpn.replacingOccurrences(of: "1194", with: "0"), ovpn.replacingOccurrences(of: "</key>", with: ""), ovpn.replacingOccurrences(of: "FAKE CA", with: ""), ovpn.replacingOccurrences(of: "proto udp", with: "proto tcp"), ovpn.replacingOccurrences(of: "dev tun", with: "dev tap")] {
    do { _ = try OVPNProfile.parse(bad); fatalError("bad profile accepted") } catch {}
}
var multi = NodeCatalog()
let ovnode = try multi.adopt(Data([42]), mtu: 0, kind: .openvpn)
assert(ovnode.protocolKind == .openvpn)
multi.setMTU(1420, for: ovnode.ref)
assert(multi.nodes.first?.mtu == 0)
let multiRestored = try JSONDecoder().decode(NodeCatalog.self, from: JSONEncoder().encode(multi))
assert(multiRestored.nodes.first?.protocolKind == .openvpn)
assert(oldRoundtrip.protocolKind == .wireguard)
print("24 OpenVPN profile/catalog cases PASS; no actual certificates or adapter execution")
// P0.6: account-based auth and old Keychain payload compatibility, synthetic only.
let accountOV = ovpn.components(separatedBy: "<cert>")[0] + "\nauth-user-pass\n"
let authParsed = try OVPNProfile.parse(accountOV)
assert(authParsed.requiresCredentials && !authParsed.hasClientCertificate)
let bothAuth = try OVPNProfile.parse(ovpn + "\nauth-user-pass")
assert(bothAuth.requiresCredentials && bothAuth.hasClientCertificate)
let auth = VPNCredentials(username: "fixture-user", password: "fixture-pass")
let saved = StoredProfile(text: accountOV, credentials: auth)
let serialized = try saved.encodeForKeychain()
let loaded = try StoredProfile.decode(serialized)
assert(loaded.text == accountOV && loaded.credentials == auth)
let loadedKind = try loaded.kind(); assert(loadedKind == .openvpn)
let oldOV = try StoredProfile.decode(Data(ovpn.utf8)); assert(oldOV.credentials == nil && oldOV.text == ovpn)
let oldEncoded = try oldOV.encodeForKeychain(); assert(oldEncoded == Data(ovpn.utf8))
for invalid in [VPNCredentials(username:"", password:"x"), VPNCredentials(username:"x", password:""), VPNCredentials(username:"x\ny", password:"x"), VPNCredentials(username:"x", password:String(repeating:"x",count:1025))] {
    do { try invalid.validate(); fatalError("bad credential") } catch {}
}
for bad in [StoredProfile(text: accountOV, credentials:nil), StoredProfile(text:ovpn, credentials:auth)] {
    do { _ = try bad.encodeForKeychain(); fatalError("auth mismatch") } catch {}
}
for bad in [accountOV.replacingOccurrences(of:"auth-user-pass",with:""), accountOV + "\nauth-user-pass", accountOV + "\n<key>\nFAKE\n</key>", accountOV.replacingOccurrences(of:"auth-user-pass",with:"auth-user-pass secret.txt")] {
    do { _ = try OVPNProfile.parse(bad); fatalError("unsupported auth config") } catch {}
}
for bad in [Data("RYU-PROFILE-V1\n{}".utf8), Data(repeating:0,count:150001), Data(accountOV.utf8)] {
    do { _ = try StoredProfile.decode(bad); fatalError("bad keychain blob") } catch {}
}
print("19 auth/storage cases PASS; synthetic data only")
// Lifecycle effects, no adapter or SDK execution.
func lifecycleCase(_ sequence: [(OpenVPNLifecycle.Event,[OpenVPNLifecycle.Effect])], phase: OpenVPNLifecycle.Phase) {
    var lc = OpenVPNLifecycle()
    for (event, effects) in sequence { assert(lc.receive(event) == effects) }
    assert(lc.phase == phase)
}
lifecycleCase([(.start,[]),(.connected,[.startOK]),(.connected,[]),(.startTimeout,[]),(.stop,[.disconnect]),(.disconnected,[.finishStops]),(.stopTimeout,[])], phase:.closed)
lifecycleCase([(.start,[]),(.stop,[.startFailed,.disconnect]),(.connected,[]),(.disconnected,[.finishStops])],phase:.closed)
lifecycleCase([(.start,[]),(.startTimeout,[.startFailed,.disconnect]),(.failure,[]),(.stop,[]),(.stopTimeout,[.finishStops]),(.disconnected,[])],phase:.closed)
lifecycleCase([(.start,[]),(.connected,[.startOK]),(.failure,[.disconnect,.cancelTunnel]),(.stop,[]),(.disconnected,[.finishStops])],phase:.closed)
lifecycleCase([(.start,[]),(.connected,[.startOK]),(.reconnecting,[.disconnect,.cancelTunnel]),(.reconnecting,[]),(.stop,[]),(.stopTimeout,[.finishStops])],phase:.closed)
lifecycleCase([(.start,[]),(.disconnected,[.startFailed]),(.stop,[.finishStops])],phase:.closed)
lifecycleCase([(.start,[]),(.connected,[.startOK]),(.disconnected,[.cancelTunnel]),(.stop,[.finishStops])],phase:.closed)
lifecycleCase([(.stop,[.finishStops]),(.connected,[])],phase:.closed)
lifecycleCase([(.start,[]),(.connected,[.startOK]),(.stop,[.disconnect]),(.stop,[]),(.stopTimeout,[.finishStops]),(.stop,[.finishStops])],phase:.closed)
lifecycleCase([(.start,[]),(.failure,[.startFailed,.disconnect]),(.disconnected,[]),(.stop,[.finishStops])],phase:.closed)
print("10 lifecycle sequences PASS; pure reducer, not SDK callbacks")
