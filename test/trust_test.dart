import 'package:omemo_dart/omemo_dart.dart';
import 'package:test/test.dart';

void main() {
  test('Test the Blind Trust Before Verification TrustManager', () async {
    // Caroline's BTBV manager
    final btbv = MemoryBTBVTrustManager();
    // Example data
    const aliceJid = 'alice@some.server';
    const bobJid = 'bob@other.server';
    
    // Caroline starts a chat a device from Alice
    await btbv.onNewSession(aliceJid, 1);
    expect(await btbv.isTrusted(aliceJid, 1), true);

    // Caroline meets with Alice and verifies her fingerprint
    await btbv.setDeviceTrust(aliceJid, 1, BTBVTrustState.verified);
    expect(await btbv.isTrusted(aliceJid, 1), true);

    // Alice adds a new device
    await btbv.onNewSession(aliceJid, 2);
    expect(await btbv.isTrusted(aliceJid, 2), false);
    expect(btbv.getDeviceTrust(aliceJid, 2), BTBVTrustState.notTrusted);

    // Caronline starts a chat with Bob but since they live far apart, Caroline cannot
    // verify his fingerprint.
    await btbv.onNewSession(bobJid, 3);

    // Bob adds a new device
    await btbv.onNewSession(bobJid, 4);
    expect(await btbv.isTrusted(bobJid, 3), true);
    expect(await btbv.isTrusted(bobJid, 4), true);
    expect(btbv.getDeviceTrust(bobJid, 3), BTBVTrustState.blindTrust);
    expect(btbv.getDeviceTrust(bobJid, 4), BTBVTrustState.blindTrust);
  });
}
