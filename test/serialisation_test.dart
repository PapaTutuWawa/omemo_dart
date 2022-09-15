import 'dart:convert';
import 'package:omemo_dart/omemo_dart.dart';
import 'package:omemo_dart/src/trust/always.dart';
import 'package:test/test.dart';

void main() {
  test('Test serialising and deserialising the Device', () async {
    // Generate a random session
    final oldSession = await OmemoSessionManager.generateNewIdentity(
      'user@test.server',
      AlwaysTrustingTrustManager(),
      opkAmount: 1,
    );
    final oldDevice = await oldSession.getDevice();
    final serialised = await oldDevice.toJson();

    final newDevice = Device.fromJson(serialised);
    expect(await oldDevice.equals(newDevice), true);
  });

  test('Test serialising and deserialising the Device after rotating the SPK', () async {
    // Generate a random session
    final oldSession = await OmemoSessionManager.generateNewIdentity(
      'user@test.server',
      AlwaysTrustingTrustManager(),
      opkAmount: 1,
    );
    final oldDevice = await (await oldSession.getDevice()).replaceSignedPrekey();
    final serialised = await oldDevice.toJson();

    final newDevice = Device.fromJson(serialised);
    expect(await oldDevice.equals(newDevice), true);
  });
  
  test('Test serialising and deserialising the OmemoDoubleRatchet', () async {
    // Generate a random ratchet
    const aliceJid = 'alice@server.example';
    const bobJid = 'bob@other.server.example';
    final aliceSession = await OmemoSessionManager.generateNewIdentity(
      aliceJid,
      AlwaysTrustingTrustManager(),
      opkAmount: 1,
    );
    final bobSession = await OmemoSessionManager.generateNewIdentity(
      bobJid,
      AlwaysTrustingTrustManager(),
      opkAmount: 1,
    );
    final aliceMessage = await aliceSession.encryptToJid(
      bobJid,
      'Hello Bob!',
      newSessions: [
        await bobSession.getDeviceBundle(),
      ],
    );
    await bobSession.decryptMessage(
      aliceMessage.ciphertext,
      aliceJid,
      await aliceSession.getDeviceId(),
      aliceMessage.encryptedKeys,
    );
    final aliceOld = aliceSession.getRatchet(bobJid, await bobSession.getDeviceId());
    final aliceSerialised = await aliceOld.toJson();
    final aliceNew = OmemoDoubleRatchet.fromJson(aliceSerialised);

    expect(await aliceOld.equals(aliceNew), true);
  });

  test('Test serialising and deserialising the OmemoSessionManager', () async {
    // Generate a random session
    final oldSession = await OmemoSessionManager.generateNewIdentity(
      'a@server',
      AlwaysTrustingTrustManager(),
      opkAmount: 4,
    );
    final bobSession = await OmemoSessionManager.generateNewIdentity(
      'b@other.server',
      AlwaysTrustingTrustManager(),
      opkAmount: 4,
    );
    await oldSession.addSessionFromBundle(
      'bob@localhost',
      await bobSession.getDeviceId(),
      await bobSession.getDeviceBundle(),
    );

    // Serialise and deserialise
    final serialised = await oldSession.toJsonWithoutSessions();
    final newSession = OmemoSessionManager.fromJsonWithoutSessions(
      serialised,
      // NOTE: At this point, we don't care about this attribute
      {},
      AlwaysTrustingTrustManager(),
    );

    final oldDevice = await oldSession.getDevice();
    final newDevice = await newSession.getDevice();
    expect(await oldDevice.equals(newDevice), true);
    expect(await oldSession.getDeviceMap(), await newSession.getDeviceMap());
  });

  test('Test serialising and deserialising the BlindTrustBeforeVerificationTrustManager', () async {
    // Caroline's BTBV manager
    final btbv = MemoryBTBVTrustManager();
    // Example data
    const aliceJid = 'alice@some.server';
    const bobJid = 'bob@other.server';
    
    // Caroline starts a chat a device from Alice
    await btbv.onNewSession(aliceJid, 1);
    expect(await btbv.isTrusted(aliceJid, 1), true);
    expect(await btbv.isEnabled(aliceJid, 1), true);

    // Caroline meets with Alice and verifies her fingerprint
    await btbv.setDeviceTrust(aliceJid, 1, BTBVTrustState.verified);
    expect(await btbv.isTrusted(aliceJid, 1), true);

    // Alice adds a new device
    await btbv.onNewSession(aliceJid, 2);
    expect(await btbv.isTrusted(aliceJid, 2), false);
    expect(btbv.getDeviceTrust(aliceJid, 2), BTBVTrustState.notTrusted);
    expect(await btbv.isEnabled(aliceJid, 2), false);

    // Caronline starts a chat with Bob but since they live far apart, Caroline cannot
    // verify his fingerprint.
    await btbv.onNewSession(bobJid, 3);

    // Bob adds a new device
    await btbv.onNewSession(bobJid, 4);
    expect(await btbv.isTrusted(bobJid, 3), true);
    expect(await btbv.isTrusted(bobJid, 4), true);
    expect(btbv.getDeviceTrust(bobJid, 3), BTBVTrustState.blindTrust);
    expect(btbv.getDeviceTrust(bobJid, 4), BTBVTrustState.blindTrust);
    expect(await btbv.isEnabled(bobJid, 3), true);
    expect(await btbv.isEnabled(bobJid, 4), true);
  });

  test('Test serializing and deserializing RatchetMapKey', () {
    const test1 = RatchetMapKey('user@example.org', 1234);
    final result1 = RatchetMapKey.fromJsonKey(test1.toJsonKey());
    expect(result1.jid, test1.jid);
    expect(result1.deviceId, test1.deviceId);

    const test2 = RatchetMapKey('user@example.org/hallo:welt', 3333);
    final result2 = RatchetMapKey.fromJsonKey(test2.toJsonKey());
    expect(result2.jid, test2.jid);
    expect(result2.deviceId, test2.deviceId);
  });

  test('Test serializing and deserializing the components of the BTBV manager', () async {
    // Caroline's BTBV manager
    final btbv = MemoryBTBVTrustManager();
    // Example data
    const aliceJid = 'alice@some.server';
    const bobJid = 'bob@other.server';
    
    await btbv.onNewSession(aliceJid, 1);
    await btbv.setDeviceTrust(aliceJid, 1, BTBVTrustState.verified);
    await btbv.onNewSession(aliceJid, 2);
    await btbv.onNewSession(bobJid, 3);
    await btbv.onNewSession(bobJid, 4);

    final managerJson = await btbv.toJson();
    final managerString = jsonEncode(managerJson);
    final managerPostJson = jsonDecode(managerString) as Map<String, dynamic>;
    final deviceList = BlindTrustBeforeVerificationTrustManager.deviceListFromJson(
      managerPostJson,
    );
    expect(btbv.devices, deviceList);

    final trustCache = BlindTrustBeforeVerificationTrustManager.trustCacheFromJson(
      managerPostJson,
    );
    expect(btbv.trustCache, trustCache);

    final enableCache = BlindTrustBeforeVerificationTrustManager.enableCacheFromJson(
      managerPostJson,
    );
    expect(btbv.enablementCache, enableCache);
  });
}
