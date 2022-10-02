import 'dart:convert';
import 'package:omemo_dart/omemo_dart.dart';
import 'package:omemo_dart/src/trust/always.dart';
import 'package:test/test.dart';

Map<String, dynamic> jsonify(Map<String, dynamic> map) {
  return jsonDecode(jsonEncode(map)) as Map<String, dynamic>;
}

void main() {
  test('Test serialising and deserialising the Device', () async {
    // Generate a random session
    final oldSession = await OmemoSessionManager.generateNewIdentity(
      'user@test.server',
      AlwaysTrustingTrustManager(),
      opkAmount: 1,
    );
    final oldDevice = await oldSession.getDevice();
    final serialised = jsonify(await oldDevice.toJson());

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
    final serialised = jsonify(await oldDevice.toJson());

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
    final aliceSerialised = jsonify(await aliceOld.toJson());
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
      0,
    );

    // Serialise and deserialise
    final serialised = jsonify(await oldSession.toJsonWithoutSessions());
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

    final serialized = jsonify(await btbv.toJson());
    final deviceList = BlindTrustBeforeVerificationTrustManager.deviceListFromJson(
      serialized,
    );
    expect(btbv.devices, deviceList);

    final trustCache = BlindTrustBeforeVerificationTrustManager.trustCacheFromJson(
      serialized,
    );
    expect(btbv.trustCache, trustCache);

    final enableCache = BlindTrustBeforeVerificationTrustManager.enableCacheFromJson(
      serialized,
    );
    expect(btbv.enablementCache, enableCache);
  });
}
