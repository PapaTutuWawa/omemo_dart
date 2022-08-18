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
    final serialised = await oldSession.toJson();
    final newSession = OmemoSessionManager.fromJson(
      serialised,
      AlwaysTrustingTrustManager(),
    );

    final oldDevice = await oldSession.getDevice();
    final newDevice = await newSession.getDevice();
    expect(await oldDevice.equals(newDevice), true);
    expect(await oldSession.getDeviceMap(), await newSession.getDeviceMap());

    expect(oldSession.getRatchetMap().length, newSession.getRatchetMap().length);
    for (final session in oldSession.getRatchetMap().entries) {
      expect(newSession.getRatchetMap().containsKey(session.key), true);

      final oldRatchet = oldSession.getRatchetMap()[session.key]!;
      final newRatchet = newSession.getRatchetMap()[session.key]!;
      expect(await oldRatchet.equals(newRatchet), true);
    }
  });
}
