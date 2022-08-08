import 'package:omemo_dart/omemo_dart.dart';
import 'package:test/test.dart';

void main() {
  test('Test serialising and deserialising the Device', () async {
    // Generate a random session
    final oldSession = await OmemoSessionManager.generateNewIdentity('user@test.server', opkAmount: 1);
    final oldDevice = await oldSession.getDevice();
    final serialised = await oldDevice.toJson();

    final newDevice = Device.fromJson(serialised);
    expect(await oldDevice.equals(newDevice), true);
  });

  test('Test serialising and deserialising the OmemoDoubleRatchet', () async {
    // Generate a random ratchet
    const aliceJid = 'alice@server.example';
    const bobJid = 'bob@other.server.example';
    final aliceSession = await OmemoSessionManager.generateNewIdentity(aliceJid, opkAmount: 1);
    final bobSession = await OmemoSessionManager.generateNewIdentity(bobJid, opkAmount: 1);
    final aliceMessage = await aliceSession.encryptToJid(
      bobJid,
      'Hello Bob!',
      newSessions: [
        await (await bobSession.getDevice()).toBundle(),
      ],
    );
    await bobSession.decryptMessage(
      aliceMessage.ciphertext,
      aliceJid,
      (await aliceSession.getDevice()).id,
      aliceMessage.encryptedKeys,
    );
    final aliceOld = aliceSession.getRatchet(bobJid, (await bobSession.getDevice()).id);
    final aliceSerialised = await aliceOld.toJson();
    final aliceNew = OmemoDoubleRatchet.fromJson(aliceSerialised);

    expect(await aliceOld.equals(aliceNew), true);
  });

  test('Test serialising and deserialising the OmemoSessionManager', () async {
    // Generate a random session
    final oldSession = await OmemoSessionManager.generateNewIdentity('a@server', opkAmount: 4);
    final bobSession = await OmemoSessionManager.generateNewIdentity('b@other.server', opkAmount: 4);
    await oldSession.addSessionFromBundle(
      'bob@localhost',
      (await bobSession.getDevice()).id,
      await (await bobSession.getDevice()).toBundle(),
    );

    // Serialise and deserialise
    final serialised = await oldSession.toJson();
    final newSession = OmemoSessionManager.fromJson(serialised);

    final oldDevice = await oldSession.getDevice();
    final newDevice = await newSession.getDevice();
    expect(await oldDevice.equals(newDevice), true);
    expect(oldSession.getDeviceMap(), newSession.getDeviceMap());

    expect(oldSession.getRatchetMap().length, newSession.getRatchetMap().length);
    for (final session in oldSession.getRatchetMap().entries) {
      expect(newSession.getRatchetMap().containsKey(session.key), true);

      final oldRatchet = oldSession.getRatchetMap()[session.key]!;
      final newRatchet = newSession.getRatchetMap()[session.key]!;
      expect(await oldRatchet.equals(newRatchet), true);
    }
  });
}
