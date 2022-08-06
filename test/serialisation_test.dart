import 'package:omemo_dart/omemo_dart.dart';
import 'package:test/test.dart';

void main() {
  test('Test serialising and deserialising the Device', () async {
    // Generate a random session
    final oldSession = await OmemoSessionManager.generateNewIdentity(opkAmount: 1);
    final oldDevice = await oldSession.getDevice();
    final serialised = await oldDevice.toJson();

    final newDevice = Device.fromJson(serialised);
    expect(oldDevice.id, newDevice.id);
    expect(await oldDevice.ik.equals(newDevice.ik), true);
    expect(await oldDevice.spk.equals(newDevice.spk), true);
    expect(listsEqual(oldDevice.spkSignature, newDevice.spkSignature), true);
    expect(oldDevice.spkId, newDevice.spkId);

    // Check the Ontime-Prekeys
    expect(oldDevice.opks.length, newDevice.opks.length);
    for (final entry in oldDevice.opks.entries) {
      expect(await newDevice.opks[entry.key]!.equals(entry.value), true);
    }
  });

  test('Test serialising and deserialising the OmemoDoubleRatchet', () async {
    // Generate a random ratchet
    const aliceJid = 'alice@server.example';
    const bobJid = 'bob@other.server.example';
    final aliceSession = await OmemoSessionManager.generateNewIdentity(opkAmount: 1);
    final bobSession = await OmemoSessionManager.generateNewIdentity(opkAmount: 1);
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

    expect(await aliceOld.dhs.equals(aliceNew.dhs), true);
    if (aliceOld.dhr == null) {
      expect(aliceNew.dhr, null);
    } else {
      expect(await aliceOld.dhr!.equals(aliceNew.dhr!), true);
    }
    expect(listsEqual(aliceOld.rk, aliceNew.rk), true);
    if (aliceOld.cks == null) {
      expect(aliceNew.cks, null);
    } else {
      expect(listsEqual(aliceOld.cks!, aliceNew.cks!), true);
    }
    if (aliceOld.ckr == null) {
      expect(aliceNew.ckr, null);
    } else {
      expect(listsEqual(aliceOld.ckr!, aliceNew.ckr!), true);
    }
    expect(aliceOld.ns, aliceNew.ns);
    expect(aliceOld.nr, aliceNew.nr);
    expect(aliceOld.pn, aliceNew.pn);
    expect(listsEqual(aliceOld.sessionAd, aliceNew.sessionAd), true);
  });
}
