import 'dart:convert';
import 'package:omemo_dart/omemo_dart.dart';
import 'package:test/test.dart';

void main() {
  test('Test using OMEMO sessions with only one device per user', () async {
    const aliceJid = 'alice@server.example';
    const bobJid = 'bob@other.server.example';
      
    // Alice and Bob generate their sessions
    final aliceSession = await OmemoSessionManager.generateNewIdentity(opkAmount: 1);
    final bobSession = await OmemoSessionManager.generateNewIdentity(opkAmount: 1);

    // Perform the X3DH
    final x3dhAliceResult = await x3dhFromBundle(
      await bobSession.device.toBundle(),
      aliceSession.device.ik,
    );
    final x3dhBobResult = await x3dhFromInitialMessage(
      X3DHMessage(
        aliceSession.device.ik.pk,
        x3dhAliceResult.ek.pk,
        '2',
      ),
      bobSession.device.spk,
      bobSession.device.opks.values.elementAt(0),
      bobSession.device.ik,
    );

    // Build the ratchets
    final aliceRatchet = await OmemoDoubleRatchet.initiateNewSession(
      bobSession.device.spk.pk,
      x3dhAliceResult.sk,
      x3dhAliceResult.ad,
    );
    final bobRatchet = await OmemoDoubleRatchet.acceptNewSession(
      bobSession.device.spk,
      x3dhBobResult.sk,
      x3dhBobResult.ad,
    );

    // Add the ratchets to the session managers
    await aliceSession.addSession(bobJid, bobSession.device.id, aliceRatchet);
    await bobSession.addSession(aliceJid, aliceSession.device.id, bobRatchet);

    // Alice encrypts a message for Bob
    const messagePlaintext = 'Hello Bob!';
    final aliceMessage = await aliceSession.encryptToJid(bobJid, messagePlaintext);
    expect(aliceMessage.encryptedKeys.length, 1);

    // Alice sends the message to Bob
    // ...

    // Bob decrypts it
    final bobMessage = await bobSession.decryptMessage(
      aliceMessage.ciphertext,
      aliceJid,
      aliceSession.device.id,
      [
        EncryptedKey(
          bobSession.device.id,
          base64.encode(aliceMessage.encryptedKeys[bobSession.device.id]!),
        ),
      ],
    );

    expect(messagePlaintext, bobMessage);
  });
}
