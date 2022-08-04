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
    final x3dhAliceResult = await aliceSession.addSessionFromBundle(
      bobJid,
      bobSession.device.id,
      await bobSession.device.toBundle(),
    );
    await bobSession.addSessionFromKeyExchange(
      aliceJid,
      aliceSession.device.id,
      X3DHMessage(
        aliceSession.device.ik.pk,
        x3dhAliceResult.ek.pk,
        '2',
      ),
    );

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
