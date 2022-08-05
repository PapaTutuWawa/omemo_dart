import 'package:omemo_dart/omemo_dart.dart';
import 'package:test/test.dart';

void main() {
  test('Test using OMEMO sessions with only one device per user', () async {
    const aliceJid = 'alice@server.example';
    const bobJid = 'bob@other.server.example';
      
    // Alice and Bob generate their sessions
    final aliceSession = await OmemoSessionManager.generateNewIdentity(opkAmount: 1);
    final bobSession = await OmemoSessionManager.generateNewIdentity(opkAmount: 1);

    // Alice encrypts a message for Bob
    const messagePlaintext = 'Hello Bob!';
    final aliceMessage = await aliceSession.encryptToJid(
      bobJid,
      messagePlaintext,
      newSession: await bobSession.device.toBundle(),
    );
    expect(aliceMessage.encryptedKeys.length, 1);

    // Alice sends the message to Bob
    // ...

    // Bob decrypts it
    final bobMessage = await bobSession.decryptMessage(
      aliceMessage.ciphertext,
      aliceJid,
      aliceSession.device.id,
      aliceMessage.encryptedKeys,
    );

    expect(messagePlaintext, bobMessage);
  });
}
