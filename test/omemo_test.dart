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
      newSessions: [
        await bobSession.device.toBundle(),
      ],
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

    // Bob responds to Alice
    const bobResponseText = 'Oh, hello Alice!';
    final bobResponseMessage = await bobSession.encryptToJid(
      aliceJid,
      bobResponseText,
    );

    // Bob sends the message to Alice
    // ...

    // Alice decrypts it
    final aliceReceivedMessage = await aliceSession.decryptMessage(
      bobResponseMessage.ciphertext,
      bobJid,
      bobSession.device.id,
      bobResponseMessage.encryptedKeys,
    );
    expect(bobResponseText, aliceReceivedMessage);
  });

  test('Test using OMEMO sessions with only two devices for the receiver', () async {
    const aliceJid = 'alice@server.example';
    const bobJid = 'bob@other.server.example';
      
    // Alice and Bob generate their sessions
    final aliceSession = await OmemoSessionManager.generateNewIdentity(opkAmount: 1);
    final bobSession = await OmemoSessionManager.generateNewIdentity(opkAmount: 1);
    // Bob's other device
    final bobSession2 = await OmemoSessionManager.generateNewIdentity(opkAmount: 1);

    // Alice encrypts a message for Bob
    const messagePlaintext = 'Hello Bob!';
    final aliceMessage = await aliceSession.encryptToJid(
      bobJid,
      messagePlaintext,
      newSessions: [
        await bobSession.device.toBundle(),
        await bobSession2.device.toBundle(),
      ],
    );
    expect(aliceMessage.encryptedKeys.length, 2);
    expect(aliceMessage.encryptedKeys[0].kex, true);
    expect(aliceMessage.encryptedKeys[1].kex, true);

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

    // Bob responds to Alice
    const bobResponseText = 'Oh, hello Alice!';
    final bobResponseMessage = await bobSession.encryptToJid(
      aliceJid,
      bobResponseText,
    );

    // Bob sends the message to Alice
    // ...

    // Alice decrypts it
    final aliceReceivedMessage = await aliceSession.decryptMessage(
      bobResponseMessage.ciphertext,
      bobJid,
      bobSession.device.id,
      bobResponseMessage.encryptedKeys,
    );
    expect(bobResponseText, aliceReceivedMessage);
  });
}
