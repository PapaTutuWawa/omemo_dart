import 'package:omemo_dart/omemo_dart.dart';
import 'package:omemo_dart/src/trust/always.dart';
import 'package:omemo_dart/src/trust/never.dart';
import 'package:test/test.dart';

void main() {
  /*
  test('Test using OMEMO sessions with only one device per user', () async {
    const aliceJid = 'alice@server.example';
    const bobJid = 'bob@other.server.example';
    // Alice and Bob generate their sessions
    var deviceModified = false;
    var ratchetModified = 0;
    var deviceMapModified = 0;
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
    final bobOpks = (await bobSession.getDevice()).opks.values.toList();
    bobSession.eventStream.listen((event) {
      if (event is DeviceModifiedEvent) {
        deviceModified = true;
      } else if (event is RatchetModifiedEvent) {
        ratchetModified++;
      } else if (event is DeviceMapModifiedEvent) {
        deviceMapModified++;
      }
    });

    // Alice encrypts a message for Bob
    const messagePlaintext = 'Hello Bob!';
    final aliceMessage = await aliceSession.encryptToJid(
      bobJid,
      messagePlaintext,
      newSessions: [
        await (await bobSession.getDevice()).toBundle(),
      ],
    );
    expect(aliceMessage.encryptedKeys.length, 1);

    // Alice sends the message to Bob
    // ...

    // Bob decrypts it
    final bobMessage = await bobSession.decryptMessage(
      aliceMessage.ciphertext,
      aliceJid,
      (await aliceSession.getDevice()).id,
      aliceMessage.encryptedKeys,
    );
    expect(messagePlaintext, bobMessage);
    // The ratchet should be modified two times: Once for when the ratchet is created and
    // other time for when the message is decrypted
    expect(ratchetModified, 2);
    // Bob's device map should be modified once
    expect(deviceMapModified, 1);
    // The event should be triggered
    expect(deviceModified, true);
    // Bob should have replaced his OPK
    expect(
      listsEqual(bobOpks, (await bobSession.getDevice()).opks.values.toList()),
      false,
    );

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
      (await bobSession.getDevice()).id,
      bobResponseMessage.encryptedKeys,
    );
    expect(bobResponseText, aliceReceivedMessage);
  });

  test('Test using OMEMO sessions with only two devices for the receiver', () async {
    const aliceJid = 'alice@server.example';
    const bobJid = 'bob@other.server.example';
      
    // Alice and Bob generate their sessions
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
    // Bob's other device
    final bobSession2 = await OmemoSessionManager.generateNewIdentity(
      bobJid,
      AlwaysTrustingTrustManager(),
      opkAmount: 1,
    );

    // Alice encrypts a message for Bob
    const messagePlaintext = 'Hello Bob!';
    final aliceMessage = await aliceSession.encryptToJid(
      bobJid,
      messagePlaintext,
      newSessions: [
        await (await bobSession.getDevice()).toBundle(),
        await (await bobSession2.getDevice()).toBundle(),
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
      (await aliceSession.getDevice()).id,
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
      (await bobSession.getDevice()).id,
      bobResponseMessage.encryptedKeys,
    );
    expect(bobResponseText, aliceReceivedMessage);

    // Alice checks the fingerprints
    final fingerprints = await aliceSession.getHexFingerprintsForJid(bobJid);
    // Check that they the fingerprints are correct
    expect(fingerprints.length, 2);
    expect(fingerprints[0] != fingerprints[1], true);
    // Check that those two calls do not throw an exception
    aliceSession
      ..getRatchet(bobJid, fingerprints[0].deviceId)
      ..getRatchet(bobJid, fingerprints[1].deviceId);
  });

  test('Test using OMEMO sessions with encrypt to self', () async {
    const aliceJid = 'alice@server.example';
    const bobJid = 'bob@other.server.example';
      
    // Alice and Bob generate their sessions
    final aliceSession1 = await OmemoSessionManager.generateNewIdentity(
      aliceJid,
      AlwaysTrustingTrustManager(),
      opkAmount: 1,
    );
    final aliceSession2 = await OmemoSessionManager.generateNewIdentity(
      aliceJid,
      AlwaysTrustingTrustManager(),
      opkAmount: 1,
    );
    final bobSession = await OmemoSessionManager.generateNewIdentity(
      bobJid,
      AlwaysTrustingTrustManager(),
      opkAmount: 1,
    );

    // Alice encrypts a message for Bob
    const messagePlaintext = 'Hello Bob!';
    final aliceMessage = await aliceSession1.encryptToJids(
      [bobJid, aliceJid],
      messagePlaintext,
      newSessions: [
        await (await bobSession.getDevice()).toBundle(),
        await (await aliceSession2.getDevice()).toBundle(),
      ],
    );
    expect(aliceMessage.encryptedKeys.length, 2);

    // Alice sends the message to Bob
    // ...

    // Bob decrypts it
    final bobMessage = await bobSession.decryptMessage(
      aliceMessage.ciphertext,
      aliceJid,
      (await aliceSession1.getDevice()).id,
      aliceMessage.encryptedKeys,
    );
    expect(messagePlaintext, bobMessage);

    // Alice's other device decrypts it
    final aliceMessage2 = await aliceSession2.decryptMessage(
      aliceMessage.ciphertext,
      aliceJid,
      (await aliceSession1.getDevice()).id,
      aliceMessage.encryptedKeys,
    );
    expect(messagePlaintext, aliceMessage2);
  });

  test('Test using sending empty OMEMO messages', () async {
    const aliceJid = 'alice@server.example';
    const bobJid = 'bob@other.server.example';
      
    // Alice and Bob generate their sessions
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

    // Alice encrypts a message for Bob
    final aliceMessage = await aliceSession.encryptToJid(
      bobJid,
      null,
      newSessions: [
        await (await bobSession.getDevice()).toBundle(),
      ],
    );
    expect(aliceMessage.encryptedKeys.length, 1);
    expect(aliceMessage.ciphertext, null);

    // Alice sends the message to Bob
    // ...

    // Bob decrypts it
    final bobMessage = await bobSession.decryptMessage(
      aliceMessage.ciphertext,
      aliceJid,
      (await aliceSession.getDevice()).id,
      aliceMessage.encryptedKeys,
    );
    expect(bobMessage, null);

    // This call must not cause an exception
    bobSession.getRatchet(aliceJid, (await aliceSession.getDevice()).id);
  });

  test('Test rotating the Signed Prekey', () async {
    // Generate the session
    const aliceJid = 'alice@some.server';
    final aliceSession = await OmemoSessionManager.generateNewIdentity(
      aliceJid,
      AlwaysTrustingTrustManager(),
      opkAmount: 1,
    );

    // Setup an event listener
    final oldDevice = await aliceSession.getDevice();
    Device? newDevice;
    aliceSession.eventStream.listen((event) {
      if (event is DeviceModifiedEvent) {
        newDevice = event.device;
      }
    });

    // Rotate the Signed Prekey
    await aliceSession.rotateSignedPrekey();

    // Just for safety...
    await Future<void>.delayed(const Duration(seconds: 2));

    expect(await oldDevice.equals(newDevice!), false);
    expect(await newDevice!.equals(await aliceSession.getDevice()), true);

    expect(await newDevice!.oldSpk!.equals(oldDevice.spk), true);
    expect(newDevice!.oldSpkId, oldDevice.spkId);
  });

  test('Test accepting a session with an old SPK', () async {
    const aliceJid = 'alice@server.example';
    const bobJid = 'bob@other.server.example';
      
    // Alice and Bob generate their sessions
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

    // Alice encrypts a message for Bob
    const messagePlaintext = 'Hello Bob!';
    final aliceMessage = await aliceSession.encryptToJid(
      bobJid,
      messagePlaintext,
      newSessions: [
        await (await bobSession.getDevice()).toBundle(),
      ],
    );
    expect(aliceMessage.encryptedKeys.length, 1);

    // Alice loses her Internet connection. Bob rotates his SPK.
    await bobSession.rotateSignedPrekey();
    
    // Alice regains her Internet connection and sends the message to Bob
    // ...

    // Bob decrypts it
    final bobMessage = await bobSession.decryptMessage(
      aliceMessage.ciphertext,
      aliceJid,
      (await aliceSession.getDevice()).id,
      aliceMessage.encryptedKeys,
    );
    expect(messagePlaintext, bobMessage);
  });

  test('Test trust bypassing with empty OMEMO messages', () async {
    const aliceJid = 'alice@server.example';
    const bobJid = 'bob@other.server.example';
      
    // Alice and Bob generate their sessions
    final aliceSession = await OmemoSessionManager.generateNewIdentity(
      aliceJid,
      NeverTrustingTrustManager(),
      opkAmount: 1,
    );
    final bobSession = await OmemoSessionManager.generateNewIdentity(
      bobJid,
      NeverTrustingTrustManager(),
      opkAmount: 1,
    );

    // Alice encrypts an empty message for Bob
    final aliceMessage = await aliceSession.encryptToJid(
      bobJid,
      null,
      newSessions: [
        await (await bobSession.getDevice()).toBundle(),
      ],
    );

    // Despite Alice not trusting Bob's device, we should have encrypted it for his
    // untrusted device.
    expect(aliceMessage.encryptedKeys.length, 1);
  });*/

  test('Test by sending multiple messages back and forth', () async {
    const aliceJid = 'alice@server.example';
    const bobJid = 'bob@other.server.example';
    // Alice and Bob generate their sessions
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

    // Alice encrypts a message for Bob
    final aliceMessage = await aliceSession.encryptToJid(
      bobJid,
      'Hello Bob!',
      newSessions: [
        await (await bobSession.getDevice()).toBundle(),
      ],
    );

    // Alice sends the message to Bob
    // ...

    await bobSession.decryptMessage(
      aliceMessage.ciphertext,
      aliceJid,
      (await aliceSession.getDevice()).id,
      aliceMessage.encryptedKeys,
    );

    for (var i = 0; i < 100; i++) {
      final messageText = 'Test Message #$i';
      // Bob responds to Alice
      final bobResponseMessage = await bobSession.encryptToJid(
        aliceJid,
        messageText,
      );

      // Bob sends the message to Alice
      // ...

      // Alice decrypts it
      final aliceReceivedMessage = await aliceSession.decryptMessage(
        bobResponseMessage.ciphertext,
        bobJid,
        (await bobSession.getDevice()).id,
        bobResponseMessage.encryptedKeys,
      );
      expect(messageText, aliceReceivedMessage);
    }
  });
}
