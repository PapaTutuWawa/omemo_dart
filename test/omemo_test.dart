import 'package:logging/logging.dart';
import 'package:omemo_dart/omemo_dart.dart';
import 'package:omemo_dart/src/trust/always.dart';
import 'package:omemo_dart/src/trust/never.dart';
import 'package:test/test.dart';

void main() {
  Logger.root
    ..level = Level.ALL
    ..onRecord.listen((record) {
      // ignore: avoid_print
      print('${record.level.name}: ${record.message}');
    });

  test('Test replacing a onetime prekey', () async {
    const aliceJid = 'alice@server.example';
    final device = await Device.generateNewDevice(aliceJid, opkAmount: 1);

    final newDevice = await device.replaceOnetimePrekey(0);

    expect(device.jid, newDevice.jid);
    expect(device.id, newDevice.id);

    var opksMatch = true;
    if (newDevice.opks.length != device.opks.length) {
      opksMatch = false;
    } else {
      for (final entry in device.opks.entries) {
        final m = await newDevice.opks[entry.key]?.equals(entry.value) ?? false;
        if (!m) opksMatch = false;
      }
    }
    
    expect(opksMatch, true);
    expect(await device.ik.equals(newDevice.ik), true);
    expect(await device.spk.equals(newDevice.spk), true);

    final oldSpkMatch = device.oldSpk != null ?
      await device.oldSpk!.equals(newDevice.oldSpk!) :
      newDevice.oldSpk == null;
    expect(oldSpkMatch, true);
    expect(listsEqual(device.spkSignature, newDevice.spkSignature), true);
  });
    
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
      } else if (event is DeviceListModifiedEvent) {
        deviceMapModified++;
      }
    });

    // Alice encrypts a message for Bob
    const messagePlaintext = 'Hello Bob!';
    final aliceMessage = await aliceSession.encryptToJid(
      bobJid,
      messagePlaintext,
      newSessions: [
        await bobSession.getDeviceBundle(),
      ],
    );
    expect(aliceMessage.encryptedKeys.length, 1);
    
    // Alice sends the message to Bob
    // ...

    // Bob decrypts it
    final bobMessage = await bobSession.decryptMessage(
      aliceMessage.ciphertext,
      aliceJid,
      await aliceSession.getDeviceId(),
      aliceMessage.encryptedKeys,
      0,
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

    // Ratchets are acked
    await aliceSession.ratchetAcknowledged(bobJid, await bobSession.getDeviceId());
    await bobSession.ratchetAcknowledged(aliceJid, await aliceSession.getDeviceId());
    
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
      await bobSession.getDeviceId(),
      bobResponseMessage.encryptedKeys,
      0,
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
        await bobSession.getDeviceBundle(),
        await bobSession2.getDeviceBundle(),
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
      await aliceSession.getDeviceId(),
      aliceMessage.encryptedKeys,
      0,
    );
    expect(messagePlaintext, bobMessage);

    // Ratchets are acked
    await aliceSession.ratchetAcknowledged(bobJid, await bobSession.getDeviceId());
    await bobSession.ratchetAcknowledged(aliceJid, await aliceSession.getDeviceId());
    
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
      await bobSession.getDeviceId(),
      bobResponseMessage.encryptedKeys,
      0,
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
        await bobSession.getDeviceBundle(),
        await aliceSession2.getDeviceBundle(),
      ],
    );
    expect(aliceMessage.encryptedKeys.length, 2);

    // Alice sends the message to Bob
    // ...

    // Bob decrypts it
    final bobMessage = await bobSession.decryptMessage(
      aliceMessage.ciphertext,
      aliceJid,
      await aliceSession1.getDeviceId(),
      aliceMessage.encryptedKeys,
      0,
    );
    expect(messagePlaintext, bobMessage);

    // Alice's other device decrypts it
    final aliceMessage2 = await aliceSession2.decryptMessage(
      aliceMessage.ciphertext,
      aliceJid,
      await aliceSession1.getDeviceId(),
      aliceMessage.encryptedKeys,
      0,
    );
    expect(messagePlaintext, aliceMessage2);
  });

  test('Test sending empty OMEMO messages', () async {
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
        await bobSession.getDeviceBundle(),
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
      await aliceSession.getDeviceId(),
      aliceMessage.encryptedKeys,
      0,
    );
    expect(bobMessage, null);

    // This call must not cause an exception
    bobSession.getRatchet(aliceJid, await aliceSession.getDeviceId());
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
        await bobSession.getDeviceBundle(),
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
      await aliceSession.getDeviceId(),
      aliceMessage.encryptedKeys,
      0,
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
        await bobSession.getDeviceBundle(),
      ],
    );

    // Despite Alice not trusting Bob's device, we should have encrypted it for his
    // untrusted device.
    expect(aliceMessage.encryptedKeys.length, 1);
  });

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
        await bobSession.getDeviceBundle(),
      ],
    );

    // Alice sends the message to Bob
    // ...

    await bobSession.decryptMessage(
      aliceMessage.ciphertext,
      aliceJid,
      await aliceSession.getDeviceId(),
      aliceMessage.encryptedKeys,
      0,
    );

    // Ratchets are acked
    await aliceSession.ratchetAcknowledged(bobJid, await bobSession.getDeviceId());
    await bobSession.ratchetAcknowledged(aliceJid, await aliceSession.getDeviceId());
    
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
        await bobSession.getDeviceId(),
        bobResponseMessage.encryptedKeys,
        0,
      );
      expect(messageText, aliceReceivedMessage);
    }
  });

  group('Test removing a ratchet', () {
    test('Test removing a ratchet when the user has multiple', () async {
      const aliceJid = 'alice@server.local';
      const bobJid = 'bob@some.server.local';
      final aliceSession = await OmemoSessionManager.generateNewIdentity(
        aliceJid,
        AlwaysTrustingTrustManager(),
        opkAmount: 1,
      );
      final bobSession1 = await OmemoSessionManager.generateNewIdentity(
        bobJid,
        AlwaysTrustingTrustManager(),
        opkAmount: 1,
      );
      final bobSession2 = await OmemoSessionManager.generateNewIdentity(
        bobJid,
        AlwaysTrustingTrustManager(),
        opkAmount: 1,
      );

      // Alice sends a message to those two Bobs
      await aliceSession.encryptToJid(
        bobJid,
        'Hallo Welt',
        newSessions: [
          await bobSession1.getDeviceBundle(),
          await bobSession2.getDeviceBundle(),
        ],
      );

      // One of those two sessions is broken, so Alice removes the session2 ratchet
      final id1 = await bobSession1.getDeviceId();
      final id2 = await bobSession2.getDeviceId();
      await aliceSession.removeRatchet(bobJid, id1);

      final map = aliceSession.getRatchetMap();
      expect(map.containsKey(RatchetMapKey(bobJid, id1)), false);
      expect(map.containsKey(RatchetMapKey(bobJid, id2)), true);
      final deviceMap = await aliceSession.getDeviceMap();
      expect(deviceMap.containsKey(bobJid), true);
      expect(deviceMap[bobJid], [id2]);
    });

    test('Test removing a ratchet when the user has only one', () async {
      const aliceJid = 'alice@server.local';
      const bobJid = 'bob@some.server.local';
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

      // Alice sends a message to those two Bobs
      await aliceSession.encryptToJid(
        bobJid,
        'Hallo Welt',
        newSessions: [
          await bobSession.getDeviceBundle(),
        ],
      );

      // One of those two sessions is broken, so Alice removes the session2 ratchet
      final id = await bobSession.getDeviceId();
      await aliceSession.removeRatchet(bobJid, id);

      final map = aliceSession.getRatchetMap();
      expect(map.containsKey(RatchetMapKey(bobJid, id)), false);
      final deviceMap = await aliceSession.getDeviceMap();
      expect(deviceMap.containsKey(bobJid), false);
    });
  });

  test('Test acknowledging a ratchet', () async {
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

    // Alice sends Bob a message
    await aliceSession.encryptToJid(
      bobJid,
      'Hallo Welt',
      newSessions: [
        await bobSession.getDeviceBundle(),
      ],
    );
    expect(
      await aliceSession.getUnacknowledgedRatchets(bobJid),
      [
        await bobSession.getDeviceId(),
      ],
    );

    // Bob sends alice an empty message
    // ...

    // Alice decrypts it
    // ...

    // Alice marks the ratchet as acknowledged
    await aliceSession.ratchetAcknowledged(bobJid, await bobSession.getDeviceId());
    expect(
      (await aliceSession.getUnacknowledgedRatchets(bobJid))!.isEmpty,
      true,
    );
  });

  test('Test overwriting sessions', () async {
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
      opkAmount: 2,
    );

    // Alice sends Bob a message
    final msg1 = await aliceSession.encryptToJid(
      bobJid,
      'Hallo Welt',
      newSessions: [
        await bobSession.getDeviceBundle(),
      ],
    );
    await bobSession.decryptMessage(
      msg1.ciphertext,
      aliceJid,
      await aliceSession.getDeviceId(),
      msg1.encryptedKeys,
      0,
    );
    final aliceRatchet1 = aliceSession.getRatchet(
      bobJid,
      await bobSession.getDeviceId(),
    );
    final bobRatchet1 = bobSession.getRatchet(
      aliceJid,
      await aliceSession.getDeviceId(),
    );

    // Alice is impatient and immediately sends another message before the original one
    // can be acknowledged by Bob
    final msg2 = await aliceSession.encryptToJid(
      bobJid,
      "Why don't you answer?",
      newSessions: [
        await bobSession.getDeviceBundle(),
      ],
    );
    await bobSession.decryptMessage(
      msg2.ciphertext,
      aliceJid,
      await aliceSession.getDeviceId(),
      msg2.encryptedKeys,
      getTimestamp(),
    );
    final aliceRatchet2 = aliceSession.getRatchet(
      bobJid,
      await bobSession.getDeviceId(),
    );
    final bobRatchet2 = bobSession.getRatchet(
      aliceJid,
      await aliceSession.getDeviceId(),
    );

    // Both should only have one ratchet
    expect(aliceSession.getRatchetMap().length, 1);
    expect(bobSession.getRatchetMap().length, 1);
    
    // The ratchets should both be different
    expect(await aliceRatchet1.equals(aliceRatchet2), false);
    expect(await bobRatchet1.equals(bobRatchet2), false);
  });

  test('Test resending key exchanges', () async {
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
      opkAmount: 2,
    );

    // Alice sends Bob a message
    final msg1 = await aliceSession.encryptToJid(
      bobJid,
      'Hallo Welt',
      newSessions: [
        await bobSession.getDeviceBundle(),
      ],
    );
    // The first message should be a kex message
    expect(msg1.encryptedKeys.first.kex, true);

    await bobSession.decryptMessage(
      msg1.ciphertext,
      aliceJid,
      await aliceSession.getDeviceId(),
      msg1.encryptedKeys,
      0,
    );

    // Alice is impatient and immediately sends another message before the original one
    // can be acknowledged by Bob
    final msg2 = await aliceSession.encryptToJid(
      bobJid,
      "Why don't you answer?",
    );
    expect(msg2.encryptedKeys.first.kex, true);

    await bobSession.decryptMessage(
      msg2.ciphertext,
      aliceJid,
      await aliceSession.getDeviceId(),
      msg2.encryptedKeys,
      getTimestamp(),
    );

  });
  
  test('Test receiving old messages including a KEX', () async {
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
      opkAmount: 2,
    );

    final bobsReceivedMessages = List<EncryptionResult>.empty(growable: true);
    final bobsReceivedMessagesTimestamps = List<int>.empty(growable: true);
    
    // Alice sends Bob a message
    final msg1 = await aliceSession.encryptToJid(
      bobJid,
      'Hallo Welt',
      newSessions: [
        await bobSession.getDeviceBundle(),
      ],
    );
    bobsReceivedMessages.add(msg1);
    final t1 = getTimestamp();
    bobsReceivedMessagesTimestamps.add(t1);

    await bobSession.decryptMessage(
      msg1.ciphertext,
      aliceJid,
      await aliceSession.getDeviceId(),
      msg1.encryptedKeys,
      t1,
    );

    // Ratchets are acked
    await aliceSession.ratchetAcknowledged(bobJid, await bobSession.getDeviceId());
    await bobSession.ratchetAcknowledged(aliceJid, await aliceSession.getDeviceId());
    
    // Bob responds
    final msg2 = await bobSession.encryptToJid(
      aliceJid,
      'Hello!',
    );

    await aliceSession.decryptMessage(
      msg2.ciphertext,
      bobJid,
      await bobSession.getDeviceId(),
      msg2.encryptedKeys,
      getTimestamp(),
    );
    
    // Send some messages between the two
    for (var i = 0; i < 100; i++) {
      final msg = await aliceSession.encryptToJid(
        bobJid,
        'Hello $i',
      );
      bobsReceivedMessages.add(msg);
      final t = getTimestamp();
      bobsReceivedMessagesTimestamps.add(t);
      final result = await bobSession.decryptMessage(
        msg.ciphertext,
        aliceJid,
        await aliceSession.getDeviceId(),
        msg.encryptedKeys,
        t,
      );

      expect(result, 'Hello $i');
    }

    // Due to some issue with the transport protocol, the messages to Bob are received
    // again.
    final ratchetPreError = bobSession
      .getRatchet(aliceJid, await aliceSession.getDeviceId())
      .clone();
    var invalidKex = 0;
    var errorCounter = 0;
    for (var i = 0; i < bobsReceivedMessages.length; i++) {
      final msg = bobsReceivedMessages[i];
      try {
        await bobSession.decryptMessage(
          msg.ciphertext,
          aliceJid,
          await aliceSession.getDeviceId(),
          msg.encryptedKeys,
          bobsReceivedMessagesTimestamps[i],
        );
        expect(true, false);
      } on InvalidMessageHMACException catch (_) {
        errorCounter++;
      } on InvalidKeyExchangeException catch (_) {
        invalidKex++;
      }
    }
    final ratchetPostError = bobSession
      .getRatchet(aliceJid, await aliceSession.getDeviceId())
      .clone();

    // The 100 messages including the initial KEX message
    expect(invalidKex, 1);
    expect(errorCounter, 100);
    expect(await ratchetPreError.equals(ratchetPostError), true);

    
    final msg3 = await aliceSession.encryptToJid(
      bobJid,
      'Are you okay?',
    );
    final result = await bobSession.decryptMessage(
      msg3.ciphertext,
      aliceJid,
      await aliceSession.getDeviceId(),
      msg3.encryptedKeys,
      104,
    );

    expect(result, 'Are you okay?');
  });

  test("Test ignoring a new KEX when we haven't acket it yet", () async {
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

    // Alice sends Bob a message
    final msg1 = await aliceSession.encryptToJid(
      bobJid,
      'Hallo Welt',
      newSessions: [
        await bobSession.getDeviceBundle(),
      ],
    );
    expect(msg1.encryptedKeys.first.kex, true);

    await bobSession.decryptMessage(
      msg1.ciphertext,
      aliceJid,
      await aliceSession.getDeviceId(),
      msg1.encryptedKeys,
      getTimestamp(),
    );

    // Alice sends another message before the ack can reach us
    final msg2 = await aliceSession.encryptToJid(
      bobJid,
      'ANSWER ME!',
    );
    expect(msg2.encryptedKeys.first.kex, true);

    await bobSession.decryptMessage(
      msg2.ciphertext,
      aliceJid,
      await aliceSession.getDeviceId(),
      msg2.encryptedKeys,
      getTimestamp(),
    );

    // Now the acks reach us
    await aliceSession.ratchetAcknowledged(bobJid, await bobSession.getDeviceId());
    await bobSession.ratchetAcknowledged(aliceJid, await aliceSession.getDeviceId());

    // Alice sends another message
    final msg3 = await aliceSession.encryptToJid(
      bobJid,
      "You read the message, didn't you?",
    );
    expect(msg3.encryptedKeys.first.kex, false);

    await bobSession.decryptMessage(
      msg3.ciphertext,
      aliceJid,
      await aliceSession.getDeviceId(),
      msg3.encryptedKeys,
      getTimestamp(),
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
        await bobSession.getDeviceId(),
        bobResponseMessage.encryptedKeys,
        0,
      );
      expect(messageText, aliceReceivedMessage);
    }
  });
}
