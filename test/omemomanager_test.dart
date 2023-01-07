import 'dart:convert';
import 'package:logging/logging.dart';
import 'package:omemo_dart/omemo_dart.dart';
import 'package:omemo_dart/src/trust/always.dart';
import 'package:test/test.dart';

void main() {
  Logger.root
    ..level = Level.ALL
    ..onRecord.listen((record) {
      // ignore: avoid_print
      print('${record.level.name}: ${record.message}');
    });

  test('Test sending a message without the device list cache', () async {
    const aliceJid = 'alice@server1';
    const bobJid = 'bob@server2';
    var aliceEmptyMessageSent = 0;
    var bobEmptyMessageSent = 0;

    final aliceDevice = await OmemoDevice.generateNewDevice(aliceJid, opkAmount: 1);
    final bobDevice = await OmemoDevice.generateNewDevice(bobJid, opkAmount: 1);

    final aliceManager = OmemoManager(
      aliceDevice,
      AlwaysTrustingTrustManager(),
      (result, recipientJid) async {
        aliceEmptyMessageSent++;
      },
      (jid) async {
        expect(jid, bobJid);
        return [ bobDevice.id ];
      },
      (jid, id) async {
        expect(jid, bobJid);
        return bobDevice.toBundle();
      },
      (jid) async {},
    );
    final bobManager = OmemoManager(
      bobDevice,
      AlwaysTrustingTrustManager(),
      (result, recipientJid) async {
        bobEmptyMessageSent++;
      },
      (jid) async {
        expect(jid, aliceJid);
        return [aliceDevice.id];
      },
      (jid, id) async {
        expect(jid, aliceJid);
        return aliceDevice.toBundle();
      },
      (jid) async {},
    );

    // Alice sends a message
    final aliceResult = await aliceManager.onOutgoingStanza(
      const OmemoOutgoingStanza(
        [bobJid],
        'Hello world',
      ),
    );

    // Bob must be able to decrypt the message
    final bobResult = await bobManager.onIncomingStanza(
      OmemoIncomingStanza(
        aliceJid,
        aliceDevice.id,
        DateTime.now().millisecondsSinceEpoch,
        aliceResult.encryptedKeys,
        base64.encode(aliceResult.ciphertext!),
      ),
    );

    expect(bobResult.payload, 'Hello world');
    expect(bobResult.error, null);
    expect(aliceEmptyMessageSent, 0);
    expect(bobEmptyMessageSent, 1);

    // Alice receives the ack message
    await aliceManager.ratchetAcknowledged(
      bobJid,
      bobDevice.id,
    );
    
    // Bob now responds
    final bobResult2 = await bobManager.onOutgoingStanza(
      const OmemoOutgoingStanza(
        [aliceJid],
        'Hello world, Alice',
      ),
    );
    final aliceResult2 = await aliceManager.onIncomingStanza(
      OmemoIncomingStanza(
        bobJid,
        bobDevice.id,
        DateTime.now().millisecondsSinceEpoch,
        bobResult2.encryptedKeys,
        base64.encode(bobResult2.ciphertext!),
      ),
    );

    expect(aliceResult2.error, null);
    expect(aliceEmptyMessageSent, 0);
    expect(bobEmptyMessageSent, 1);
    expect(aliceResult2.payload, 'Hello world, Alice');
  });

  test('Test triggering the heartbeat', () async {
    const aliceJid = 'alice@server1';
    const bobJid = 'bob@server2';
    var aliceEmptyMessageSent = 0;
    var bobEmptyMessageSent = 0;

    final aliceDevice = await OmemoDevice.generateNewDevice(aliceJid, opkAmount: 1);
    final bobDevice = await OmemoDevice.generateNewDevice(bobJid, opkAmount: 1);

    final aliceManager = OmemoManager(
      aliceDevice,
      AlwaysTrustingTrustManager(),
      (result, recipientJid) async {
        aliceEmptyMessageSent++;
      },
      (jid) async {
        expect(jid, bobJid);
        return [ bobDevice.id ];
      },
      (jid, id) async {
        expect(jid, bobJid);
        return bobDevice.toBundle();
      },
      (jid) async {},
    );
    final bobManager = OmemoManager(
      bobDevice,
      AlwaysTrustingTrustManager(),
      (result, recipientJid) async {
        bobEmptyMessageSent++;
      },
      (jid) async {
        expect(jid, aliceJid);
        return [aliceDevice.id];
      },
      (jid, id) async {
        expect(jid, aliceJid);
        return aliceDevice.toBundle();
      },
      (jid) async {},
    );

    // Alice sends a message
    final aliceResult = await aliceManager.onOutgoingStanza(
      const OmemoOutgoingStanza(
        [bobJid],
        'Hello world',
      ),
    );

    // Bob must be able to decrypt the message
    final bobResult = await bobManager.onIncomingStanza(
      OmemoIncomingStanza(
        aliceJid,
        aliceDevice.id,
        DateTime.now().millisecondsSinceEpoch,
        aliceResult.encryptedKeys,
        base64.encode(aliceResult.ciphertext!),
      ),
    );

    expect(aliceEmptyMessageSent, 0);
    expect(bobEmptyMessageSent, 1);
    expect(bobResult.payload, 'Hello world');

    // Bob acknowledges the message
    await aliceManager.ratchetAcknowledged(bobJid, bobDevice.id);
    
    // Alice now sends 52 messages that Bob decrypts
    for (var i = 0; i <= 51; i++) {
      final aliceResultLoop = await aliceManager.onOutgoingStanza(
        OmemoOutgoingStanza(
          [bobJid],
          'Test message $i',
        ),
      );

      final bobResultLoop = await bobManager.onIncomingStanza(
        OmemoIncomingStanza(
          aliceJid,
          aliceDevice.id,
          DateTime.now().millisecondsSinceEpoch,
          aliceResultLoop.encryptedKeys,
          base64.encode(aliceResultLoop.ciphertext!),
        ),
      );

      expect(aliceEmptyMessageSent, 0);
      expect(bobEmptyMessageSent, 1);
      expect(bobResultLoop.payload, 'Test message $i');
    }

    // Alice sends a final message that triggers a heartbeat
    final aliceResultFinal = await aliceManager.onOutgoingStanza(
      const OmemoOutgoingStanza(
        [bobJid],
        'Test message last',
      ),
    );

    final bobResultFinal = await bobManager.onIncomingStanza(
      OmemoIncomingStanza(
        aliceJid,
        aliceDevice.id,
        DateTime.now().millisecondsSinceEpoch,
        aliceResultFinal.encryptedKeys,
        base64.encode(aliceResultFinal.ciphertext!),
      ),
    );

    expect(aliceEmptyMessageSent, 0);
    expect(bobEmptyMessageSent, 2);
    expect(bobResultFinal.payload, 'Test message last');
  });

  test('Test accessing data without it existing', () async {
    const aliceJid = 'alice@server1';
    const bobJid = 'bob@server2';
    final aliceDevice = await OmemoDevice.generateNewDevice(aliceJid, opkAmount: 1);

    final aliceManager = OmemoManager(
      aliceDevice,
      AlwaysTrustingTrustManager(),
      (result, recipientJid) async {},
      (jid) async => [],
      (jid, id) async => null,
      (jid) async {},
    );

    // Get non-existant fingerprints
    expect(
      await aliceManager.getFingerprintsForJid(bobJid),
      null,
    );

    // Ack a non-existant ratchet
    await aliceManager.ratchetAcknowledged(
      bobJid,
      42,
    );
  });

  test('Test receiving a message encrypted for another device', () async {
    const aliceJid = 'alice@server1';
    const bobJid = 'bob@server2';
    var oldDevice = true;

    final aliceDevice = await OmemoDevice.generateNewDevice(aliceJid, opkAmount: 1);
    final bobOldDevice = await OmemoDevice.generateNewDevice(bobJid, opkAmount: 1);
    final bobCurrentDevice = await OmemoDevice.generateNewDevice(bobJid, opkAmount: 1);

    final aliceManager = OmemoManager(
      aliceDevice,
      AlwaysTrustingTrustManager(),
      (result, recipientJid) async {},
      (jid) async {
        expect(jid, bobJid);

        return oldDevice ?
          [ bobOldDevice.id ] :
          [ bobCurrentDevice.id ];
      },
      (jid, id) async {
        expect(jid, bobJid);
        return oldDevice ?
          bobOldDevice.toBundle() :
          bobCurrentDevice.toBundle();
      },
      (jid) async {},
    );
    final bobManager = OmemoManager(
      bobCurrentDevice,
      AlwaysTrustingTrustManager(),
      (result, recipientJid) async {},
      (jid) async => [],
      (jid, id) async => null,
      (jid) async {},
    );

    // Alice encrypts a message to Bob
    final aliceResult1 = await aliceManager.onOutgoingStanza(
      const OmemoOutgoingStanza(
        [bobJid],
        'Hello Bob',
      ),
    );

    // Bob's current device receives it
    final bobResult1 = await bobManager.onIncomingStanza(
      OmemoIncomingStanza(
        aliceJid,
        aliceDevice.id,
        DateTime.now().millisecondsSinceEpoch,
        aliceResult1.encryptedKeys,
        base64.encode(aliceResult1.ciphertext!),
      ),
    );

    expect(bobResult1.payload, null);
    expect(bobResult1.error is NotEncryptedForDeviceException, true);

    // Now Alice's client loses and regains the connection
    aliceManager.onNewConnection();
    oldDevice = false;

    // And Alice sends a new message
    final aliceResult2 = await aliceManager.onOutgoingStanza(
      const OmemoOutgoingStanza(
        [bobJid],
        'Hello Bob x2',
      ),
    );
    final bobResult2 = await bobManager.onIncomingStanza(
      OmemoIncomingStanza(
        aliceJid,
        aliceDevice.id,
        DateTime.now().millisecondsSinceEpoch,
        aliceResult2.encryptedKeys,
        base64.encode(aliceResult2.ciphertext!),
      ),
    );

    expect(aliceResult2.encryptedKeys.length, 1);
    expect(bobResult2.payload, 'Hello Bob x2');
  });

  test('Test receiving a response from a new device', () async {
    const aliceJid = 'alice@server1';
    const bobJid = 'bob@server2';
    var bothDevices = false;

    final aliceDevice = await OmemoDevice.generateNewDevice(aliceJid, opkAmount: 1);
    final bobDevice1 = await OmemoDevice.generateNewDevice(bobJid, opkAmount: 1);
    final bobDevice2 = await OmemoDevice.generateNewDevice(bobJid, opkAmount: 1);

    final aliceManager = OmemoManager(
      aliceDevice,
      AlwaysTrustingTrustManager(),
      (result, recipientJid) async {},
      (jid) async {
        expect(jid, bobJid);

        return [
          bobDevice1.id,

          if (bothDevices)
            bobDevice2.id,
        ];
      },
      (jid, id) async {
        expect(jid, bobJid);

        if (bothDevices) {
          if (id == bobDevice1.id) {
            return bobDevice1.toBundle();
          } else if (id == bobDevice2.id) {
            return bobDevice2.toBundle();
          }
        } else {
          if (id == bobDevice1.id) return bobDevice1.toBundle();
        }

        return null;
      },
      (jid) async {},
    );
    final bobManager1 = OmemoManager(
      bobDevice1,
      AlwaysTrustingTrustManager(),
      (result, recipientJid) async {},
      (jid) async => [],
      (jid, id) async => null,
      (jid) async {},
    );
    final bobManager2 = OmemoManager(
      bobDevice2,
      AlwaysTrustingTrustManager(),
      (result, recipientJid) async {},
      (jid) async {
        expect(jid, aliceJid);
        return [aliceDevice.id];
      },
      (jid, id) async {
        expect(jid, aliceJid);
        return aliceDevice.toBundle();
      },
      (jid) async {},
    );

    // Alice sends a message to Bob
    final aliceResult1 = await aliceManager.onOutgoingStanza(
      const OmemoOutgoingStanza(
        [bobJid],
        'Hello Bob!',
      ),
    );

    // Bob decrypts it
    final bobResult1 = await bobManager1.onIncomingStanza(
      OmemoIncomingStanza(
        aliceJid,
        aliceDevice.id,
        DateTime.now().millisecondsSinceEpoch,
        aliceResult1.encryptedKeys,
        base64.encode(aliceResult1.ciphertext!),
      ),
    );

    expect(aliceResult1.encryptedKeys.length, 1);
    expect(bobResult1.payload, 'Hello Bob!');

    // Now Bob encrypts from his new device
    bothDevices = true;
    final bobResult2 = await bobManager2.onOutgoingStanza(
      const OmemoOutgoingStanza(
        [aliceJid],
        'Hello from my new device',
      ),
    );

    // And Alice decrypts it
    final aliceResult2 = await aliceManager.onIncomingStanza(
      OmemoIncomingStanza(
        bobJid,
        bobDevice2.id,
        DateTime.now().millisecondsSinceEpoch,
        bobResult2.encryptedKeys,
        base64.encode(bobResult2.ciphertext!),
      ),
    );

    expect(aliceResult2.payload, 'Hello from my new device');
  });

  test('Test receiving a device list update', () async {
    const aliceJid = 'alice@server1';
    const bobJid = 'bob@server2';
    var bothDevices = false;

    final aliceDevice = await OmemoDevice.generateNewDevice(aliceJid, opkAmount: 1);
    final bobDevice1 = await OmemoDevice.generateNewDevice(bobJid, opkAmount: 1);
    final bobDevice2 = await OmemoDevice.generateNewDevice(bobJid, opkAmount: 1);

    final aliceManager = OmemoManager(
      aliceDevice,
      AlwaysTrustingTrustManager(),
      (result, recipientJid) async {},
      (jid) async {
        expect(jid, bobJid);

        return [
          bobDevice1.id,

          if (bothDevices)
            bobDevice2.id,
        ];
      },
      (jid, id) async {
        expect(jid, bobJid);

        if (bothDevices) {
          if (id == bobDevice1.id) {
            return bobDevice1.toBundle();
          } else if (id == bobDevice2.id) {
            return bobDevice2.toBundle();
          }
        } else {
          if (id == bobDevice1.id) return bobDevice1.toBundle();
        }

        return null;
      },
      (jid) async {},
    );
    final bobManager1 = OmemoManager(
      bobDevice1,
      AlwaysTrustingTrustManager(),
      (result, recipientJid) async {},
      (jid) async => null,
      (jid, id) async => null,
      (jid) async {},
    );
    final bobManager2 = OmemoManager(
      bobDevice2,
      AlwaysTrustingTrustManager(),
      (result, recipientJid) async {},
      (jid) async => null,
      (jid, id) async => null,
      (jid) async {},
    );

    // Alice sends a message to Bob
    final aliceResult1 = await aliceManager.onOutgoingStanza(
      const OmemoOutgoingStanza(
        [bobJid],
        'Hello Bob!',
      ),
    );

    // Bob decrypts it
    final bobResult1 = await bobManager1.onIncomingStanza(
      OmemoIncomingStanza(
        aliceJid,
        aliceDevice.id,
        DateTime.now().millisecondsSinceEpoch,
        aliceResult1.encryptedKeys,
        base64.encode(aliceResult1.ciphertext!),
      ),
    );

    expect(aliceResult1.encryptedKeys.length, 1);
    expect(bobResult1.payload, 'Hello Bob!');

    // Bob acks the ratchet session
    await aliceManager.ratchetAcknowledged(bobJid, bobDevice1.id);
    
    // Bob now publishes a new device
    bothDevices = true;
    aliceManager.onDeviceListUpdate(
      bobJid,
      [
        bobDevice1.id,
        bobDevice2.id,
      ],
    );
    
    // Now Alice encrypts another message
    final aliceResult2 = await aliceManager.onOutgoingStanza(
      const OmemoOutgoingStanza(
        [bobJid],
        'Hello Bob! x2',
      ),
    );

    expect(aliceResult2.encryptedKeys.length, 2);

    // And Bob decrypts it
    final bobResult21 = await bobManager1.onIncomingStanza(
      OmemoIncomingStanza(
        aliceJid,
        aliceDevice.id,
        DateTime.now().millisecondsSinceEpoch,
        aliceResult2.encryptedKeys,
        base64.encode(aliceResult2.ciphertext!),
      ),
    );
    final bobResult22 = await bobManager2.onIncomingStanza(
      OmemoIncomingStanza(
        aliceJid,
        aliceDevice.id,
        DateTime.now().millisecondsSinceEpoch,
        aliceResult2.encryptedKeys,
        base64.encode(aliceResult2.ciphertext!),
      ),
    );

    expect(bobResult21.payload, 'Hello Bob! x2');
    expect(bobResult22.payload, 'Hello Bob! x2');

    // Bob2 now responds
    final bobResult32 = await bobManager2.onOutgoingStanza(
      const OmemoOutgoingStanza(
        [aliceJid],
        'Hello Alice!',
      ),
    );

    // And Alice responds
    final aliceResult3 = await aliceManager.onIncomingStanza(
      OmemoIncomingStanza(
        bobJid,
        bobDevice2.id,
        DateTime.now().millisecondsSinceEpoch,
        bobResult32.encryptedKeys,
        base64.encode(bobResult32.ciphertext!),
      ),
    );

    expect(aliceResult3.payload, 'Hello Alice!');
  });

  test('Test sending a message to two different JIDs', () async {
    const aliceJid = 'alice@server1';
    const bobJid = 'bob@server2';
    const cocoJid = 'coco@server3';

    final aliceDevice = await OmemoDevice.generateNewDevice(aliceJid, opkAmount: 1);
    final bobDevice = await OmemoDevice.generateNewDevice(bobJid, opkAmount: 1);
    final cocoDevice = await OmemoDevice.generateNewDevice(cocoJid, opkAmount: 1);

    final aliceManager = OmemoManager(
      aliceDevice,
      AlwaysTrustingTrustManager(),
      (result, recipientJid) async {},
      (jid) async {
        if (jid == bobJid) {
          return [bobDevice.id];
        } else if (jid == cocoJid) {
          return [cocoDevice.id];
        }

        return null;
      },
      (jid, id) async {
        if (jid == bobJid) {
          return bobDevice.toBundle();
        } else if (jid == cocoJid) {
          return cocoDevice.toBundle();
        }

        return null;
      },
      (jid) async {},
    );
    final bobManager = OmemoManager(
      bobDevice,
      AlwaysTrustingTrustManager(),
      (result, recipientJid) async {},
      (jid) async => null,
      (jid, id) async => null,
      (jid) async {},
    );
    final cocoManager = OmemoManager(
      cocoDevice,
      AlwaysTrustingTrustManager(),
      (result, recipientJid) async {},
      (jid) async => null,
      (jid, id) async => null,
      (jid) async {},
    );

    // Alice sends a message to Bob and Coco
    final aliceResult = await aliceManager.onOutgoingStanza(
      const OmemoOutgoingStanza(
        [bobJid, cocoJid],
        'Hello Bob and Coco!',
      ),
    );

    // Bob and Coco decrypt them
    final bobResult = await bobManager.onIncomingStanza(
      OmemoIncomingStanza(
        aliceJid,
        aliceDevice.id,
        DateTime.now().millisecondsSinceEpoch,
        aliceResult.encryptedKeys,
        base64.encode(aliceResult.ciphertext!),
      ),
    );
    final cocoResult = await cocoManager.onIncomingStanza(
      OmemoIncomingStanza(
        aliceJid,
        aliceDevice.id,
        DateTime.now().millisecondsSinceEpoch,
        aliceResult.encryptedKeys,
        base64.encode(aliceResult.ciphertext!),
      ),
    );

    expect(bobResult.error, null);
    expect(cocoResult.error, null);
    expect(bobResult.payload, 'Hello Bob and Coco!');
    expect(cocoResult.payload, 'Hello Bob and Coco!');
  });

  test('Test a fetch failure', () async {
    const aliceJid = 'alice@server1';
    const bobJid = 'bob@server2';
    var failure = false;

    final aliceDevice = await OmemoDevice.generateNewDevice(aliceJid, opkAmount: 1);
    final bobDevice = await OmemoDevice.generateNewDevice(bobJid, opkAmount: 1);

    final aliceManager = OmemoManager(
      aliceDevice,
      AlwaysTrustingTrustManager(),
      (result, recipientJid) async {},
      (jid) async {
        expect(jid, bobJid);

        return failure ?
          null :
          [bobDevice.id];
      },
      (jid, id) async {
        expect(jid, bobJid);

        return failure ?
          null :
          bobDevice.toBundle();
      },
      (jid) async {},
    );
    final bobManager = OmemoManager(
      bobDevice,
      AlwaysTrustingTrustManager(),
      (result, recipientJid) async {},
      (jid) async => null,
      (jid, id) async => null,
      (jid) async {},
    );

    // Alice sends a message to Bob and Coco
    final aliceResult1 = await aliceManager.onOutgoingStanza(
      const OmemoOutgoingStanza(
        [bobJid],
        'Hello Bob!',
      ),
    );

    // Bob decrypts it
    final bobResult1 = await bobManager.onIncomingStanza(
      OmemoIncomingStanza(
        aliceJid,
        aliceDevice.id,
        DateTime.now().millisecondsSinceEpoch,
        aliceResult1.encryptedKeys,
        base64.encode(aliceResult1.ciphertext!),
      ),
    );

    expect(bobResult1.error, null);
    expect(bobResult1.payload, 'Hello Bob!');

    // Bob acks the message
    await aliceManager.ratchetAcknowledged(
      bobJid,
      bobDevice.id,
    );

    // Alice has to reconnect but has no connection yet
    failure = true;
    aliceManager.onNewConnection();

    // Alice sends another message to Bob
    final aliceResult2 = await aliceManager.onOutgoingStanza(
      const OmemoOutgoingStanza(
        [bobJid],
        'Hello Bob! x2',
      ),
    );

    // And Bob decrypts it
    final bobResult2 = await bobManager.onIncomingStanza(
      OmemoIncomingStanza(
        aliceJid,
        aliceDevice.id,
        DateTime.now().millisecondsSinceEpoch,
        aliceResult2.encryptedKeys,
        base64.encode(aliceResult2.ciphertext!),
      ),
    );

    expect(bobResult2.error, null);
    expect(bobResult2.payload, 'Hello Bob! x2');
  });

  test('Test sending a message with failed lookups', () async {
    const aliceJid = 'alice@server1';
    const bobJid = 'bob@server2';

    final aliceDevice = await OmemoDevice.generateNewDevice(aliceJid, opkAmount: 1);

    final aliceManager = OmemoManager(
      aliceDevice,
      AlwaysTrustingTrustManager(),
      (result, recipientJid) async {},
      (jid) async {
        expect(jid, bobJid);

        return null;
      },
      (jid, id) async {
        expect(jid, bobJid);

        return null;
      },
      (jid) async {},
    );

    // Alice sends a message to Bob
    final aliceResult = await aliceManager.onOutgoingStanza(
      const OmemoOutgoingStanza(
        [bobJid],
        'Hello Bob!',
      ),
    );

    expect(aliceResult.isSuccess(1), false);
    expect(aliceResult.jidEncryptionErrors[bobJid] is NoKeyMaterialAvailableException, true);
  });

  test('Test sending a message two two JIDs with failed lookups', () async {
    const aliceJid = 'alice@server1';
    const bobJid = 'bob@server2';
    const cocoJid = 'coco@server3';

    final aliceDevice = await OmemoDevice.generateNewDevice(aliceJid, opkAmount: 1);
    final bobDevice = await OmemoDevice.generateNewDevice(bobJid, opkAmount: 1);

    final aliceManager = OmemoManager(
      aliceDevice,
      AlwaysTrustingTrustManager(),
      (result, recipientJid) async {},
      (jid) async {
        if (jid == bobJid) {
          return [bobDevice.id];
        }

        return null;
      },
      (jid, id) async {
        if (jid == bobJid) {
          return bobDevice.toBundle();
        }

        return null;
      },
      (jid) async {},
    );
    final bobManager = OmemoManager(
      bobDevice,
      AlwaysTrustingTrustManager(),
      (result, recipientJid) async {},
      (jid) async => null,
      (jid, id) async => null,
      (jid) async {},
    );

    // Alice sends a message to Bob and Coco
    final aliceResult = await aliceManager.onOutgoingStanza(
      const OmemoOutgoingStanza(
        [bobJid, cocoJid],
        'Hello Bob and Coco!',
      ),
    );

    expect(aliceResult.isSuccess(2), true);
    expect(aliceResult.jidEncryptionErrors[cocoJid] is NoKeyMaterialAvailableException, true);

    // Bob decrypts it
    final bobResult = await bobManager.onIncomingStanza(
      OmemoIncomingStanza(
        aliceJid,
        aliceDevice.id,
        DateTime.now().millisecondsSinceEpoch,
        aliceResult.encryptedKeys,
        base64.encode(aliceResult.ciphertext!),
      ),
    );

    expect(bobResult.payload, 'Hello Bob and Coco!');
  });

  test('Test sending multiple messages back and forth', () async {
    const aliceJid = 'alice@server1';
    const bobJid = 'bob@server2';

    final aliceDevice = await OmemoDevice.generateNewDevice(aliceJid, opkAmount: 1);
    final bobDevice = await OmemoDevice.generateNewDevice(bobJid, opkAmount: 1);

    final aliceManager = OmemoManager(
      aliceDevice,
      AlwaysTrustingTrustManager(),
      (result, recipientJid) async {},
      (jid) async {
        expect(jid, bobJid);

        return [bobDevice.id];
      },
      (jid, id) async {
        expect(jid, bobJid);

        return bobDevice.toBundle();
      },
      (jid) async {},
    );
    final bobManager = OmemoManager(
      bobDevice,
      AlwaysTrustingTrustManager(),
      (result, recipientJid) async {},
      (jid) async => null,
      (jid, id) async => null,
      (jid) async {},
    );

    // Alice encrypts a message for Bob
    final aliceMessage = await aliceManager.onOutgoingStanza(
      const OmemoOutgoingStanza(
        [bobJid],
        'Hello Bob!',
      ),
    );

    // And Bob decrypts it
    await bobManager.onIncomingStanza(
      OmemoIncomingStanza(
        aliceJid,
        aliceDevice.id,
        DateTime.now().millisecondsSinceEpoch,
        aliceMessage.encryptedKeys,
        base64.encode(aliceMessage.ciphertext!),
      ),

    );

    // Ratchets are acked
    await aliceManager.ratchetAcknowledged(
      bobJid,
      bobDevice.id,
    );
    
    for (var i = 0; i < 100; i++) {
      final messageText = 'Test Message #$i';
      // Bob responds to Alice
      final bobResponseMessage = await bobManager.onOutgoingStanza(
        OmemoOutgoingStanza(
          [aliceJid],
          messageText,
        ),
      );
      expect(bobResponseMessage.isSuccess(1), true);
      
      final aliceReceivedMessage = await aliceManager.onIncomingStanza(
        OmemoIncomingStanza(
          bobJid,
          bobDevice.id,
          DateTime.now().millisecondsSinceEpoch,
          bobResponseMessage.encryptedKeys,
          base64.encode(bobResponseMessage.ciphertext!),
        ),
      );
      expect(aliceReceivedMessage.payload, messageText);
    }
  });

  test('Test removing all ratchets and sending a message', () async {
     const aliceJid = 'alice@server1';
    const bobJid = 'bob@server2';

    final aliceDevice = await OmemoDevice.generateNewDevice(aliceJid, opkAmount: 1);
    final bobDevice = await OmemoDevice.generateNewDevice(bobJid, opkAmount: 1);

    final aliceManager = OmemoManager(
      aliceDevice,
      AlwaysTrustingTrustManager(),
      (result, recipientJid) async {},
      (jid) async {
        expect(jid, bobJid);

        return [bobDevice.id];
      },
      (jid, id) async {
        expect(jid, bobJid);

        return bobDevice.toBundle();
      },
      (jid) async {},
    );
    final bobManager = OmemoManager(
      bobDevice,
      AlwaysTrustingTrustManager(),
      (result, recipientJid) async {},
      (jid) async => null,
      (jid, id) async => null,
      (jid) async {},
    );

    // Alice encrypts a message for Bob
    final aliceResult1 = await aliceManager.onOutgoingStanza(
      const OmemoOutgoingStanza(
        [bobJid],
        'Hello Bob!',
      ),
    );

    // And Bob decrypts it
    await bobManager.onIncomingStanza(
      OmemoIncomingStanza(
        aliceJid,
        aliceDevice.id,
        DateTime.now().millisecondsSinceEpoch,
        aliceResult1.encryptedKeys,
        base64.encode(aliceResult1.ciphertext!),
      ),
    );

    // Ratchets are acked
    await aliceManager.ratchetAcknowledged(
      bobJid,
      bobDevice.id,
    );

    // Alice now removes all ratchets for Bob and sends another new message
    await aliceManager.removeAllRatchets(bobJid);

    expect(aliceManager.getRatchet(RatchetMapKey(bobJid, bobDevice.id)), null);

    final aliceResult2 = await aliceManager.onOutgoingStanza(
      const OmemoOutgoingStanza(
        [bobJid],
        'I did not trust your last device, Bob!',
      ),
    );

    // Bob decrypts it
    final bobResult2 = await bobManager.onIncomingStanza(
      OmemoIncomingStanza(
        aliceJid,
        aliceDevice.id,
        DateTime.now().millisecondsSinceEpoch,
        aliceResult2.encryptedKeys,
        base64.encode(aliceResult2.ciphertext!),
      ),
    );

    expect(bobResult2.payload, 'I did not trust your last device, Bob!');
  });
}
