import 'dart:convert';
import 'package:collection/collection.dart';
import 'package:logging/logging.dart';
import 'package:omemo_dart/omemo_dart.dart';
import 'package:omemo_dart/src/protobuf/schema.pb.dart';
import 'package:omemo_dart/src/trust/always.dart';
import 'package:test/test.dart';

class TestingTrustManager extends AlwaysTrustingTrustManager {
  final Map<String, int> devices = {};

  @override
  Future<void> onNewSession(String jid, int deviceId) async {
    devices[jid] = deviceId;
  }
}

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

    final aliceDevice =
        await OmemoDevice.generateNewDevice(aliceJid, opkAmount: 1);
    final bobDevice = await OmemoDevice.generateNewDevice(bobJid, opkAmount: 1);

    final aliceManager = OmemoManager(
      aliceDevice,
      AlwaysTrustingTrustManager(),
      (result, recipientJid) async {
        aliceEmptyMessageSent++;
      },
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
        aliceResult.encryptedKeys[bobJid]!,
        base64.encode(aliceResult.ciphertext!),
        false,
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
        bobResult2.encryptedKeys[aliceJid]!,
        base64.encode(bobResult2.ciphertext!),
        false,
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

    final aliceDevice =
        await OmemoDevice.generateNewDevice(aliceJid, opkAmount: 1);
    final bobDevice = await OmemoDevice.generateNewDevice(bobJid, opkAmount: 1);

    EncryptionResult? bobEmptyMessage;
    final aliceManager = OmemoManager(
      aliceDevice,
      AlwaysTrustingTrustManager(),
      (result, recipientJid) async {
        aliceEmptyMessageSent++;
      },
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
      (result, recipientJid) async {
        bobEmptyMessageSent++;
        bobEmptyMessage = result;
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
        aliceResult.encryptedKeys[bobJid]!,
        base64.encode(aliceResult.ciphertext!),
        false,
      ),
    );

    expect(aliceEmptyMessageSent, 0);
    expect(bobEmptyMessageSent, 1);
    expect(bobResult.payload, 'Hello world');

    // Bob acknowledges the message
    await aliceManager.onIncomingStanza(
      OmemoIncomingStanza(
        bobJid,
        bobDevice.id,
        getTimestamp(),
        bobEmptyMessage!.encryptedKeys[aliceJid]!,
        null,
        false,
      ),
    );

    // Alice now sends 52 messages that Bob decrypts
    for (var i = 0; i < 52; i++) {
      Logger.root.finest('${i + 1}/52');
      final aliceResultLoop = await aliceManager.onOutgoingStanza(
        OmemoOutgoingStanza(
          [bobJid],
          'Test message $i',
        ),
      );

      expect(aliceResultLoop.encryptedKeys[bobJid]!.first.kex, isFalse);

      final bobResultLoop = await bobManager.onIncomingStanza(
        OmemoIncomingStanza(
          aliceJid,
          aliceDevice.id,
          DateTime.now().millisecondsSinceEpoch,
          aliceResultLoop.encryptedKeys[bobJid]!,
          base64.encode(aliceResultLoop.ciphertext!),
          false,
        ),
      );

      expect(bobResultLoop.error, null);
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
        aliceResultFinal.encryptedKeys[bobJid]!,
        base64.encode(aliceResultFinal.ciphertext!),
        false,
      ),
    );

    expect(aliceEmptyMessageSent, 0);
    expect(bobEmptyMessageSent, 2);
    expect(bobResultFinal.payload, 'Test message last');

    // Alice receives it and sends another message
    final aliceResultPostFinal = await aliceManager.onIncomingStanza(
      OmemoIncomingStanza(
        bobJid,
        bobDevice.id,
        getTimestamp(),
        bobEmptyMessage!.encryptedKeys[aliceJid]!,
        null,
        false,
      ),
    );
    expect(aliceResultPostFinal.error, null);
    final aliceMessagePostFinal = await aliceManager.onOutgoingStanza(
      const OmemoOutgoingStanza(
        [bobJid],
        "I'm not done yet!",
      ),
    );

    // And Bob decrypts it
    final bobResultPostFinal = await bobManager.onIncomingStanza(
      OmemoIncomingStanza(
        aliceJid,
        aliceDevice.id,
        getTimestamp(),
        aliceMessagePostFinal.encryptedKeys[bobJid]!,
        base64Encode(aliceMessagePostFinal.ciphertext!),
        false,
      ),
    );

    expect(bobResultPostFinal.error, null);
    expect(bobResultPostFinal.payload, "I'm not done yet!");
    expect(aliceEmptyMessageSent, 0);
    expect(bobEmptyMessageSent, 2);
  });

  test('Test accessing data without it existing', () async {
    const aliceJid = 'alice@server1';
    const bobJid = 'bob@server2';
    final aliceDevice =
        await OmemoDevice.generateNewDevice(aliceJid, opkAmount: 1);

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

    final aliceDevice =
        await OmemoDevice.generateNewDevice(aliceJid, opkAmount: 1);
    final bobOldDevice =
        await OmemoDevice.generateNewDevice(bobJid, opkAmount: 1);
    final bobCurrentDevice =
        await OmemoDevice.generateNewDevice(bobJid, opkAmount: 1);

    final aliceManager = OmemoManager(
      aliceDevice,
      AlwaysTrustingTrustManager(),
      (result, recipientJid) async {},
      (jid) async {
        expect(jid, bobJid);

        return oldDevice ? [bobOldDevice.id] : [bobCurrentDevice.id];
      },
      (jid, id) async {
        expect(jid, bobJid);
        return oldDevice
            ? bobOldDevice.toBundle()
            : bobCurrentDevice.toBundle();
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
        aliceResult1.encryptedKeys[bobJid]!,
        base64.encode(aliceResult1.ciphertext!),
        false,
      ),
    );

    expect(bobResult1.payload, null);
    expect(bobResult1.error, const TypeMatcher<NotEncryptedForDeviceError>());

    // Now Alice's client loses and regains the connection
    await aliceManager.onNewConnection();
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
        aliceResult2.encryptedKeys[bobJid]!,
        base64.encode(aliceResult2.ciphertext!),
        false,
      ),
    );

    expect(aliceResult2.encryptedKeys.length, 1);
    expect(bobResult2.error, null);
    expect(bobResult2.payload, 'Hello Bob x2');
  });

  test('Test receiving a response from a new device', () async {
    const aliceJid = 'alice@server1';
    const bobJid = 'bob@server2';
    var bothDevices = false;

    final aliceDevice =
        await OmemoDevice.generateNewDevice(aliceJid, opkAmount: 1);
    final bobDevice1 =
        await OmemoDevice.generateNewDevice(bobJid, opkAmount: 1);
    final bobDevice2 =
        await OmemoDevice.generateNewDevice(bobJid, opkAmount: 1);

    final aliceManager = OmemoManager(
      aliceDevice,
      AlwaysTrustingTrustManager(),
      (result, recipientJid) async {},
      (jid) async {
        expect(jid, bobJid);

        return [
          bobDevice1.id,
          if (bothDevices) bobDevice2.id,
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
        aliceResult1.encryptedKeys[bobJid]!,
        base64.encode(aliceResult1.ciphertext!),
        false,
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
        bobResult2.encryptedKeys[aliceJid]!,
        base64.encode(bobResult2.ciphertext!),
        false,
      ),
    );

    expect(aliceResult2.payload, 'Hello from my new device');
  });

  test('Test receiving a device list update', () async {
    const aliceJid = 'alice@server1';
    const bobJid = 'bob@server2';
    var bothDevices = false;

    final aliceDevice =
        await OmemoDevice.generateNewDevice(aliceJid, opkAmount: 1);
    final bobDevice1 =
        await OmemoDevice.generateNewDevice(bobJid, opkAmount: 1);
    final bobDevice2 =
        await OmemoDevice.generateNewDevice(bobJid, opkAmount: 1);

    final aliceManager = OmemoManager(
      aliceDevice,
      AlwaysTrustingTrustManager(),
      (result, recipientJid) async {},
      (jid) async {
        expect(jid, bobJid);

        return [
          bobDevice1.id,
          if (bothDevices) bobDevice2.id,
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
        aliceResult1.encryptedKeys[bobJid]!,
        base64.encode(aliceResult1.ciphertext!),
        false,
      ),
    );

    expect(aliceResult1.encryptedKeys.length, 1);
    expect(bobResult1.payload, 'Hello Bob!');

    // Bob acks the ratchet session
    await aliceManager.ratchetAcknowledged(bobJid, bobDevice1.id);

    // Bob now publishes a new device
    bothDevices = true;
    await aliceManager.onDeviceListUpdate(
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

    expect(aliceResult2.encryptedKeys[bobJid]!.length, 2);

    // And Bob decrypts it
    final bobResult21 = await bobManager1.onIncomingStanza(
      OmemoIncomingStanza(
        aliceJid,
        aliceDevice.id,
        DateTime.now().millisecondsSinceEpoch,
        aliceResult2.encryptedKeys[bobJid]!,
        base64.encode(aliceResult2.ciphertext!),
        false,
      ),
    );
    final bobResult22 = await bobManager2.onIncomingStanza(
      OmemoIncomingStanza(
        aliceJid,
        aliceDevice.id,
        DateTime.now().millisecondsSinceEpoch,
        aliceResult2.encryptedKeys[bobJid]!,
        base64.encode(aliceResult2.ciphertext!),
        false,
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
        bobResult32.encryptedKeys[aliceJid]!,
        base64.encode(bobResult32.ciphertext!),
        false,
      ),
    );

    expect(aliceResult3.payload, 'Hello Alice!');
  });

  test('Test sending a message to two different JIDs', () async {
    const aliceJid = 'alice@server1';
    const bobJid = 'bob@server2';
    const cocoJid = 'coco@server3';

    final aliceDevice =
        await OmemoDevice.generateNewDevice(aliceJid, opkAmount: 1);
    final bobDevice = await OmemoDevice.generateNewDevice(bobJid, opkAmount: 1);
    final cocoDevice =
        await OmemoDevice.generateNewDevice(cocoJid, opkAmount: 1);

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
        aliceResult.encryptedKeys[bobJid]!,
        base64.encode(aliceResult.ciphertext!),
        false,
      ),
    );
    final cocoResult = await cocoManager.onIncomingStanza(
      OmemoIncomingStanza(
        aliceJid,
        aliceDevice.id,
        DateTime.now().millisecondsSinceEpoch,
        aliceResult.encryptedKeys[cocoJid]!,
        base64.encode(aliceResult.ciphertext!),
        false,
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

    final aliceDevice =
        await OmemoDevice.generateNewDevice(aliceJid, opkAmount: 1);
    final bobDevice = await OmemoDevice.generateNewDevice(bobJid, opkAmount: 1);

    final aliceManager = OmemoManager(
      aliceDevice,
      AlwaysTrustingTrustManager(),
      (result, recipientJid) async {},
      (jid) async {
        expect(jid, bobJid);

        return failure ? null : [bobDevice.id];
      },
      (jid, id) async {
        expect(jid, bobJid);

        return failure ? null : bobDevice.toBundle();
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
        aliceResult1.encryptedKeys[bobJid]!,
        base64.encode(aliceResult1.ciphertext!),
        false,
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
    await aliceManager.onNewConnection();

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
        aliceResult2.encryptedKeys[bobJid]!,
        base64.encode(aliceResult2.ciphertext!),
        false,
      ),
    );

    expect(bobResult2.error, null);
    expect(bobResult2.payload, 'Hello Bob! x2');
  });

  test('Test sending a message with failed lookups', () async {
    const aliceJid = 'alice@server1';
    const bobJid = 'bob@server2';

    final aliceDevice =
        await OmemoDevice.generateNewDevice(aliceJid, opkAmount: 1);

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

    expect(aliceResult.isSuccess(1), isFalse);
    expect(aliceResult.deviceEncryptionErrors[bobJid]!.length, 1);
    final error = aliceResult.deviceEncryptionErrors[bobJid]!.first;
    expect(error.error, const TypeMatcher<NoKeyMaterialAvailableError>());
  });

  test('Test sending a message two two JIDs with failed lookups', () async {
    const aliceJid = 'alice@server1';
    const bobJid = 'bob@server2';
    const cocoJid = 'coco@server3';

    final aliceDevice =
        await OmemoDevice.generateNewDevice(aliceJid, opkAmount: 1);
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

    expect(aliceResult.isSuccess(2), isFalse);
    expect(aliceResult.deviceEncryptionErrors[cocoJid]!.length, 1);
    expect(
      aliceResult.deviceEncryptionErrors[cocoJid]!.first.error,
      const TypeMatcher<NoKeyMaterialAvailableError>(),
    );

    // Bob decrypts it
    final bobResult = await bobManager.onIncomingStanza(
      OmemoIncomingStanza(
        aliceJid,
        aliceDevice.id,
        DateTime.now().millisecondsSinceEpoch,
        aliceResult.encryptedKeys[bobJid]!,
        base64.encode(aliceResult.ciphertext!),
        false,
      ),
    );

    expect(bobResult.payload, 'Hello Bob and Coco!');
  });

  test('Test sending multiple messages back and forth', () async {
    const aliceJid = 'alice@server1';
    const bobJid = 'bob@server2';

    final aliceDevice =
        await OmemoDevice.generateNewDevice(aliceJid, opkAmount: 1);
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
        aliceMessage.encryptedKeys[bobJid]!,
        base64.encode(aliceMessage.ciphertext!),
        false,
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
      expect(bobResponseMessage.isSuccess(1), isTrue);

      final aliceReceivedMessage = await aliceManager.onIncomingStanza(
        OmemoIncomingStanza(
          bobJid,
          bobDevice.id,
          DateTime.now().millisecondsSinceEpoch,
          bobResponseMessage.encryptedKeys[aliceJid]!,
          base64.encode(bobResponseMessage.ciphertext!),
          false,
        ),
      );
      expect(aliceReceivedMessage.payload, messageText);
    }
  });

  test('Test removing all ratchets and sending a message', () async {
    const aliceJid = 'alice@server1';
    const bobJid = 'bob@server2';

    final aliceDevice =
        await OmemoDevice.generateNewDevice(aliceJid, opkAmount: 1);
    final bobDevice = await OmemoDevice.generateNewDevice(bobJid, opkAmount: 1);

    EncryptionResult? aliceEmptyMessage;
    final aliceManager = OmemoManager(
      aliceDevice,
      AlwaysTrustingTrustManager(),
      (result, recipientJid) async {
        aliceEmptyMessage = result;
      },
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
        aliceResult1.encryptedKeys[bobJid]!,
        base64.encode(aliceResult1.ciphertext!),
        false,
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

    // Alice prepares an empty OMEMO message
    await aliceManager.sendOmemoHeartbeat(bobJid);

    // And Bob receives it
    final bobResult2 = await bobManager.onIncomingStanza(
      OmemoIncomingStanza(
        aliceJid,
        await aliceManager.getDeviceId(),
        DateTime.now().millisecondsSinceEpoch,
        aliceEmptyMessage!.encryptedKeys[bobJid]!,
        null,
        false,
      ),
    );
    expect(bobResult2.error, null);

    // Bob acks the new ratchet
    await aliceManager.ratchetAcknowledged(
      bobJid,
      await bobManager.getDeviceId(),
    );

    // Alice sends another message
    final aliceResult3 = await aliceManager.onOutgoingStanza(
      const OmemoOutgoingStanza(
        [bobJid],
        'I did not trust your last device, Bob!',
      ),
    );

    // Bob decrypts it
    final bobResult3 = await bobManager.onIncomingStanza(
      OmemoIncomingStanza(
        aliceJid,
        aliceDevice.id,
        DateTime.now().millisecondsSinceEpoch,
        aliceResult3.encryptedKeys[bobJid]!,
        base64.encode(aliceResult3.ciphertext!),
        false,
      ),
    );

    expect(bobResult3.error, null);
    expect(bobResult3.payload, 'I did not trust your last device, Bob!');

    // Bob responds
    final bobResult4 = await bobManager.onOutgoingStanza(
      const OmemoOutgoingStanza(
        [aliceJid],
        "That's okay.",
      ),
    );

    // Alice decrypts
    final aliceResult4 = await aliceManager.onIncomingStanza(
      OmemoIncomingStanza(
        bobJid,
        bobDevice.id,
        DateTime.now().millisecondsSinceEpoch,
        bobResult4.encryptedKeys[aliceJid]!,
        base64.encode(bobResult4.ciphertext!),
        false,
      ),
    );

    expect(aliceResult4.error, null);
    expect(aliceResult4.payload, "That's okay.");
  });

  test(
      'Test removing all ratchets and sending a message without post-heartbeat ack',
      () async {
    // This test is the same as "Test removing all ratchets and sending a message" except
    // that Bob does not ack the ratchet after Alice's heartbeat after she recreated
    // all ratchets.
    const aliceJid = 'alice@server1';
    const bobJid = 'bob@server2';

    final aliceDevice =
        await OmemoDevice.generateNewDevice(aliceJid, opkAmount: 1);
    final bobDevice = await OmemoDevice.generateNewDevice(bobJid, opkAmount: 1);

    EncryptionResult? aliceEmptyMessage;
    final aliceManager = OmemoManager(
      aliceDevice,
      AlwaysTrustingTrustManager(),
      (result, recipientJid) async {
        aliceEmptyMessage = result;
      },
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
    final bobResult1 = await bobManager.onIncomingStanza(
      OmemoIncomingStanza(
        aliceJid,
        aliceDevice.id,
        DateTime.now().millisecondsSinceEpoch,
        aliceResult1.encryptedKeys[bobJid]!,
        base64.encode(aliceResult1.ciphertext!),
        false,
      ),
    );
    expect(bobResult1.error, isNull);

    // Ratchets are acked
    await aliceManager.ratchetAcknowledged(
      bobJid,
      bobDevice.id,
    );

    // Alice now removes all ratchets for Bob and sends another new message
    Logger.root.info('Removing all ratchets for $bobJid');
    await aliceManager.removeAllRatchets(bobJid);

    expect(
      aliceManager.getRatchet(RatchetMapKey(bobJid, bobDevice.id)),
      isNull,
    );

    // Alice prepares an empty OMEMO message
    await aliceManager.sendOmemoHeartbeat(bobJid);

    // And Bob receives it
    final bobResult2 = await bobManager.onIncomingStanza(
      OmemoIncomingStanza(
        aliceJid,
        await aliceManager.getDeviceId(),
        DateTime.now().millisecondsSinceEpoch,
        aliceEmptyMessage!.encryptedKeys[bobJid]!,
        null,
        false,
      ),
    );
    expect(bobResult2.error, null);

    // Alice sends another message
    Logger.root.info('Sending final message');
    final aliceResult3 = await aliceManager.onOutgoingStanza(
      const OmemoOutgoingStanza(
        [bobJid],
        'I did not trust your last device, Bob!',
      ),
    );
    expect(aliceResult3.encryptedKeys[bobJid]!.first.kex, isTrue);

    // Bob decrypts it
    final bobResult3 = await bobManager.onIncomingStanza(
      OmemoIncomingStanza(
        aliceJid,
        aliceDevice.id,
        DateTime.now().millisecondsSinceEpoch,
        aliceResult3.encryptedKeys[bobJid]!,
        base64.encode(aliceResult3.ciphertext!),
        false,
      ),
    );

    expect(bobResult3.error, null);
    expect(bobResult3.payload, 'I did not trust your last device, Bob!');

    // Bob responds
    final bobResult4 = await bobManager.onOutgoingStanza(
      const OmemoOutgoingStanza(
        [aliceJid],
        "That's okay.",
      ),
    );

    // Alice decrypts
    final aliceResult4 = await aliceManager.onIncomingStanza(
      OmemoIncomingStanza(
        bobJid,
        bobDevice.id,
        DateTime.now().millisecondsSinceEpoch,
        bobResult4.encryptedKeys[aliceJid]!,
        base64.encode(bobResult4.ciphertext!),
        false,
      ),
    );

    expect(aliceResult4.error, null);
    expect(aliceResult4.payload, "That's okay.");
  });

  test('Test resending key exchanges', () async {
    const aliceJid = 'alice@server1';
    const bobJid = 'bob@server2';

    final aliceDevice =
        await OmemoDevice.generateNewDevice(aliceJid, opkAmount: 1);
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

    // Alice sends Bob a message
    final aliceResult1 = await aliceManager.onOutgoingStanza(
      const OmemoOutgoingStanza(
        [bobJid],
        'Hello World!',
      ),
    );

    // The first message must be a KEX message
    expect(aliceResult1.encryptedKeys[bobJid]!.first.kex, isTrue);

    // Bob decrypts Alice's message
    final bobResult1 = await bobManager.onIncomingStanza(
      OmemoIncomingStanza(
        aliceJid,
        aliceDevice.id,
        DateTime.now().millisecondsSinceEpoch,
        aliceResult1.encryptedKeys[bobJid]!,
        base64.encode(aliceResult1.ciphertext!),
        false,
      ),
    );
    expect(bobResult1.error, null);
    expect(bobResult1.payload, 'Hello World!');

    // Alice immediately sends another message
    final aliceResult2 = await aliceManager.onOutgoingStanza(
      const OmemoOutgoingStanza(
        [bobJid],
        'Hello Bob',
      ),
    );

    // The response should contain a KEX
    expect(aliceResult2.encryptedKeys[bobJid]!.first.kex, isTrue);

    // The basic data should be the same
    final parsedFirstKex = OMEMOKeyExchange.fromBuffer(
      base64.decode(aliceResult1.encryptedKeys[bobJid]!.first.value),
    );
    final parsedSecondKex = OMEMOKeyExchange.fromBuffer(
      base64.decode(aliceResult2.encryptedKeys[bobJid]!.first.value),
    );
    expect(parsedSecondKex.pkId, parsedFirstKex.pkId);
    expect(parsedSecondKex.spkId, parsedFirstKex.spkId);
    expect(parsedSecondKex.ik, parsedFirstKex.ik);
    expect(parsedSecondKex.ek, parsedFirstKex.ek);

    // Bob decrypts it
    final bobResult2 = await bobManager.onIncomingStanza(
      OmemoIncomingStanza(
        aliceJid,
        aliceDevice.id,
        DateTime.now().millisecondsSinceEpoch,
        aliceResult2.encryptedKeys[bobJid]!,
        base64.encode(aliceResult2.ciphertext!),
        false,
      ),
    );
    expect(bobResult2.error, null);
    expect(bobResult2.payload, 'Hello Bob');

    // Bob also sends a message
    final bobResult3 = await bobManager.onOutgoingStanza(
      const OmemoOutgoingStanza(
        [aliceJid],
        'Hello Alice!',
      ),
    );

    // Alice decrypts it
    final aliceResult3 = await aliceManager.onIncomingStanza(
      OmemoIncomingStanza(
        bobJid,
        bobDevice.id,
        DateTime.now().millisecondsSinceEpoch,
        bobResult3.encryptedKeys[aliceJid]!,
        base64.encode(bobResult3.ciphertext!),
        false,
      ),
    );
    expect(aliceResult3.error, null);
    expect(aliceResult3.payload, 'Hello Alice!');

    // Bob now acks the ratchet
    await aliceManager.ratchetAcknowledged(
      bobJid,
      bobDevice.id,
    );

    // Alice replies
    final aliceResult4 = await aliceManager.onOutgoingStanza(
      const OmemoOutgoingStanza(
        [bobJid],
        'Hi Bob',
      ),
    );

    // The response should contain no KEX
    expect(aliceResult4.encryptedKeys[bobJid]!.first.kex, isFalse);

    // Bob decrypts it
    final bobResult4 = await bobManager.onIncomingStanza(
      OmemoIncomingStanza(
        aliceJid,
        aliceDevice.id,
        DateTime.now().millisecondsSinceEpoch,
        aliceResult4.encryptedKeys[bobJid]!,
        base64.encode(aliceResult4.ciphertext!),
        false,
      ),
    );
    expect(bobResult4.error, null);
    expect(bobResult4.payload, 'Hi Bob');
  });

  test('Test correct trust behaviour on receiving', () async {
    const aliceJid = 'alice@server1';
    const bobJid = 'bob@server2';

    final aliceDevice =
        await OmemoDevice.generateNewDevice(aliceJid, opkAmount: 1);
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
      TestingTrustManager(),
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

    // Alice sends Bob a message
    final aliceResult1 = await aliceManager.onOutgoingStanza(
      const OmemoOutgoingStanza(
        [bobJid],
        'Hello World!',
      ),
    );

    // Bob decrypts Alice's message
    final bobResult1 = await bobManager.onIncomingStanza(
      OmemoIncomingStanza(
        aliceJid,
        aliceDevice.id,
        DateTime.now().millisecondsSinceEpoch,
        aliceResult1.encryptedKeys[bobJid]!,
        base64.encode(aliceResult1.ciphertext!),
        false,
      ),
    );
    expect(bobResult1.error, null);

    // Bob should have some trust state
    expect(
      (bobManager.trustManager as TestingTrustManager).devices[aliceJid],
      await aliceManager.getDeviceId(),
    );
  });

  test('Test receiving a non-KEX from a new device', () async {
    const aliceJid = 'alice@server1';
    const bobJid = 'bob@server2';

    final aliceDevice1 =
        await OmemoDevice.generateNewDevice(aliceJid, opkAmount: 1);
    final aliceDevice2 =
        await OmemoDevice.generateNewDevice(aliceJid, opkAmount: 1);
    final bobDevice = await OmemoDevice.generateNewDevice(bobJid, opkAmount: 1);

    final aliceManager1 = OmemoManager(
      aliceDevice1,
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
    final aliceManager2 = OmemoManager(
      aliceDevice2,
      TestingTrustManager(),
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

    EncryptionResult? bobEmptyMessage;
    var includeAlice2 = false;
    final bobManager = OmemoManager(
      bobDevice,
      TestingTrustManager(),
      (result, recipientJid) async {
        bobEmptyMessage = result;
      },
      (jid) async {
        expect(jid, aliceJid);
        return [
          aliceDevice1.id,
          if (includeAlice2) aliceDevice2.id,
        ];
      },
      (jid, id) async {
        expect(jid, aliceJid);

        if (id == aliceDevice1.id) {
          return aliceDevice1.toBundle();
        } else if (id == aliceDevice2.id) {
          return aliceDevice2.toBundle();
        }

        return null;
      },
      (jid) async {},
    );

    // Alice sends Bob a message
    final aliceResult1 = await aliceManager1.onOutgoingStanza(
      const OmemoOutgoingStanza(
        [bobJid],
        'Hello World!',
      ),
    );

    // Bob decrypts Alice's message
    final bobResult1 = await bobManager.onIncomingStanza(
      OmemoIncomingStanza(
        aliceJid,
        aliceDevice1.id,
        DateTime.now().millisecondsSinceEpoch,
        aliceResult1.encryptedKeys[bobJid]!,
        base64.encode(aliceResult1.ciphertext!),
        false,
      ),
    );
    expect(bobResult1.error, null);
    expect(bobEmptyMessage, isNotNull);

    // Somehow create a non-KEX message without Bob creating a ratchet
    await aliceManager2.onOutgoingStanza(
      const OmemoOutgoingStanza([bobJid], 'lol'),
    );
    await aliceManager2.ratchetAcknowledged(bobJid, bobDevice.id);
    final aliceResult2 = await aliceManager2.onOutgoingStanza(
      const OmemoOutgoingStanza([bobJid], 'lol x2'),
    );

    // Bob decrypts it and fails, but builds a session with the new device
    bobEmptyMessage = null;
    includeAlice2 = true;
    final bobResult2 = await bobManager.onIncomingStanza(
      OmemoIncomingStanza(
        aliceJid,
        aliceDevice2.id,
        getTimestamp(),
        aliceResult2.encryptedKeys[bobJid]!,
        base64Encode(aliceResult2.ciphertext!),
        false,
      ),
    );
    expect(bobResult2.error, const TypeMatcher<NoSessionWithDeviceError>());
    expect(bobEmptyMessage, isNotNull);

    // Check that the empty message is encrypted for both of Alice's devices
    expect(
      bobEmptyMessage!.encryptedKeys[aliceJid]!
          .firstWhereOrNull((key) => key.rid == aliceDevice1.id),
      isNotNull,
    );
    expect(
      bobEmptyMessage!.encryptedKeys[aliceJid]!
          .firstWhereOrNull((key) => key.rid == aliceDevice1.id),
      isNotNull,
    );
  });

  test(
      'Test receiving a non-KEX from a new device without device list inclusion',
      () async {
    const aliceJid = 'alice@server1';
    const bobJid = 'bob@server2';

    final aliceDevice1 =
        await OmemoDevice.generateNewDevice(aliceJid, opkAmount: 1);
    final aliceDevice2 =
        await OmemoDevice.generateNewDevice(aliceJid, opkAmount: 1);
    final bobDevice = await OmemoDevice.generateNewDevice(bobJid, opkAmount: 1);

    final aliceManager1 = OmemoManager(
      aliceDevice1,
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
    final aliceManager2 = OmemoManager(
      aliceDevice2,
      TestingTrustManager(),
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

    EncryptionResult? bobEmptyMessage;
    final bobManager = OmemoManager(
      bobDevice,
      TestingTrustManager(),
      (result, recipientJid) async {
        bobEmptyMessage = result;
      },
      (jid) async {
        expect(jid, aliceJid);
        return [
          aliceDevice1.id,
        ];
      },
      (jid, id) async {
        expect(jid, aliceJid);

        if (id == aliceDevice1.id) {
          return aliceDevice1.toBundle();
        } else if (id == aliceDevice2.id) {
          return aliceDevice2.toBundle();
        }

        return null;
      },
      (jid) async {},
    );

    // Alice sends Bob a message
    final aliceResult1 = await aliceManager1.onOutgoingStanza(
      const OmemoOutgoingStanza(
        [bobJid],
        'Hello World!',
      ),
    );

    // Bob decrypts Alice's message
    final bobResult1 = await bobManager.onIncomingStanza(
      OmemoIncomingStanza(
        aliceJid,
        aliceDevice1.id,
        DateTime.now().millisecondsSinceEpoch,
        aliceResult1.encryptedKeys[bobJid]!,
        base64.encode(aliceResult1.ciphertext!),
        false,
      ),
    );
    expect(bobResult1.error, null);
    expect(bobEmptyMessage, isNotNull);

    // Somehow create a non-KEX message without Bob creating a ratchet
    await aliceManager2.onOutgoingStanza(
      const OmemoOutgoingStanza([bobJid], 'lol'),
    );
    await aliceManager2.ratchetAcknowledged(bobJid, bobDevice.id);
    final aliceResult2 = await aliceManager2.onOutgoingStanza(
      const OmemoOutgoingStanza([bobJid], 'lol x2'),
    );

    // Bob decrypts it and fails, but builds a session with the new device
    bobEmptyMessage = null;
    final bobResult2 = await bobManager.onIncomingStanza(
      OmemoIncomingStanza(
        aliceJid,
        aliceDevice2.id,
        getTimestamp(),
        aliceResult2.encryptedKeys[bobJid]!,
        base64Encode(aliceResult2.ciphertext!),
        false,
      ),
    );
    expect(bobResult2.error, const TypeMatcher<NoSessionWithDeviceError>());
    expect(bobEmptyMessage, isNotNull);

    // Check that the empty message is encrypted for both of Alice's devices
    expect(
      bobEmptyMessage!.encryptedKeys[aliceJid]!
          .firstWhereOrNull((key) => key.rid == aliceDevice1.id),
      isNotNull,
    );
    expect(
      bobEmptyMessage!.encryptedKeys[aliceJid]!
          .firstWhereOrNull((key) => key.rid == aliceDevice1.id),
      isNotNull,
    );
  });
}
