import 'dart:convert';
import 'package:logging/logging.dart';
import 'package:omemo_dart/omemo_dart.dart';
import 'package:omemo_dart/src/omemo/omemomanager.dart' as omemo;
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

    final aliceDevice = await Device.generateNewDevice(aliceJid, opkAmount: 1);
    final bobDevice = await Device.generateNewDevice(bobJid, opkAmount: 1);

    final aliceManager = omemo.OmemoManager(
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
    );
    final bobManager = omemo.OmemoManager(
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
        aliceResult!.encryptedKeys,
        base64.encode(aliceResult.ciphertext!),
      ),
    );

    expect(aliceEmptyMessageSent, 0);
    expect(bobEmptyMessageSent, 1);
    expect(bobResult.payload, 'Hello world');

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
        bobResult2!.encryptedKeys,
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

    final aliceDevice = await Device.generateNewDevice(aliceJid, opkAmount: 1);
    final bobDevice = await Device.generateNewDevice(bobJid, opkAmount: 1);

    final aliceManager = omemo.OmemoManager(
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
    );
    final bobManager = omemo.OmemoManager(
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
        aliceResult!.encryptedKeys,
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
          aliceResultLoop!.encryptedKeys,
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
        aliceResultFinal!.encryptedKeys,
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
    final aliceDevice = await Device.generateNewDevice(aliceJid, opkAmount: 1);

    final aliceManager = omemo.OmemoManager(
      aliceDevice,
      AlwaysTrustingTrustManager(),
      (result, recipientJid) async {},
      (jid) async => [],
      (jid, id) async => null,
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

    final aliceDevice = await Device.generateNewDevice(aliceJid, opkAmount: 1);
    final bobOldDevice = await Device.generateNewDevice(bobJid, opkAmount: 1);
    final bobCurrentDevice = await Device.generateNewDevice(bobJid, opkAmount: 1);

    final aliceManager = omemo.OmemoManager(
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
    );
    final bobManager = omemo.OmemoManager(
      bobCurrentDevice,
      AlwaysTrustingTrustManager(),
      (result, recipientJid) async {},
      (jid) async => [],
      (jid, id) async => null,
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
        aliceResult1!.encryptedKeys,
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
        aliceResult2!.encryptedKeys,
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

    final aliceDevice = await Device.generateNewDevice(aliceJid, opkAmount: 1);
    final bobDevice1 = await Device.generateNewDevice(bobJid, opkAmount: 1);
    final bobDevice2 = await Device.generateNewDevice(bobJid, opkAmount: 1);

    final aliceManager = omemo.OmemoManager(
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
    );
    final bobManager1 = omemo.OmemoManager(
      bobDevice1,
      AlwaysTrustingTrustManager(),
      (result, recipientJid) async {},
      (jid) async => [],
      (jid, id) async => null,
    );
    final bobManager2 = omemo.OmemoManager(
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
        aliceResult1!.encryptedKeys,
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
        bobResult2!.encryptedKeys,
        base64.encode(bobResult2.ciphertext!),
      ),
    );

    expect(aliceResult2.payload, 'Hello from my new device');
  });

  test('Test receiving a device list update', () async {
    const aliceJid = 'alice@server1';
    const bobJid = 'bob@server2';
    var bothDevices = false;

    final aliceDevice = await Device.generateNewDevice(aliceJid, opkAmount: 1);
    final bobDevice1 = await Device.generateNewDevice(bobJid, opkAmount: 1);
    final bobDevice2 = await Device.generateNewDevice(bobJid, opkAmount: 1);

    final aliceManager = omemo.OmemoManager(
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
    );
    final bobManager1 = omemo.OmemoManager(
      bobDevice1,
      AlwaysTrustingTrustManager(),
      (result, recipientJid) async {},
      (jid) async => null,
      (jid, id) async => null,
    );
    final bobManager2 = omemo.OmemoManager(
      bobDevice2,
      AlwaysTrustingTrustManager(),
      (result, recipientJid) async {},
      (jid) async => null,
      (jid, id) async => null,
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
        aliceResult1!.encryptedKeys,
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

    expect(aliceResult2!.encryptedKeys.length, 2);

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
        bobResult32!.encryptedKeys,
        base64.encode(bobResult32.ciphertext!),
      ),
    );

    expect(aliceResult3.payload, 'Hello Alice!');
  });
}
