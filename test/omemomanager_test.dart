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
}
