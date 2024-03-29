import 'dart:convert';
import 'dart:developer';
import 'package:cryptography/cryptography.dart';
import 'package:omemo_dart/omemo_dart.dart';
import 'package:test/test.dart';

void main() {
  test('Test the Double Ratchet', () async {
    // Generate keys
    const bobJid = 'bob@other.example.server';
    final ikAlice = await OmemoKeyPair.generateNewPair(KeyPairType.ed25519);
    final ikBob = await OmemoKeyPair.generateNewPair(KeyPairType.ed25519);
    final spkBob = await OmemoKeyPair.generateNewPair(KeyPairType.x25519);
    final opkBob = await OmemoKeyPair.generateNewPair(KeyPairType.x25519);
    final bundleBob = OmemoBundle(
      bobJid,
      1,
      await spkBob.pk.asBase64(),
      3,
      base64Encode(
        await sig(ikBob, await spkBob.pk.getBytes()),
      ),
      //'Q5in+/L4kJixEX692h6mJkPMyp4I3SlQ84L0E7ipPzqfPHOMiraUlqG2vG/O8wvFjLsKYZpPBraga9IvwhqVDA==',
      await ikBob.pk.asBase64(),
      {
        2: await opkBob.pk.asBase64(),
      },
    );

    // Alice does X3DH
    final resultAliceRaw = await x3dhFromBundle(bundleBob, ikAlice);
    final resultAlice = resultAliceRaw.get<X3DHAliceResult>();

    // Alice sends the inital message to Bob
    // ...

    // Bob does X3DH
    final resultBob = await x3dhFromInitialMessage(
      X3DHMessage(
        ikAlice.pk,
        resultAlice.ek.pk,
        2,
      ),
      spkBob,
      opkBob,
      ikBob,
    );

    log('X3DH key exchange done');

    // Alice and Bob now share sk as a common secret and ad
    // Build a session
    final alicesRatchet = await OmemoDoubleRatchet.initiateNewSession(
      spkBob.pk,
      bundleBob.spkId,
      ikBob.pk,
      ikAlice.pk,
      resultAlice.ek.pk,
      resultAlice.sk,
      resultAlice.ad,
      resultAlice.opkId,
    );
    final bobsRatchet = await OmemoDoubleRatchet.acceptNewSession(
      spkBob,
      bundleBob.spkId,
      ikAlice.pk,
      2,
      resultAlice.ek.pk,
      resultBob.sk,
      resultBob.ad,
    );

    expect(alicesRatchet.sessionAd, bobsRatchet.sessionAd);

    for (var i = 0; i < 100; i++) {
      final messageText = 'Hello, dear $i';

      log('${i + 1}/100');
      if (i.isEven) {
        // Alice encrypts a message
        final aliceRatchetResult =
            await alicesRatchet.ratchetEncrypt(utf8.encode(messageText));
        log('Alice sent the message');

        // Alice sends it to Bob
        // ...

        // Bob tries to decrypt it
        final bobRatchetResult = await bobsRatchet.ratchetDecrypt(
          aliceRatchetResult,
        );
        log('Bob decrypted the message');

        expect(bobRatchetResult.isType<List<int>>(), true);
        expect(bobRatchetResult.get<List<int>>(), utf8.encode(messageText));
      } else {
        // Bob sends a message to Alice
        final bobRatchetResult =
            await bobsRatchet.ratchetEncrypt(utf8.encode(messageText));
        log('Bob sent the message');

        // Bobs sends it to Alice
        // ...

        // Alice tries to decrypt it
        final aliceRatchetResult = await alicesRatchet.ratchetDecrypt(
          bobRatchetResult,
        );
        log('Alice decrypted the message');

        expect(aliceRatchetResult.isType<List<int>>(), true);
        expect(aliceRatchetResult.get<List<int>>(), utf8.encode(messageText));
        expect(utf8.encode(messageText), aliceRatchetResult.get<List<int>>());
      }
    }
  });
}
