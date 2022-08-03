// ignore_for_file: avoid_print
import 'dart:convert';
import 'package:cryptography/cryptography.dart';
import 'package:omemo_dart/omemo_dart.dart';
import 'package:omemo_dart/protobuf/schema.pb.dart';
import 'package:omemo_dart/src/double_ratchet/crypto.dart';
import 'package:test/test.dart';

void main() {
  test('Test encrypting and decrypting', () async {
    final sessionAd = List<int>.filled(32, 0x0);
    final mk = List<int>.filled(32, 0x1);
    final plaintext = utf8.encode('Hallo');
    final header = OMEMOMessage()
      ..n = 0
      ..pn = 0
      ..dhPub = List<int>.empty();
    final asd = concat([sessionAd, header.writeToBuffer()]);
      
    final ciphertext = await encrypt(
      mk,
      plaintext,
      asd,
      sessionAd,
    );

    final decrypted = await decrypt(
      mk,
      ciphertext,
      asd,
      sessionAd,
    );

    expect(decrypted, plaintext);
  });

  test('Test the Double Ratchet', () async {
    // Generate keys
    final ikAlice = await OmemoKeyPair.generateNewPair(KeyPairType.ed25519);
    final ikBob = await OmemoKeyPair.generateNewPair(KeyPairType.ed25519);
    final spkBob = await OmemoKeyPair.generateNewPair(KeyPairType.x25519);
    final opkBob = await OmemoKeyPair.generateNewPair(KeyPairType.x25519);
    final bundleBob = OmemoBundle(
      '1',
      await spkBob.pk.asBase64(),
      '3',
      base64Encode(
        await sig(ikBob, await spkBob.pk.getBytes()),
      ),
      //'Q5in+/L4kJixEX692h6mJkPMyp4I3SlQ84L0E7ipPzqfPHOMiraUlqG2vG/O8wvFjLsKYZpPBraga9IvwhqVDA==',
      await ikBob.pk.asBase64(),
      {
        '2': await opkBob.pk.asBase64(),
      },
    );
    
    // Alice does X3DH
    final resultAlice = await x3dhFromBundle(bundleBob, ikAlice);

    // Alice sends the inital message to Bob
    // ...
    
    // Bob does X3DH
    final resultBob = await x3dhFromInitialMessage(
      X3DHMessage(
        ikAlice.pk,
        resultAlice.ek.pk,
        '2',
      ),
      spkBob,
      opkBob,
      ikBob,
    );

    print('X3DH key exchange done');

    // Alice and Bob now share sk as a common secret and ad
    final alicesRatchet = await OmemoDoubleRatchet.initiateNewSession(
      spkBob.pk,
      resultAlice.sk,
      resultAlice.ad,
    );
    final bobsRatchet = await OmemoDoubleRatchet.acceptNewSession(
      spkBob,
      resultBob.sk,
      resultBob.ad,
    );

    expect(alicesRatchet.sessionAd, bobsRatchet.sessionAd);
    //expect(await alicesRatchet.dhr.getBytes(), await ikBob.pk.getBytes());
    
    // Alice encrypts a message
    final aliceRatchetResult1 = await alicesRatchet.ratchetEncrypt(utf8.encode('Hello Bob'));
    print('Alice sent the message');

    // Alice sends it to Bob
    // ...

    // Bob tries to decrypt it
    final bobRatchetResult1 = await bobsRatchet.ratchetDecrypt(
      aliceRatchetResult1.header,
      aliceRatchetResult1.ciphertext,
    );
    print('Bob decrypted the message');

    expect(utf8.encode('Hello Bob'), bobRatchetResult1);

    // Bob sends a message to Alice
    final bobRatchetResult2 = await bobsRatchet.ratchetEncrypt(utf8.encode('Hello Alice'));
    print('Bob sent the message');

    // Bobs sends it to Alice
    // ...

    // Alice tries to decrypt it
    final aliceRatchetResult2 = await alicesRatchet.ratchetDecrypt(
      bobRatchetResult2.header,
      bobRatchetResult2.ciphertext,
    );
    print('Alice decrypted the message');

    expect(utf8.encode('Hello Alice'), aliceRatchetResult2);
  });
}
