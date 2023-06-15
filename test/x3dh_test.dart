import 'dart:convert';
import 'package:cryptography/cryptography.dart';
import 'package:omemo_dart/omemo_dart.dart';
import 'package:test/test.dart';

void main() {
  test('X3DH with correct signature', () async {
    // Generate keys
    final ikAlice = await OmemoKeyPair.generateNewPair(KeyPairType.ed25519);
    final ikBob = await OmemoKeyPair.generateNewPair(KeyPairType.ed25519);
    final spkBob = await OmemoKeyPair.generateNewPair(KeyPairType.x25519);
    final opkBob = await OmemoKeyPair.generateNewPair(KeyPairType.x25519);
    final bundleBob = OmemoBundle(
      'alice@some.server',
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

    expect(resultAlice.sk, resultBob.sk);
    expect(resultAlice.ad, resultBob.ad);
  });

  test('X3DH with incorrect signature', () async {
    // Generate keys
    final ikAlice = await OmemoKeyPair.generateNewPair(KeyPairType.ed25519);
    final ikBob = await OmemoKeyPair.generateNewPair(KeyPairType.ed25519);
    final spkBob = await OmemoKeyPair.generateNewPair(KeyPairType.x25519);
    final opkBob = await OmemoKeyPair.generateNewPair(KeyPairType.x25519);
    final bundleBob = OmemoBundle(
      'bob@some.server',
      1,
      await spkBob.pk.asBase64(),
      3,
      // NOTE: A bit flakey, but it is highly unlikely that the same keypair as this one
      //       gets generated.
      'Q5in+/L4kJixEX692h6mJkPMyp4I3SlQ84L0E7ipPzqfPHOMiraUlqG2vG/O8wvFjLsKYZpPBraga9IvwhqVDA==',
      await ikBob.pk.asBase64(),
      {
        2: await opkBob.pk.asBase64(),
      },
    );

    // Alice does X3DH
    final result = await x3dhFromBundle(bundleBob, ikAlice);
    expect(result.isType<InvalidKeyExchangeSignatureError>(), isTrue);
  });
}
