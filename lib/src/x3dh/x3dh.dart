import 'dart:convert';
import 'package:cryptography/cryptography.dart';
import 'package:cryptography/dart.dart';

/// The overarching assumption is that we use Ed25519 keys for the identity keys

class X3DHRun {

  const X3DHRun(this.epk, this.sharedSecret);
  final SimpleKeyPair epk;
  final List<int> sharedSecret;
}

SimpleKeyPairData fromPublicKey(SimplePublicKey pk) {
  return SimpleKeyPairData([], publicKey: pk, type: KeyPairType.x25519);
}

Future<List<int>> sig(SimpleKeyPair keyPair, List<int> message) async {
  final signature = await Ed25519().sign(
    message,
    keyPair: keyPair,
  );

  return signature.bytes;
}

/// Performs X25519 with [pk1] and [pk2]. If [identityKey] is set, then
/// it indicates which of [pk1] ([identityKey] == 1) or [pk2] ([identityKey] == 2)
/// is the identity key.
Future<List<int>> dh(SimpleKeyPair kp, SimplePublicKey pk, int identityKey) async {
  var ckp = kp;
  var cpk = pk;

  /*
  if (identityKey == 1) {
    final pkc = await DartEd25519.publicKeyToCurve25519(kp);
    final skc = await DartEd25519.privateKeyToCurve25519(kp);
    ckp = SimpleKeyPairData(skc, publicKey: pkc, type: KeyPairType.x25519);
  } else if (identityKey == 2) {
    cpk = await DartEd25519.publicKeyToCurve25519(fromPublicKey(pk));
  }
  */

  final shared = await Cryptography.instance.x25519().sharedSecretKey(
    keyPair: ckp,
    remotePublicKey: cpk,
  );

  return shared.extractBytes();
}

Future<List<int>> kdf(List<int> km) async {
  final f = List<int>.filled(32, 0xFF);
  final input = List<int>.empty(growable: true);
  input
    ..addAll(f)
    ..addAll(km);

  final algorithm = Hkdf(
    hmac: Hmac(Sha256()),
    outputLength: 32,
  );
  final output = await algorithm.deriveKey(
    secretKey: SecretKey(input),
    // TODO: Fix
    nonce: List<int>.filled(32, 0x00),
    info: utf8.encode('OMEMO X3DH'),
  );

  return output.extractBytes();
}

List<int> concat(List<List<int>> inputs) {
  final tmp = List<int>.empty(growable: true);
  for (final input in inputs) {
    tmp.addAll(input);
  }

  return tmp;
}

// Alice -> Bob
Future<X3DHRun> x3dhFromPrekeyBundle(SimplePublicKey ikb, SimplePublicKey spkb, SimplePublicKey opkb, SimpleKeyPair ika) async {
  // Generate EPK
  final epk = await Cryptography.instance.x25519().newKeyPair();

  final dh1 = await dh(ika, spkb, 1);
  final dh2 = await dh(epk, ikb,  2);
  final dh3 = await dh(epk, spkb, 0);
  final dh4 = await dh(epk, opkb, 0);

  final sk = await kdf(concat([dh1, dh2, dh3, dh4]));

  return X3DHRun(
    epk,
    sk,
  );
}

Future<List<int>> x3dhFromInitialMessage(SimplePublicKey ika, SimplePublicKey epk, SimpleKeyPair opkb, SimpleKeyPair spk, SimpleKeyPair ikb) async {
  final dh1 = await dh(spk, ika, 2);
  final dh2 = await dh(ikb, epk, 1);
  final dh3 = await dh(spk, epk, 0);
  final dh4 = await dh(opkb, epk, 0);

  return kdf(concat([dh1, dh2, dh3, dh4]));
}
