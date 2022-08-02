import 'dart:convert';
import 'dart:math';
import 'package:cryptography/cryptography.dart';
import 'bundle.dart';
import 'key.dart';

/// The overarching assumption is that we use Ed25519 keys for the identity keys

/// Performed by Alice
class X3DHResult {

  const X3DHResult(this.ek, this.sk, this.opkId);
  final OmemoKeyPair ek;
  final List<int> sk;
  final String opkId;
}

/// Received by Bob
class X3DHMessage {

  const X3DHMessage(this.ik, this.ek, this.opkId);
  final OmemoPublicKey ik;
  final OmemoPublicKey ek;
  final String opkId;
}

/// Sign [message] using the keypair [keyPair]. Note that [keyPair] must be
/// a Ed25519 keypair.
Future<List<int>> sig(OmemoKeyPair keyPair, List<int> message) async {
  assert(keyPair.type == KeyPairType.ed25519);
  final signature = await Ed25519().sign(
    message,
    keyPair: await keyPair.asKeyPair(),
  );

  return signature.bytes;
}

/// Performs X25519 with [pk1] and [pk2]. If [identityKey] is set, then
/// it indicates which of [pk1] ([identityKey] == 1) or [pk2] ([identityKey] == 2)
/// is the identity key.
Future<List<int>> dh(OmemoKeyPair kp, OmemoPublicKey pk, int identityKey) async {
  var ckp = kp;
  var cpk = pk;

  if (identityKey == 1) {
    ckp = await kp.toCurve25519();
  } else if (identityKey == 2) {
    cpk = await pk.toCurve25519();
  }

  final shared = await Cryptography.instance.x25519().sharedSecretKey(
    keyPair: await ckp.asKeyPair(),
    remotePublicKey: cpk.asPublicKey(),
  );

  return shared.extractBytes();
}

/// Derive a secret from the key material [km].
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

/// Flattens [inputs] and concatenates the elements.
List<int> concat(List<List<int>> inputs) {
  final tmp = List<int>.empty(growable: true);
  for (final input in inputs) {
    tmp.addAll(input);
  }

  return tmp;
}

/// Alice builds a session with Bob using his bundle [bundle] and Alice's identity key
/// pair [ika].
Future<X3DHResult> x3dhFromBundle(OmemoBundle bundle, OmemoKeyPair ik) async {
  // Generate EK
  final ek = await OmemoKeyPair.generateNewPair(KeyPairType.x25519);

  final random = Random.secure();
  final opkIndex = random.nextInt(bundle.opksEncoded.length);
  final opkId = bundle.opksEncoded.keys.elementAt(opkIndex);
  final opk = bundle.getOpk(opkId);
  
  final dh1 = await dh(ik, bundle.spk, 1);
  final dh2 = await dh(ek, bundle.ik,  2);
  final dh3 = await dh(ek, bundle.spk, 0);
  final dh4 = await dh(ek, opk, 0);

  final sk = await kdf(concat([dh1, dh2, dh3, dh4]));

  return X3DHResult(ek, sk, opkId);
}

/// Bob builds the X3DH shared secret from the inital message [msg], the SPK [spk], the
/// OPK [opk] that was selected by Alice and our IK [ik]. Returns the shared secret.
Future<List<int>> x3dhFromInitialMessage(X3DHMessage msg, OmemoKeyPair spk, OmemoKeyPair opk, OmemoKeyPair ik) async {
  final dh1 = await dh(spk, msg.ik, 2);
  final dh2 = await dh(ik,  msg.ek, 1);
  final dh3 = await dh(spk, msg.ek, 0);
  final dh4 = await dh(opk, msg.ek, 0);

  return kdf(concat([dh1, dh2, dh3, dh4]));
}
