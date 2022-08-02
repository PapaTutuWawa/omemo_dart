import 'dart:convert';
import 'dart:math';
import 'package:cryptography/cryptography.dart';
import 'package:omemo_dart/src/bundle.dart';
import 'package:omemo_dart/src/errors.dart';
import 'package:omemo_dart/src/helpers.dart';
import 'package:omemo_dart/src/key.dart';

/// The overarching assumption is that we use Ed25519 keys for the identity keys
const omemoX3DHInfoString = 'OMEMO X3DH';

/// Performed by Alice
class X3DHAliceResult {

  const X3DHAliceResult(this.ek, this.sk, this.opkId, this.ad);
  final OmemoKeyPair ek;
  final List<int> sk;
  final String opkId;
  final List<int> ad;
}

/// Received by Bob
class X3DHMessage {

  const X3DHMessage(this.ik, this.ek, this.opkId);
  final OmemoPublicKey ik;
  final OmemoPublicKey ek;
  final String opkId;
}

class X3DHBobResult {

  const X3DHBobResult(this.sk, this.ad);
  final List<int> sk;
  final List<int> ad;
}

/// Sign [message] using the keypair [keyPair]. Note that [keyPair] must be
/// a Ed25519 keypair.
Future<List<int>> sig(OmemoKeyPair keyPair, List<int> message) async {
  assert(keyPair.type == KeyPairType.ed25519, 'Signature keypair must be Ed25519');
  final signature = await Ed25519().sign(
    message,
    keyPair: await keyPair.asKeyPair(),
  );

  return signature.bytes;
}

/// Performs X25519 with [kp] and [pk]. If [identityKey] is set, then
/// it indicates which of [kp] ([identityKey] == 1) or [pk] ([identityKey] == 2)
/// is the identity key. This is needed since the identity key pair/public key is
/// an Ed25519 key, but we need them as X25519 keys for DH.
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
  final input = List<int>.empty(growable: true)
    ..addAll(f)
    ..addAll(km);

  final algorithm = Hkdf(
    hmac: Hmac(Sha256()),
    outputLength: 32,
  );
  final output = await algorithm.deriveKey(
    secretKey: SecretKey(input),
    nonce: List<int>.filled(32, 0x00),
    info: utf8.encode(omemoX3DHInfoString),
  );

  return output.extractBytes();
}

/// Alice builds a session with Bob using his bundle [bundle] and Alice's identity key
/// pair [ik].
Future<X3DHAliceResult> x3dhFromBundle(OmemoBundle bundle, OmemoKeyPair ik) async {
  // Check the signature first
  final signatureValue = await Ed25519().verify(
    await bundle.spk.getBytes(),
    signature: Signature(
      bundle.spkSignature,
      publicKey: bundle.ik.asPublicKey(),
    ),
  );

  if (!signatureValue) {
    throw InvalidSignatureException();
  }

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
  final ad = concat([
    await ik.pk.getBytes(),
    await bundle.ik.getBytes(),
  ]);

  return X3DHAliceResult(ek, sk, opkId, ad);
}

/// Bob builds the X3DH shared secret from the inital message [msg], the SPK [spk], the
/// OPK [opk] that was selected by Alice and our IK [ik]. Returns the shared secret.
Future<X3DHBobResult> x3dhFromInitialMessage(X3DHMessage msg, OmemoKeyPair spk, OmemoKeyPair opk, OmemoKeyPair ik) async {
  final dh1 = await dh(spk, msg.ik, 2);
  final dh2 = await dh(ik,  msg.ek, 1);
  final dh3 = await dh(spk, msg.ek, 0);
  final dh4 = await dh(opk, msg.ek, 0);

  final sk = await kdf(concat([dh1, dh2, dh3, dh4]));
  final ad = concat([
    await msg.ik.getBytes(),
    await ik.pk.getBytes(),
  ]);

  return X3DHBobResult(sk, ad);
}
