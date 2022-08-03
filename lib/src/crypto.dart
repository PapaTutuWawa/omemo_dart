import 'package:cryptography/cryptography.dart';
import 'package:omemo_dart/src/keys.dart';

/// Performs X25519 with [kp] and [pk]. If [identityKey] is set, then
/// it indicates which of [kp] ([identityKey] == 1) or [pk] ([identityKey] == 2)
/// is the identity key. This is needed since the identity key pair/public key is
/// an Ed25519 key, but we need them as X25519 keys for DH.
Future<List<int>> omemoDH(OmemoKeyPair kp, OmemoPublicKey pk, int identityKey) async {
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
