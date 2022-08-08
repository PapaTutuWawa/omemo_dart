import 'dart:convert';
import 'package:cryptography/cryptography.dart';
import 'package:omemo_dart/src/keys.dart';

class OmemoBundle {

  const OmemoBundle(
    this.jid,
    this.id,
    this.spkEncoded,
    this.spkId,
    this.spkSignatureEncoded,
    this.ikEncoded,
    this.opksEncoded,
  );
  /// The bare Jid the Bundle belongs to
  final String jid;
  /// The device Id
  final int id;
  /// The SPK but base64 encoded
  final String spkEncoded;
  final int spkId;
  /// The SPK signature but base64 encoded
  final String spkSignatureEncoded;
  /// The IK but base64 encoded
  final String ikEncoded;
  /// The mapping of a OPK's id to the base64 encoded data
  final Map<int, String> opksEncoded;

  OmemoPublicKey get spk {
    final data = base64Decode(spkEncoded);
    return OmemoPublicKey.fromBytes(data, KeyPairType.x25519);
  }

  OmemoPublicKey get ik {
    final data = base64Decode(ikEncoded);
    return OmemoPublicKey.fromBytes(data, KeyPairType.ed25519);
  }

  OmemoPublicKey getOpk(int id) {
    final data = base64Decode(opksEncoded[id]!);
    return OmemoPublicKey.fromBytes(data, KeyPairType.x25519);
  }

  List<int> get spkSignature => base64Decode(spkSignatureEncoded);
}
