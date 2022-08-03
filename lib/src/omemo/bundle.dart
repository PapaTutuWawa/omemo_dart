import 'dart:convert';
import 'package:cryptography/cryptography.dart';
import 'package:omemo_dart/src/keys.dart';

class OmemoBundle {

  const OmemoBundle(
    this.id,
    this.spkEncoded,
    this.spkId,
    this.spkSignatureEncoded,
    this.ikEncoded,
    this.opksEncoded,
  );
  final String id;
  /// The SPK but base64 encoded
  final String spkEncoded;
  final String spkId;
  /// The SPK signature but base64 encoded
  final String spkSignatureEncoded;
  /// The IK but base64 encoded
  final String ikEncoded;
  /// The mapping of a OPK's id to the base64 encoded data
  final Map<String, String> opksEncoded;

  OmemoPublicKey get spk {
    final data = base64Decode(spkEncoded);
    return OmemoPublicKey.fromBytes(data, KeyPairType.x25519);
  }

  OmemoPublicKey get ik {
    final data = base64Decode(ikEncoded);
    return OmemoPublicKey.fromBytes(data, KeyPairType.ed25519);
  }

  OmemoPublicKey getOpk(String id) {
    final data = base64Decode(opksEncoded[id]!);
    return OmemoPublicKey.fromBytes(data, KeyPairType.x25519);
  }

  List<int> get spkSignature => base64Decode(spkSignatureEncoded);
}
