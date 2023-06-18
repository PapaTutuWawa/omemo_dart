import 'dart:convert';
import 'package:cryptography/cryptography.dart';
import 'package:moxlib/moxlib.dart';
import 'package:omemo_dart/src/errors.dart';
import 'package:omemo_dart/src/keys.dart';

/// Performs X25519 with [kp] and [pk]. If [identityKey] is set, then
/// it indicates which of [kp] ([identityKey] == 1) or [pk] ([identityKey] == 2)
/// is the identity key. This is needed since the identity key pair/public key is
/// an Ed25519 key, but we need them as X25519 keys for DH.
Future<List<int>> omemoDH(
  OmemoKeyPair kp,
  OmemoPublicKey pk,
  int identityKey,
) async {
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

class HkdfKeyResult {
  const HkdfKeyResult(this.encryptionKey, this.authenticationKey, this.iv);
  final List<int> encryptionKey;
  final List<int> authenticationKey;
  final List<int> iv;
}

/// cryptography _really_ wants to check the MAC output from AES-256-CBC. Since
/// we don't have it, we need the MAC check to always "pass".
class NoMacSecretBox extends SecretBox {
  NoMacSecretBox(super.cipherText, {required super.nonce})
      : super(mac: Mac.empty);

  @override
  Future<void> checkMac({
    required MacAlgorithm macAlgorithm,
    required SecretKey secretKey,
    required List<int> aad,
  }) async {}
}

/// OMEMO 0.8.3 often derives the three keys for encryption, authentication and the IV from
/// some input using HKDF-SHA-256. As such, this is a helper function that already provides
/// those three keys from [input] and the info string [info].
Future<HkdfKeyResult> deriveEncryptionKeys(List<int> input, String info) async {
  final algorithm = Hkdf(
    hmac: Hmac(Sha256()),
    outputLength: 80,
  );
  final result = await algorithm.deriveKey(
    secretKey: SecretKey(input),
    nonce: List<int>.filled(32, 0x0),
    info: utf8.encode(info),
  );
  final bytes = await result.extractBytes();

  return HkdfKeyResult(
    bytes.sublist(0, 32),
    bytes.sublist(32, 64),
    bytes.sublist(64, 80),
  );
}

/// A small helper function to make AES-256-CBC easier. Encrypt [plaintext] using [key] as
/// the encryption key and [iv] as the IV. Returns the ciphertext.
Future<List<int>> aes256CbcEncrypt(
  List<int> plaintext,
  List<int> key,
  List<int> iv,
) async {
  final algorithm = AesCbc.with256bits(
    macAlgorithm: MacAlgorithm.empty,
  );
  final result = await algorithm.encrypt(
    plaintext,
    secretKey: SecretKey(key),
    nonce: iv,
  );

  return result.cipherText;
}

/// A small helper function to make AES-256-CBC easier. Decrypt [ciphertext] using [key] as
/// the encryption key and [iv] as the IV. Returns the ciphertext.
Future<Result<MalformedCiphertextError, List<int>>> aes256CbcDecrypt(
  List<int> ciphertext,
  List<int> key,
  List<int> iv,
) async {
  final algorithm = AesCbc.with256bits(
    macAlgorithm: MacAlgorithm.empty,
  );
  try {
    return Result(
      await algorithm.decrypt(
        NoMacSecretBox(
          ciphertext,
          nonce: iv,
        ),
        secretKey: SecretKey(key),
      ),
    );
  } catch (ex) {
    return Result(MalformedCiphertextError(ex));
  }
}

/// OMEMO often uses the output of a HMAC-SHA-256 truncated to its first 16 bytes.
/// Calculate the HMAC-SHA-256 of [input] using the authentication key [key] and
/// truncate the output to 16 bytes.
Future<List<int>> truncatedHmac(List<int> input, List<int> key) async {
  final algorithm = Hmac.sha256();
  final result = await algorithm.calculateMac(
    input,
    secretKey: SecretKey(key),
  );

  return result.bytes.sublist(0, 16);
}
