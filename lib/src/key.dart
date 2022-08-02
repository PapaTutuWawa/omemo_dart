import 'dart:convert';
import 'package:cryptography/cryptography.dart';
import 'package:pinenacl/api.dart';
import 'package:pinenacl/tweetnacl.dart';

const privateKeyLength = 32;
const publicKeyLength = 32;

class OmemoPublicKey {

  const OmemoPublicKey(this._pubkey);

  factory OmemoPublicKey.fromBytes(List<int> bytes, KeyPairType type) {
    return OmemoPublicKey(
      SimplePublicKey(
        bytes,
        type: type,
      ),
    );
  }

  final SimplePublicKey _pubkey;
  
  KeyPairType get type => _pubkey.type;

  /// Return the bytes that comprise the public key.
  Future<List<int>> getBytes() async => _pubkey.bytes;

  /// Returns the public key encoded as base64.
  Future<String> asBase64() async => base64Encode(_pubkey.bytes);

  Future<OmemoPublicKey> toCurve25519() async {
    assert(type == KeyPairType.ed25519, 'Cannot convert non-Ed25519 public key to X25519');

    final pkc = Uint8List(publicKeyLength);
    TweetNaClExt.crypto_sign_ed25519_pk_to_x25519_pk(
      pkc,
      Uint8List.fromList(await getBytes()),
    );

    return OmemoPublicKey(SimplePublicKey(List<int>.from(pkc), type: KeyPairType.x25519));
  }

  SimplePublicKey asPublicKey() => _pubkey;
  
  /// Convert the public key into a [SimpleKeyPairData] with a stub private key. Useful
  /// for when cryptography calls for a KeyPair, but only uses the public key.
  //SimpleKeyPairData asPseudoKeypair() {
  //
  //}
}

class OmemoPrivateKey {

  const OmemoPrivateKey(this._privkey, this.type);
  final List<int> _privkey;
  final KeyPairType type;

  Future<List<int>> getBytes() async => _privkey;
  
  Future<OmemoPrivateKey> toCurve25519() async {
    assert(type == KeyPairType.ed25519, 'Cannot convert non-Ed25519 private key to X25519');

    final skc = Uint8List(privateKeyLength);
    TweetNaClExt.crypto_sign_ed25519_sk_to_x25519_sk(
      skc,
      Uint8List.fromList(await getBytes()),
    );

    return OmemoPrivateKey(List<int>.from(skc), KeyPairType.x25519);
  }
}

/// A generic wrapper class for both Ed25519 and X25519 keypairs
class OmemoKeyPair {

  const OmemoKeyPair(this.pk, this.sk, this.type);
  final KeyPairType type;
  final OmemoPublicKey pk;
  final OmemoPrivateKey sk;

  static Future<OmemoKeyPair> generateNewPair(KeyPairType type) async {
    assert(type == KeyPairType.ed25519 || type == KeyPairType.x25519, 'Keypair must be either Ed25519 or X25519');

    SimpleKeyPair kp;
    if (type == KeyPairType.ed25519) {
      final ed = Ed25519();
      kp = await ed.newKeyPair();
    } else if (type == KeyPairType.x25519) {
      final x = Cryptography.instance.x25519();
      kp = await x.newKeyPair();
    } else {
      // Should never happen
      throw Exception();
    }

    final kpd = await kp.extract();
    
    return OmemoKeyPair(
      OmemoPublicKey(await kp.extractPublicKey()),
      OmemoPrivateKey(await kpd.extractPrivateKeyBytes(), type),
      type,
    );
  }
  
  /// Return the bytes that comprise the public key.
  Future<OmemoKeyPair> toCurve25519() async {
    assert(type == KeyPairType.ed25519, 'Cannot convert non-Ed25519 keypair to X25519');

    return OmemoKeyPair(
      await pk.toCurve25519(),
      await sk.toCurve25519(),
      KeyPairType.x25519,
    );
  }

  Future<SimpleKeyPairData> asKeyPair() async {
    return SimpleKeyPairData(
      await sk.getBytes(),
      publicKey: pk.asPublicKey(),
      type: type,
    );
  }
}
