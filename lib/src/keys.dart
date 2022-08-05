import 'dart:convert';
import 'package:cryptography/cryptography.dart';
import 'package:meta/meta.dart';
import 'package:omemo_dart/src/helpers.dart';
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

  @visibleForTesting
  Future<bool> equals(OmemoPublicKey key) async {
    return type == key.type && listsEqual(
      await getBytes(),
      await key.getBytes(),
    );
  }
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

  @visibleForTesting
  Future<bool> equals(OmemoPrivateKey key) async {
    return type == key.type && listsEqual(
      await getBytes(),
      await key.getBytes(),
    );
  }
}

/// A generic wrapper class for both Ed25519 and X25519 keypairs
class OmemoKeyPair {

  const OmemoKeyPair(this.pk, this.sk, this.type);

  /// Create an OmemoKeyPair just from a [type] and the bytes of the private and public
  /// key.
  factory OmemoKeyPair.fromBytes(List<int> publicKey, List<int> privateKey, KeyPairType type) {
    return OmemoKeyPair(
      OmemoPublicKey.fromBytes(
        publicKey,
        type,
      ),
      OmemoPrivateKey(
        privateKey,
        type,
      ),
      type,
    );
  }

  /// Generate a completely new random OmemoKeyPair of type [type]. [type] must be either
  /// KeyPairType.ed25519 or KeyPairType.x25519.
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

  final KeyPairType type;
  final OmemoPublicKey pk;
  final OmemoPrivateKey sk;
  
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

  @visibleForTesting
  Future<bool> equals(OmemoKeyPair pair) async {
    return type == pair.type &&
      await pk.equals(pair.pk) &&
      await sk.equals(pair.sk);
  }
}
