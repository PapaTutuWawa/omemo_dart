import 'dart:convert';
import 'package:cryptography/cryptography.dart';
import 'package:omemo_dart/protobuf/schema.pb.dart';
import 'package:omemo_dart/src/bundle.dart';
import 'package:omemo_dart/src/helpers.dart';
import 'package:omemo_dart/src/key.dart';
import 'package:omemo_dart/src/x3dh.dart';

class OmemoRatchetStepResult {

  const OmemoRatchetStepResult(this.header, this.cipherText);
  final List<int> header;
  final List<int> cipherText;
}

class OmemoEncryptionResult {

  const OmemoEncryptionResult(this.cipherText, this.keys);
  /// The encrypted plaintext
  final List<int> cipherText;
  /// Mapping between Device id and the key to decrypt cipherText;
  final Map<String, List<int>> keys;
}

/// The session state of one party
class AliceOmemoSession {

  AliceOmemoSession(
    this.dhs,
    this.dhr,
    this.ek,
    this.rk,
    this.cks,
    this.ckr,
    this.ns,
    this.nr,
    this.pn,
    // this.skippedMessages,
    this.ad,
  );
  
  /// The Diffie-Hellman sending key pair
  final OmemoKeyPair dhs;

  /// The Diffie-Hellman receiving key pair
  final OmemoPublicKey dhr;

  /// The EK used by X3DH
  final OmemoKeyPair ek;
  
  /// The Root Key
  List<int> rk;

  /// Sending Chain Key
  List<int> cks;

  /// Receiving Chain Key
  List<int>? ckr;

  /// Message number for sending
  int ns;

  /// Message number for receiving
  int nr;

  /// Number of messages in the previous sending chain
  int pn;
  
  /// The associated data from the X3DH
  final List<int> ad;

  // TODO(PapaTutuWawa): Track skipped over message keys

  static Future<AliceOmemoSession> newSession(OmemoBundle bundle, OmemoKeyPair ik) async {
    // TODO(PapaTutuWawa): Error handling
    final x3dhResult = await x3dhFromBundle(bundle, ik);
    final dhs = await OmemoKeyPair.generateNewPair(KeyPairType.x25519);
    final dhr = bundle.ik;
    final ek = x3dhResult.ek;
    final sk = x3dhResult.sk;
    final kdfRkResult = await kdfRk(sk, await dh(dhs, dhr, 2));
    
    return AliceOmemoSession(
      dhs,
      dhr,
      ek,
      kdfRkResult.rk,
      kdfRkResult.ck,
      null,
      0,
      0,
      0,
      x3dhResult.ad,
    );
  }

  /// The associated_data parameter is implicit as it belongs to the session
  Future<List<int>> _encrypt(List<int> mk, List<int> plaintext, List<int> associatedData) async {
    final algorithm = Hkdf(
      hmac: Hmac(Sha256()),
      outputLength: 80,
    );
    final hkdfResult = await algorithm.deriveKey(
      secretKey: SecretKey(mk),
      nonce: List<int>.filled(32, 0x00),
      info: utf8.encode(encryptHkdfInfoString),
    );
    final bytes = await hkdfResult.extractBytes();

    final encKey = bytes.sublist(0, 32);
    final authKey = bytes.sublist(32, 64);
    final iv = bytes.sublist(64, 82);

    // TODO(PapaTutuWawa): Remove once done
    assert(encKey.length == 32);
    assert(authKey.length == 32);
    assert(iv.length == 16);

    // 32 = 256 / 8
    final encodedPlaintext = pkcs7padding(plaintext, 32);

    final aesAlgorithm = AesCbc.with256bits(
      macAlgorithm: Hmac.sha256(),
    );
    final secretBox = await aesAlgorithm.encrypt(
      encodedPlaintext,
      secretKey: SecretKey(encKey),
      nonce: iv,
    );

    final ad_ = associatedData.sublist(0, ad.length);
    final message = OMEMOMessage.fromBuffer(associatedData.sublist(ad.length))
      ..ciphertext = secretBox.cipherText;
    final messageBytes = message.writeToBuffer();

    final input = concat([ad_, messageBytes]);
    final authBytes = (await Hmac.sha256().calculateMac(
      input,
      secretKey: SecretKey(authKey),
    )).bytes.sublist(0, 16);

    final authenticatedMessage = OMEMOAuthenticatedMessage()
      ..mac = authBytes
      ..message = messageBytes;

    return authenticatedMessage.writeToBuffer();
  }

  Future<List<int>> ratchetStep(List<int> plaintext) async {
    final kdfResult = await kdfCk(cks);
    final message = OMEMOMessage()
      ..dhPub = await dhs.pk.getBytes()
      ..pn = pn
      ..n = ns;
    final header = message.writeToBuffer();
    
    cks = kdfResult.ck;
    ns++;

    return _encrypt(
      kdfResult.mk,
      plaintext,
      concat([ad, header]),
    );
  }
}

Future<OmemoEncryptionResult> encryptForSessions(List<AliceOmemoSession> sessions, String plaintext) async {
  // TODO(PapaTutuWawa): Generate random data
  final key = List<int>.filled(32, 0x0);
  final algorithm = Hkdf(
    hmac: Hmac(Sha256()),
    outputLength: 80,
  );
  final result = await algorithm.deriveKey(
    secretKey: SecretKey(key),
    nonce: List<int>.filled(32, 0x0),
    info: utf8.encode(encryptionHkdfInfoString),
  );
  final bytes = await result.extractBytes();

  final encKey = bytes.sublist(0, 32);
  final authKey = bytes.sublist(32, 64);
  final iv = bytes.sublist(64, 80);

  final encodedPlaintext = pkcs7padding(utf8.encode(plaintext), 32);
  final aesAlgorithm = AesCbc.with256bits(
    macAlgorithm: Hmac.sha256(),
  );
  final secretBox = await aesAlgorithm.encrypt(
    encodedPlaintext,
    secretKey: SecretKey(encKey),
    nonce: iv,
  );
  final hmac = (await Hmac.sha256().calculateMac(
    secretBox.cipherText,
    secretKey: SecretKey(authKey),
  )).bytes.sublist(0, 16);

  final keyData = concat([encKey, hmac]);

  final keyMap = <String, List<int>>{};
  for (final session in sessions) {
    final ratchetKey = await session.ratchetStep(keyData);
  }
  
  return OmemoEncryptionResult(
    secretBox.cipherText,
    keyMap,
  );
}

/// Result of the KDF_RK function from the Double Ratchet spec.
class KdfRkResult {

  const KdfRkResult(this.rk, this.ck);
  /// 32 byte Root Key
  final List<int> rk;

  /// 32 byte Chain Key
  final List<int> ck;
}

/// Result of the KDF_CK function from the Double Ratchet spec.
class KdfCkResult {

  const KdfCkResult(this.ck, this.mk);
  /// 32 byte Chain Key
  final List<int> ck;

  /// 32 byte Message Key
  final List<int> mk;
}

/// Amount of messages we may skip per session
const maxSkip = 1000;

/// Info string for KDF_RK
const kdfRkInfoString = 'OMEMO Root Chain';

/// Info string for ENCRYPT
const encryptHkdfInfoString = 'OMEMO Message Key Material';

/// Info string for encrypting a message
const encryptionHkdfInfoString = 'OMEMO Payload';

/// Flags for KDF_CK
const kdfCkNextMessageKey = 0x01;
const kdfCkNextChainKey = 0x02;

Future<KdfRkResult> kdfRk(List<int> rk, List<int> dhOut) async {
  final algorithm = Hkdf(
    hmac: Hmac(Sha256()),
    outputLength: 32,
  );
  final result = await algorithm.deriveKey(
    secretKey: SecretKey(dhOut),
    nonce: rk,
    info: utf8.encode(kdfRkInfoString),
  );

  // TODO(PapaTutuWawa): Does the rk in the tuple (rk, ck) refer to the input rk?
  return KdfRkResult(rk, await result.extractBytes());
}

Future<KdfCkResult> kdfCk(List<int> ck) async {
  final hkdf = Hkdf(hmac: Hmac(Sha256()), outputLength: 32);
  final newCk = await hkdf.deriveKey(
    secretKey: SecretKey(ck),
    nonce: [kdfCkNextChainKey],
  );
  final mk = await hkdf.deriveKey(
    secretKey: SecretKey(ck),
    nonce: [kdfCkNextMessageKey],
  );

  return KdfCkResult(
    await newCk.extractBytes(),
    await mk.extractBytes(),
  );
}
