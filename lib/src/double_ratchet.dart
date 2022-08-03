import 'package:cryptography/cryptography.dart';
import 'package:meta/meta.dart';
import 'package:omemo_dart/protobuf/schema.pb.dart';
import 'package:omemo_dart/src/double_ratchet/crypto.dart';
import 'package:omemo_dart/src/double_ratchet/kdf.dart';
import 'package:omemo_dart/src/helpers.dart';
import 'package:omemo_dart/src/key.dart';
import 'package:omemo_dart/src/x3dh.dart';

/// Amount of messages we may skip per session
const maxSkip = 1000;

class RatchetStep {

  const RatchetStep(this.header, this.ciphertext);
  final OMEMOMessage header;
  final List<int> ciphertext;
}

@immutable
class SkippedKey {

  const SkippedKey(this.dh, this.n);
  final OmemoPublicKey dh;
  final int n;

  @override
  bool operator ==(Object other) {
    return other is SkippedKey && other.dh == dh && other.n == n;
  }

  @override
  int get hashCode => dh.hashCode ^ n.hashCode;
}

class OmemoDoubleRatchet {

  OmemoDoubleRatchet(
    this.dhs, // DHs
    this.dhr, // DHr
    this.rk,  // RK
    this.cks, // CKs
    this.ckr, // CKr
    this.ns,  // Ns
    this.nr,  // Nr
    this.pn,  // Pn
    this.sessionAd,
  );
     
  /// Sending DH keypair
  OmemoKeyPair dhs;

  /// Receiving Public key
  OmemoPublicKey? dhr;

  /// 32 byte Root Key
  List<int> rk;

  /// Sending and receiving Chain Keys
  List<int>? cks;
  List<int>? ckr;

  /// Sending and receiving message numbers
  int ns;
  int nr;

  /// Previous sending chain number
  int pn;

  final List<int> sessionAd;

  final Map<SkippedKey, List<int>> mkSkipped = {};

  /// This is performed by the initiating entity
  static Future<OmemoDoubleRatchet> initiateNewSession(OmemoPublicKey spk, List<int> sk, List<int> ad) async {
    final dhs = await OmemoKeyPair.generateNewPair(KeyPairType.x25519);
    final dhr = spk;
    final rk  = await kdfRk(sk, await dh(dhs, dhr, 0));
    final cks = rk;

    return OmemoDoubleRatchet(
      dhs,
      dhr,
      rk,
      cks,
      null,
      0,
      0,
      0,
      ad,
    );
  }

  /// This is performed by the accepting entity
  static Future<OmemoDoubleRatchet> acceptNewSession(OmemoKeyPair spk, List<int> sk, List<int> ad) async {
    final dhs = spk;
    return OmemoDoubleRatchet(
      dhs,
      null,
      sk,
      null,
      null,
      0,
      0,
      0,
      ad,
    );
  }
  
  Future<RatchetStep> ratchetEncrypt(List<int> plaintext) async {
    final newCks = await kdfCk(cks!, kdfCkNextChainKey);
    final mk = await kdfCk(cks!, kdfCkNextMessageKey);

    cks = newCks;
    final header = OMEMOMessage()
      ..dhPub = await dhs.pk.getBytes()
      ..pn = pn
      ..n = ns;

    ns++;

    return RatchetStep(
      header,
      await encrypt(mk, plaintext, concat([sessionAd, header.writeToBuffer()]), sessionAd),
    );
  }

  Future<List<int>?> trySkippedMessageKeys(OMEMOMessage header, List<int> ciphertext) async {
    final key = SkippedKey(
      OmemoPublicKey.fromBytes(header.dhPub, KeyPairType.x25519),
      header.n,
    );
    if (mkSkipped.containsKey(key)) {
      final mk = mkSkipped[key]!;
      mkSkipped.remove(key);

      return decrypt(mk, ciphertext, concat([sessionAd, header.writeToBuffer()]), sessionAd);
    }

    return null;
  }

  Future<void> skipMessageKeys(int until) async {
    if (nr + maxSkip < until) {
      // TODO(PapaTutuWawa): Custom exception
      throw Exception();
    }

    if (ckr != null) {
      while (nr < until) {
        final newCkr = await kdfCk(ckr!, kdfCkNextChainKey);
        final mk = await kdfCk(ckr!, kdfCkNextMessageKey);
        ckr = newCkr;
        mkSkipped[SkippedKey(dhr!, nr)] = mk;
        nr++;
      }
    }
  }

  Future<void> dhRatchet(OMEMOMessage header) async {
    pn = header.n;
    ns = 0;
    nr = 0;
    dhr = OmemoPublicKey.fromBytes(header.dhPub, KeyPairType.x25519);

    final newRk = await kdfRk(rk, await dh(dhs, dhr!, 0));
    rk = newRk;
    ckr = newRk;
    dhs = await OmemoKeyPair.generateNewPair(KeyPairType.x25519);
    final newNewRk = await kdfRk(rk, await dh(dhs, dhr!, 0));
    rk = newNewRk;
    cks = newNewRk;
  }
  
  Future<List<int>> ratchetDecrypt(OMEMOMessage header, List<int> ciphertext) async {
    // Check if we skipped too many messages
    final plaintext = await trySkippedMessageKeys(header, ciphertext);
    if (plaintext != null) {
      return plaintext;
    }

    if (header.dhPub != await dhr?.getBytes()) {
      await skipMessageKeys(header.pn);
      await dhRatchet(header);
    }

    await skipMessageKeys(header.n);
    final newCkr = await kdfCk(ckr!, kdfCkNextChainKey);
    final mk = await kdfCk(ckr!, kdfCkNextMessageKey);
    ckr = newCkr;
    nr++;

    return decrypt(mk, ciphertext, concat([sessionAd, header.writeToBuffer()]), sessionAd);
  }
}
