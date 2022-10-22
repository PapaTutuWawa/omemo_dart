import 'dart:convert';
import 'package:cryptography/cryptography.dart';
import 'package:meta/meta.dart';
import 'package:omemo_dart/src/crypto.dart';
import 'package:omemo_dart/src/double_ratchet/crypto.dart';
import 'package:omemo_dart/src/double_ratchet/kdf.dart';
import 'package:omemo_dart/src/errors.dart';
import 'package:omemo_dart/src/helpers.dart';
import 'package:omemo_dart/src/keys.dart';
import 'package:omemo_dart/src/protobuf/omemo_message.dart';

/// Amount of messages we may skip per session
const maxSkip = 1000;

class RatchetStep {

  const RatchetStep(this.header, this.ciphertext);
  final OmemoMessage header;
  final List<int> ciphertext;
}

@immutable
class SkippedKey {

  const SkippedKey(this.dh, this.n);

  factory SkippedKey.fromJson(Map<String, dynamic> data) {
    return SkippedKey(
      OmemoPublicKey.fromBytes(
        base64.decode(data['public']! as String),
        KeyPairType.x25519,
      ),
      data['n']! as int,
    );
  }

  final OmemoPublicKey dh;
  final int n;

  Future<Map<String, dynamic>> toJson() async {
    return {
      'public': base64.encode(await dh.getBytes()),
      'n': n,
    };
  }
  
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
    this.ik,
    this.sessionAd,
    this.mkSkipped, // MKSKIPPED
    this.acknowledged,
    this.kexTimestamp,
    this.kex,
  );
  
  factory OmemoDoubleRatchet.fromJson(Map<String, dynamic> data) {
    /*
    {
      'dhs': 'base/64/encoded',
      'dhs_pub': 'base/64/encoded',
      'dhr': null | 'base/64/encoded',
      'rk': 'base/64/encoded',
      'cks': null | 'base/64/encoded',
      'ckr': null | 'base/64/encoded',
      'ns': 0,
      'nr': 0,
      'pn': 0,
      'ik_pub': null | 'base/64/encoded',
      'session_ad': 'base/64/encoded',
      'acknowledged': true | false,
      'kex_timestamp': int,
      'kex': 'base/64/encoded',
      'mkskipped': [
        {
          'key': 'base/64/encoded',
          'public': 'base/64/encoded',
          'n': 0
        }, ...
      ]
    }
    */
    // NOTE: Dart has some issues with just casting a List<dynamic> to List<Map<...>>, as
    //       such we need to convert the items by hand.
    final mkSkipped = Map<SkippedKey, List<int>>.fromEntries(
      (data['mkskipped']! as List<dynamic>).map<MapEntry<SkippedKey, List<int>>>(
        (entry) {
          final map = entry as Map<String, dynamic>;
          final key = SkippedKey.fromJson(map);
          return MapEntry(
            key,
            base64.decode(map['key']! as String),
          );
        },
      ),
    );
    
    return OmemoDoubleRatchet(
      OmemoKeyPair.fromBytes(
        base64.decode(data['dhs_pub']! as String),
        base64.decode(data['dhs']! as String),
        KeyPairType.x25519,
      ),
      decodeKeyIfNotNull(data, 'dhr', KeyPairType.x25519),
      base64.decode(data['rk']! as String),
      base64DecodeIfNotNull(data, 'cks'),
      base64DecodeIfNotNull(data, 'ckr'),
      data['ns']! as int,
      data['nr']! as int,
      data['pn']! as int,
      OmemoPublicKey.fromBytes(
        base64.decode(data['ik_pub']! as String),
        KeyPairType.ed25519,
      ),
      base64.decode(data['session_ad']! as String),
      mkSkipped,
      data['acknowledged']! as bool,
      data['kex_timestamp']! as int,
      data['kex'] as String?,
    );
  }
  
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

  /// The IK public key from the chat partner. Not used for the actual encryption but
  /// for verification purposes
  final OmemoPublicKey ik;
  
  final List<int> sessionAd;

  final Map<SkippedKey, List<int>> mkSkipped;

  /// The point in time at which we performed the kex exchange to create this ratchet.
  /// Precision is milliseconds since epoch.
  int kexTimestamp;

  /// The key exchange that was used for initiating the session.
  final String? kex;
  
  /// Indicates whether we received an empty OMEMO message after building a session with
  /// the device. 
  bool acknowledged;

  /// Create an OMEMO session using the Signed Pre Key [spk], the shared secret [sk] that
  /// was obtained using a X3DH and the associated data [ad] that was also obtained through
  /// a X3DH. [ik] refers to Bob's (the receiver's) IK public key.
  static Future<OmemoDoubleRatchet> initiateNewSession(OmemoPublicKey spk, OmemoPublicKey ik, List<int> sk, List<int> ad, int timestamp) async {
    final dhs = await OmemoKeyPair.generateNewPair(KeyPairType.x25519);
    final dhr = spk;
    final rk  = await kdfRk(sk, await omemoDH(dhs, dhr, 0));
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
      ik,
      ad,
      {},
      false,
      timestamp,
      '',
    );
  }

  /// Create an OMEMO session that was not initiated by the caller using the used Signed
  /// Pre Key keypair [spk], the shared secret [sk] that was obtained through a X3DH and
  /// the associated data [ad] that was also obtained through a X3DH. [ik] refers to
  /// Alice's (the initiator's) IK public key.
  static Future<OmemoDoubleRatchet> acceptNewSession(OmemoKeyPair spk, OmemoPublicKey ik, List<int> sk, List<int> ad, int kexTimestamp) async {
    return OmemoDoubleRatchet(
      spk,
      null,
      sk,
      null,
      null,
      0,
      0,
      0,
      ik,
      ad,
      {},
      false,
      kexTimestamp,
      null,
    );
  }

  Future<Map<String, dynamic>> toJson() async {
    final mkSkippedSerialised = List<Map<String, dynamic>>.empty(growable: true);
    for (final entry in mkSkipped.entries) {
      final result = await entry.key.toJson();
      result['key'] = base64.encode(entry.value);

      mkSkippedSerialised.add(result);
    }
    
    return {
      'dhs': base64.encode(await dhs.sk.getBytes()),
      'dhs_pub': base64.encode(await dhs.pk.getBytes()),
      'dhr': dhr != null ? base64.encode(await dhr!.getBytes()) : null,
      'rk': base64.encode(rk),
      'cks': cks != null ? base64.encode(cks!) : null,
      'ckr': ckr != null ? base64.encode(ckr!) : null,
      'ns': ns,
      'nr': nr,
      'pn': pn,
      'ik_pub': base64.encode(await ik.getBytes()),
      'session_ad': base64.encode(sessionAd),
      'mkskipped': mkSkippedSerialised,
      'acknowledged': acknowledged,
      'kex_timestamp': kexTimestamp,
      'kex': kex,
    };
  }
  
  Future<List<int>?> _trySkippedMessageKeys(OmemoMessage header, List<int> ciphertext) async {
    final key = SkippedKey(
      OmemoPublicKey.fromBytes(header.dhPub!, KeyPairType.x25519),
      header.n!,
    );
    if (mkSkipped.containsKey(key)) {
      final mk = mkSkipped[key]!;
      mkSkipped.remove(key);

      return decrypt(mk, ciphertext, concat([sessionAd, header.writeToBuffer()]), sessionAd);
    }

    return null;
  }

  Future<void> _skipMessageKeys(int until) async {
    if (nr + maxSkip < until) {
      throw SkippingTooManyMessagesException();
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

  Future<void> _dhRatchet(OmemoMessage header) async {
    pn = ns;
    ns = 0;
    nr = 0;
    dhr = OmemoPublicKey.fromBytes(header.dhPub!, KeyPairType.x25519);

    final newRk = await kdfRk(rk, await omemoDH(dhs, dhr!, 0));
    rk = List.from(newRk);
    ckr = List.from(newRk);
    dhs = await OmemoKeyPair.generateNewPair(KeyPairType.x25519);
    final newNewRk = await kdfRk(rk, await omemoDH(dhs, dhr!, 0));
    rk = List.from(newNewRk);
    cks = List.from(newNewRk);
  }

  /// Encrypt [plaintext] using the Double Ratchet.
  Future<RatchetStep> ratchetEncrypt(List<int> plaintext) async {
    final newCks = await kdfCk(cks!, kdfCkNextChainKey);
    final mk = await kdfCk(cks!, kdfCkNextMessageKey);

    cks = newCks;
    final header = OmemoMessage()
      ..dhPub = await dhs.pk.getBytes()
      ..pn = pn
      ..n = ns;

    ns++;

    return RatchetStep(
      header,
      await encrypt(mk, plaintext, concat([sessionAd, header.writeToBuffer()]), sessionAd),
    );
  }

  /// Decrypt a [ciphertext] that was sent with the header [header] using the Double
  /// Ratchet. Returns the decrypted (raw) plaintext.
  ///
  /// Throws an SkippingTooManyMessagesException if too many messages were to be skipped.
  Future<List<int>> ratchetDecrypt(OmemoMessage header, List<int> ciphertext) async {
    // Check if we skipped too many messages
    final plaintext = await _trySkippedMessageKeys(header, ciphertext);
    if (plaintext != null) {
      return plaintext;
    }

    final dhPubMatches = listsEqual(
      header.dhPub!,
      (await dhr?.getBytes()) ?? <int>[],
    );
    if (!dhPubMatches) {
      await _skipMessageKeys(header.pn!);
      await _dhRatchet(header);
    }
    
    await _skipMessageKeys(header.n!);
    final newCkr = await kdfCk(ckr!, kdfCkNextChainKey);
    final mk = await kdfCk(ckr!, kdfCkNextMessageKey);
    ckr = newCkr;
    nr++;

    return decrypt(mk, ciphertext, concat([sessionAd, header.writeToBuffer()]), sessionAd);
  }

  OmemoDoubleRatchet clone() {
    return OmemoDoubleRatchet(
      dhs,
      dhr,
      rk,
      cks != null ?
        List<int>.from(cks!) :
        null,
      ckr != null ?
        List<int>.from(ckr!) :
        null,
      ns,
      nr,
      pn,
      ik,
      sessionAd,
      Map<SkippedKey, List<int>>.from(mkSkipped),
      acknowledged,
      kexTimestamp,
      kex,
    );
  }

  OmemoDoubleRatchet cloneWithKex(String kex) {
    return OmemoDoubleRatchet(
      dhs,
      dhr,
      rk,
      cks != null ?
        List<int>.from(cks!) :
        null,
      ckr != null ?
        List<int>.from(ckr!) :
        null,
      ns,
      nr,
      pn,
      ik,
      sessionAd,
      Map<SkippedKey, List<int>>.from(mkSkipped),
      acknowledged,
      kexTimestamp,
      kex,
    );
  }
  
  @visibleForTesting
  Future<bool> equals(OmemoDoubleRatchet other) async {
    final dhrMatch = dhr == null ?
      other.dhr == null :
      // ignore: invalid_use_of_visible_for_testing_member
      other.dhr != null && await dhr!.equals(other.dhr!);
    final ckrMatch = ckr == null ?
      other.ckr == null :
      other.ckr != null && listsEqual(ckr!, other.ckr!);
    final cksMatch = cks == null ?
      other.cks == null :
      other.cks != null && listsEqual(cks!, other.cks!);
 
    // ignore: invalid_use_of_visible_for_testing_member
    final dhsMatch = await dhs.equals(other.dhs);
    // ignore: invalid_use_of_visible_for_testing_member
    final ikMatch = await ik.equals(other.ik);

    return dhsMatch &&
      ikMatch &&
      dhrMatch &&
      listsEqual(rk, other.rk) &&
      cksMatch &&
      ckrMatch &&
      ns == other.ns &&
      nr == other.nr &&
      pn == other.pn &&
      listsEqual(sessionAd, other.sessionAd) &&
      kexTimestamp == other.kexTimestamp;
  }
}
