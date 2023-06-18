import 'package:cryptography/cryptography.dart';
import 'package:hex/hex.dart';
import 'package:meta/meta.dart';
import 'package:moxlib/moxlib.dart';
import 'package:omemo_dart/src/common/constants.dart';
import 'package:omemo_dart/src/crypto.dart';
import 'package:omemo_dart/src/double_ratchet/kdf.dart';
import 'package:omemo_dart/src/errors.dart';
import 'package:omemo_dart/src/helpers.dart';
import 'package:omemo_dart/src/keys.dart';
import 'package:omemo_dart/src/protobuf/schema.pb.dart';

@immutable
class SkippedKey {
  const SkippedKey(this.dh, this.n);

  /// The DH public key for which we skipped a message key.
  final OmemoPublicKey dh;

  /// The associated number of the message key we skipped.
  final int n;

  @override
  bool operator ==(Object other) {
    return other is SkippedKey && other.dh == dh && other.n == n;
  }

  @override
  int get hashCode => dh.hashCode ^ n.hashCode;
}

@immutable
class KeyExchangeData {
  const KeyExchangeData(
    this.pkId,
    this.spkId,
    this.ik,
    this.ek,
  );

  /// The id of the used OPK.
  final int pkId;

  /// The id of the used SPK.
  final int spkId;

  /// The ephemeral key used while the key exchange.
  final OmemoPublicKey ek;

  /// The identity key used in the key exchange.
  final OmemoPublicKey ik;
}

class OmemoDoubleRatchet {
  OmemoDoubleRatchet(
    this.dhs, // DHs
    this.dhr, // DHr
    this.rk, // RK
    this.cks, // CKs
    this.ckr, // CKr
    this.ns, // Ns
    this.nr, // Nr
    this.pn, // Pn
    this.ik,
    this.sessionAd,
    this.mkSkipped, // MKSKIPPED
    this.acknowledged,
    this.kex,
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

  /// The IK public key from the chat partner. Not used for the actual encryption but
  /// for verification purposes
  final OmemoPublicKey ik;

  /// Associated data for this ratchet.
  final List<int> sessionAd;

  /// List of skipped message keys.
  final Map<SkippedKey, List<int>> mkSkipped;

  /// The key exchange that was used for initiating the session.
  final KeyExchangeData kex;

  /// Indicates whether we received an empty OMEMO message after building a session with
  /// the device.
  bool acknowledged;

  /// Create an OMEMO session using the Signed Pre Key [spk], the shared secret [sk] that
  /// was obtained using a X3DH and the associated data [ad] that was also obtained through
  /// a X3DH. [ik] refers to Bob's (the receiver's) IK public key.
  static Future<OmemoDoubleRatchet> initiateNewSession(
    OmemoPublicKey spk,
    int spkId,
    OmemoPublicKey ik,
    OmemoPublicKey ownIk,
    OmemoPublicKey ek,
    List<int> sk,
    List<int> ad,
    int pkId,
  ) async {
    final dhs = await OmemoKeyPair.generateNewPair(KeyPairType.x25519);
    final rk = await kdfRk(sk, await omemoDH(dhs, spk, 0));

    return OmemoDoubleRatchet(
      dhs,
      spk,
      List.from(rk),
      List.from(rk),
      null,
      0,
      0,
      0,
      ik,
      ad,
      {},
      false,
      KeyExchangeData(
        pkId,
        spkId,
        ownIk,
        ek,
      ),
    );
  }

  /// Create an OMEMO session that was not initiated by the caller using the used Signed
  /// Pre Key keypair [spk], the shared secret [sk] that was obtained through a X3DH and
  /// the associated data [ad] that was also obtained through a X3DH. [ik] refers to
  /// Alice's (the initiator's) IK public key.
  static Future<OmemoDoubleRatchet> acceptNewSession(
    OmemoKeyPair spk,
    int spkId,
    OmemoPublicKey ik,
    int pkId,
    OmemoPublicKey ek,
    List<int> sk,
    List<int> ad,
  ) async {
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
      true,
      KeyExchangeData(
        pkId,
        spkId,
        ik,
        ek,
      ),
    );
  }

  /// Performs a single ratchet step in case we received a new
  /// public key in [header].
  Future<void> _dhRatchet(OMEMOMessage header) async {
    pn = ns;
    ns = 0;
    nr = 0;
    dhr = OmemoPublicKey.fromBytes(header.dhPub, KeyPairType.x25519);
    final newRk1 = await kdfRk(
      rk,
      await omemoDH(
        dhs,
        dhr!,
        0,
      ),
    );
    rk = List.from(newRk1);
    ckr = List.from(newRk1);

    dhs = await OmemoKeyPair.generateNewPair(KeyPairType.x25519);
    final newRk2 = await kdfRk(
      rk,
      await omemoDH(
        dhs,
        dhr!,
        0,
      ),
    );
    rk = List.from(newRk2);
    cks = List.from(newRk2);
  }

  /// Skip (and keep track of) message keys until our receive counter is
  /// equal to [until]. If we would skip too many messages, returns
  /// a [SkippingTooManyKeysError]. If not, returns null.
  Future<OmemoError?> _skipMessageKeys(int until) async {
    if (nr + maxSkip < until) {
      return SkippingTooManyKeysError();
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

    return null;
  }

  /// Decrypt [ciphertext] using keys derived from the message key [mk]. Also computes the
  /// HMAC from the [OMEMOMessage] embedded in [message].
  ///
  /// If the computed HMAC does not match the HMAC in [message], returns
  /// [InvalidMessageHMACError]. If it matches, returns the decrypted
  /// payload.
  Future<Result<OmemoError, List<int>>> _decrypt(
    OMEMOAuthenticatedMessage message,
    List<int> ciphertext,
    List<int> mk,
  ) async {
    final keys = await deriveEncryptionKeys(mk, encryptHkdfInfoString);

    final hmacInput = concat([sessionAd, message.message]);
    final hmacResult = await truncatedHmac(hmacInput, keys.authenticationKey);
    if (!listsEqual(hmacResult, message.mac)) {
      return Result(InvalidMessageHMACError());
    }

    final plaintext =
        await aes256CbcDecrypt(ciphertext, keys.encryptionKey, keys.iv);
    if (plaintext.isType<MalformedCiphertextError>()) {
      return Result(plaintext.get<MalformedCiphertextError>());
    }

    return Result(plaintext.get<List<int>>());
  }

  /// Checks whether we could decrypt the payload in [header] with a skipped key. If yes,
  /// attempts to decrypt it. If not, returns null.
  ///
  /// If the decryption is successful, returns the plaintext payload. If an error occurs, like
  /// an [InvalidMessageHMACError], that is returned instead.
  Future<Result<OmemoError, List<int>?>> _trySkippedMessageKeys(
    OMEMOAuthenticatedMessage message,
    OMEMOMessage header,
  ) async {
    final key = SkippedKey(
      OmemoPublicKey.fromBytes(header.dhPub, KeyPairType.x25519),
      header.n,
    );
    if (mkSkipped.containsKey(key)) {
      final mk = mkSkipped[key]!;
      mkSkipped.remove(key);

      return _decrypt(message, header.ciphertext, mk);
    }

    return const Result(null);
  }

  /// Decrypt the payload (deeply) embedded in [message].
  ///
  /// If everything goes well, returns the plaintext payload. If an error occurs, that
  /// is returned instead.
  Future<Result<OmemoError, List<int>>> ratchetDecrypt(
    OMEMOAuthenticatedMessage message,
  ) async {
    final header = OMEMOMessage.fromBuffer(message.message);

    // Try skipped keys
    final plaintextRaw = await _trySkippedMessageKeys(message, header);
    if (plaintextRaw.isType<OmemoError>()) {
      // Propagate the error
      return Result(plaintextRaw.get<OmemoError>());
    }

    final plaintext = plaintextRaw.get<List<int>?>();
    if (plaintext != null) {
      return Result(plaintext);
    }

    if (dhr == null || !listsEqual(header.dhPub, await dhr!.getBytes())) {
      final skipResult1 = await _skipMessageKeys(header.pn);
      if (skipResult1 != null) {
        return Result(skipResult1);
      }

      await _dhRatchet(header);
    }

    final skipResult2 = await _skipMessageKeys(header.n);
    if (skipResult2 != null) {
      return Result(skipResult2);
    }

    final ck = await kdfCk(ckr!, kdfCkNextChainKey);
    final mk = await kdfCk(ckr!, kdfCkNextMessageKey);
    ckr = ck;
    nr++;

    return _decrypt(message, header.ciphertext, mk);
  }

  /// Encrypt the payload [plaintext] using the double ratchet session.
  Future<OMEMOAuthenticatedMessage> ratchetEncrypt(List<int> plaintext) async {
    // Advance the ratchet
    final ck = await kdfCk(cks!, kdfCkNextChainKey);
    final mk = await kdfCk(cks!, kdfCkNextMessageKey);
    cks = ck;

    // Generate encryption, authentication key and IV
    final keys = await deriveEncryptionKeys(mk, encryptHkdfInfoString);
    final ciphertext =
        await aes256CbcEncrypt(plaintext, keys.encryptionKey, keys.iv);

    // Fill-in the header and serialize it here so we do it only once
    final header = OMEMOMessage()
      ..dhPub = await dhs.pk.getBytes()
      ..pn = pn
      ..n = ns
      ..ciphertext = ciphertext;
    final headerBytes = header.writeToBuffer();

    // Increment the send counter
    ns++;

    final newAd = concat([sessionAd, headerBytes]);
    final hmac = await truncatedHmac(newAd, keys.authenticationKey);
    return OMEMOAuthenticatedMessage()
      ..mac = hmac
      ..message = headerBytes;
  }

  /// Returns a copy of the ratchet.
  OmemoDoubleRatchet clone() {
    return OmemoDoubleRatchet(
      dhs,
      dhr,
      rk,
      cks != null ? List<int>.from(cks!) : null,
      ckr != null ? List<int>.from(ckr!) : null,
      ns,
      nr,
      pn,
      ik,
      sessionAd,
      Map<SkippedKey, List<int>>.from(mkSkipped),
      acknowledged,
      kex,
    );
  }

  /// Computes the fingerprint of the double ratchet, according to
  /// XEP-0384.
  Future<String> get fingerprint async {
    final curveKey = await ik.toCurve25519();
    return HEX.encode(
      await curveKey.getBytes(),
    );
  }

  @visibleForTesting
  Future<bool> equals(OmemoDoubleRatchet other) async {
    final dhrMatch = dhr == null
        ? other.dhr == null
        :
        // ignore: invalid_use_of_visible_for_testing_member
        other.dhr != null && await dhr!.equals(other.dhr!);
    final ckrMatch = ckr == null
        ? other.ckr == null
        : other.ckr != null && listsEqual(ckr!, other.ckr!);
    final cksMatch = cks == null
        ? other.cks == null
        : other.cks != null && listsEqual(cks!, other.cks!);

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
        listsEqual(sessionAd, other.sessionAd);
  }
}
