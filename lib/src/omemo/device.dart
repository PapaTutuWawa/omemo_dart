import 'dart:convert';
import 'package:cryptography/cryptography.dart';
import 'package:hex/hex.dart';
import 'package:meta/meta.dart';
import 'package:omemo_dart/src/helpers.dart';
import 'package:omemo_dart/src/keys.dart';
import 'package:omemo_dart/src/omemo/bundle.dart';
import 'package:omemo_dart/src/x3dh/x3dh.dart';

/// This class represents an OmemoBundle but with all keypairs belonging to the keys
@immutable
class OmemoDevice {
  const OmemoDevice(
    this.jid,
    this.id,
    this.ik,
    this.spk,
    this.spkId,
    this.spkSignature,
    this.oldSpk,
    this.oldSpkId,
    this.opks,
  );

  /// Generate a completely new device, i.e. cryptographic identity.
  static Future<OmemoDevice> generateNewDevice(
    String jid, {
    int opkAmount = 100,
  }) async {
    final id = generateRandom32BitNumber();
    final ik = await OmemoKeyPair.generateNewPair(KeyPairType.ed25519);
    final spk = await OmemoKeyPair.generateNewPair(KeyPairType.x25519);
    final spkId = generateRandom32BitNumber();
    final signature = await sig(ik, await spk.pk.getBytes());

    final opks = <int, OmemoKeyPair>{};
    for (var i = 0; i < opkAmount; i++) {
      opks[i] = await OmemoKeyPair.generateNewPair(KeyPairType.x25519);
    }

    return OmemoDevice(jid, id, ik, spk, spkId, signature, null, null, opks);
  }

  /// Our bare Jid
  final String jid;

  /// The device Id
  final int id;

  /// The identity key
  final OmemoKeyPair ik;

  /// The signed prekey...
  final OmemoKeyPair spk;

  /// ...its Id, ...
  final int spkId;

  /// ...and its signature
  final List<int> spkSignature;

  /// The old Signed Prekey...
  final OmemoKeyPair? oldSpk;

  /// ...and its Id
  final int? oldSpkId;

  /// Map of an id to the associated Onetime-Prekey
  final Map<int, OmemoKeyPair> opks;

  /// This replaces the Onetime-Prekey with id [id] with a completely new one. Returns
  /// a new Device object that copies over everything but replaces said key.
  @internal
  Future<OmemoDevice> replaceOnetimePrekey(int id) async {
    opks[id] = await OmemoKeyPair.generateNewPair(KeyPairType.x25519);

    return OmemoDevice(
      jid,
      this.id,
      ik,
      spk,
      spkId,
      spkSignature,
      oldSpk,
      oldSpkId,
      opks,
    );
  }

  /// This replaces the Signed-Prekey with a completely new one. Returns a new Device object
  /// that copies over everything but replaces the Signed-Prekey and its signature.
  @internal
  Future<OmemoDevice> replaceSignedPrekey() async {
    final newSpk = await OmemoKeyPair.generateNewPair(KeyPairType.x25519);
    final newSpkId = generateRandom32BitNumber();
    final newSignature = await sig(ik, await newSpk.pk.getBytes());

    return OmemoDevice(
      jid,
      id,
      ik,
      newSpk,
      newSpkId,
      newSignature,
      spk,
      spkId,
      opks,
    );
  }

  /// Returns a new device that is equal to this one with the exception that the new
  /// device's id is a new number between 0 and 2**32 - 1.
  @internal
  OmemoDevice withNewId() {
    return OmemoDevice(
      jid,
      generateRandom32BitNumber(),
      ik,
      spk,
      spkId,
      spkSignature,
      oldSpk,
      oldSpkId,
      opks,
    );
  }

  /// Converts this device into an OmemoBundle that could be used for publishing.
  Future<OmemoBundle> toBundle() async {
    final encodedOpks = <int, String>{};

    for (final opkKey in opks.keys) {
      encodedOpks[opkKey] = base64.encode(await opks[opkKey]!.pk.getBytes());
    }

    return OmemoBundle(
      jid,
      id,
      base64.encode(await spk.pk.getBytes()),
      spkId,
      base64.encode(spkSignature),
      base64.encode(await ik.pk.getBytes()),
      encodedOpks,
    );
  }

  /// Returns the fingerprint of the current device
  Future<String> getFingerprint() async {
    // Since the local key is Ed25519, we must convert it to Curve25519 first
    final curveKey = await ik.pk.toCurve25519();
    return HEX.encode(await curveKey.getBytes());
  }

  @visibleForTesting
  Future<bool> equals(OmemoDevice other) async {
    var opksMatch = true;
    if (opks.length != other.opks.length) {
      opksMatch = false;
    } else {
      for (final entry in opks.entries) {
        // ignore: invalid_use_of_visible_for_testing_member
        final matches =
            // ignore: invalid_use_of_visible_for_testing_member
            await other.opks[entry.key]?.equals(entry.value) ?? false;
        if (!matches) {
          opksMatch = false;
        }
      }
    }

    // ignore: invalid_use_of_visible_for_testing_member
    final ikMatch = await ik.equals(other.ik);
    // ignore: invalid_use_of_visible_for_testing_member
    final spkMatch = await spk.equals(other.spk);
    // ignore: invalid_use_of_visible_for_testing_member
    final oldSpkMatch = oldSpk != null
        // ignore: invalid_use_of_visible_for_testing_member
        ? await oldSpk!.equals(other.oldSpk!)
        : other.oldSpk == null;
    return id == other.id &&
        ikMatch &&
        spkMatch &&
        oldSpkMatch &&
        jid == other.jid &&
        listsEqual(spkSignature, other.spkSignature) &&
        spkId == other.spkId &&
        oldSpkId == other.oldSpkId &&
        opksMatch;
  }
}
