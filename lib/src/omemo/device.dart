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

  /// Deserialize the Device
  factory OmemoDevice.fromJson(Map<String, dynamic> data) {
    // NOTE: We use the way OpenSSH names their keys, meaning that ik is the Identity
    //       Keypair's private key, while ik_pub refers to the Identity Keypair's public
    //       key.
    /*
    {
      'jid': 'alice@...',
      'id': 123,
      'ik': 'base/64/encoded',
      'ik_pub': 'base/64/encoded',
      'spk': 'base/64/encoded',
      'spk_pub': 'base/64/encoded',
      'spk_id': 123,
      'spk_sig': 'base/64/encoded',
      'old_spk': 'base/64/encoded',
      'old_spk_pub': 'base/64/encoded',
      'old_spk_id': 122,
      'opks': [
        {
          'id': 0,
          'public': 'base/64/encoded',
          'private': 'base/64/encoded'
        }, ...
      ]
    }
    */
    // NOTE: Dart has some issues with just casting a List<dynamic> to List<Map<...>>, as
    //       such we need to convert the items by hand.
    final opks = Map<int, OmemoKeyPair>.fromEntries(
      (data['opks']! as List<dynamic>).map<MapEntry<int, OmemoKeyPair>>(
        (opk) {
          final map = opk as Map<String, dynamic>;
          return MapEntry(
            map['id']! as int,
            OmemoKeyPair.fromBytes(
              base64.decode(map['public']! as String),
              base64.decode(map['private']! as String),
              KeyPairType.x25519,
            ),
          );
        },
      ),
    );

    return OmemoDevice(
      data['jid']! as String,
      data['id']! as int,
      OmemoKeyPair.fromBytes(
        base64.decode(data['ik_pub']! as String),
        base64.decode(data['ik']! as String),
        KeyPairType.ed25519,
      ),
      OmemoKeyPair.fromBytes(
        base64.decode(data['spk_pub']! as String),
        base64.decode(data['spk']! as String),
        KeyPairType.x25519,
      ),
      data['spk_id']! as int,
      base64.decode(data['spk_sig']! as String),
      decodeKeyPairIfNotNull(
        data['old_spk_pub'] as String?,
        data['old_spk'] as String?,
        KeyPairType.x25519,
      ),
      data['old_spk_id'] as int?,
      opks,
    );
  }
  
  /// Generate a completely new device, i.e. cryptographic identity.
  static Future<OmemoDevice> generateNewDevice(String jid, { int opkAmount = 100 }) async {
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
  
  /// Serialise the device information.
  Future<Map<String, dynamic>> toJson() async {
    /// Serialise the OPKs
    final serialisedOpks = List<Map<String, dynamic>>.empty(growable: true);
    for (final entry in opks.entries) {
      serialisedOpks.add({
        'id': entry.key,
        'public': base64.encode(await entry.value.pk.getBytes()),
        'private': base64.encode(await entry.value.sk.getBytes()),
      });
    }
    
    return {
      'jid': jid,
      'id': id,
      'ik': base64.encode(await ik.sk.getBytes()),
      'ik_pub': base64.encode(await ik.pk.getBytes()),
      'spk': base64.encode(await spk.sk.getBytes()),
      'spk_pub': base64.encode(await spk.pk.getBytes()),
      'spk_id': spkId,
      'spk_sig': base64.encode(spkSignature),
      'old_spk': base64EncodeIfNotNull(await oldSpk?.sk.getBytes()),
      'old_spk_pub': base64EncodeIfNotNull(await oldSpk?.pk.getBytes()),
      'old_spk_id': oldSpkId,
      'opks': serialisedOpks,
    };
  }

  @visibleForTesting
  Future<bool> equals(OmemoDevice other) async {
    var opksMatch = true;
    if (opks.length != other.opks.length) {
      opksMatch = false;
    } else {
      for (final entry in opks.entries) {
        // ignore: invalid_use_of_visible_for_testing_member
        final matches = await other.opks[entry.key]?.equals(entry.value) ?? false;
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
    final oldSpkMatch = oldSpk != null ? await oldSpk!.equals(other.oldSpk!) : other.oldSpk == null;
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
