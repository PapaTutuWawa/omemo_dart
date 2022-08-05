import 'dart:convert';
import 'package:cryptography/cryptography.dart';
import 'package:meta/meta.dart';
import 'package:omemo_dart/src/helpers.dart';
import 'package:omemo_dart/src/keys.dart';
import 'package:omemo_dart/src/omemo/bundle.dart';
import 'package:omemo_dart/src/x3dh/x3dh.dart';

/// This class represents an OmemoBundle but with all keypairs belonging to the keys
@immutable
class Device {

  const Device(this.id, this.ik, this.spk, this.spkId, this.spkSignature, this.opks);

  /// Deserialize the Device
  factory Device.fromJson(Map<String, dynamic> data) {
    // NOTE: We use the way OpenSSH names their keys, meaning that ik is the Identity
    //       Keypair's private key, while ik_pub refers to the Identity Keypair's public
    //       key.
    /*
    {
      'id': 123,
      'ik': 'base/64/encoded',
      'ik_pub': 'base/64/encoded',
      'spk': 'base/64/encoded',
      'spk_pub': 'base/64/encoded',
      'spk_id': 123,
      'spk_sig': 'base/64/encoded',
      'opks': [
        {
          'id': 0,
          'public': 'base/64/encoded',
          'private': 'base/64/encoded'
        }, ...
      ]
    }
    */
    final opks = <int, OmemoKeyPair>{};
    for (final opk in data['opks']! as List<Map<String, dynamic>>) {
      opks[opk['id']! as int] = OmemoKeyPair.fromBytes(
        base64.decode(opk['public']! as String),
        base64.decode(opk['private']! as String),
        KeyPairType.x25519,
      );
    }

    return Device(
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
      opks,
    );
  }
  
  /// Generate a completely new device, i.e. cryptographic identity.
  static Future<Device> generateNewDevice({ int opkAmount = 100 }) async {
    final id = generateRandom32BitNumber();
    final ik = await OmemoKeyPair.generateNewPair(KeyPairType.ed25519);
    final spk = await OmemoKeyPair.generateNewPair(KeyPairType.x25519);
    final spkId = generateRandom32BitNumber();
    final signature = await sig(ik, await spk.pk.getBytes());

    final opks = <int, OmemoKeyPair>{};
    for (var i = 0; i < opkAmount; i++) {
      opks[i] = await OmemoKeyPair.generateNewPair(KeyPairType.x25519);
    }

    return Device(id, ik, spk, spkId, signature, opks);
  }
  
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

  /// Map of an id to the associated Onetime-Prekey
  final Map<int, OmemoKeyPair> opks;

  /// This replaces the Onetime-Prekey with id [id] with a completely new one. Returns
  /// a new Device object that copies over everything but replaces said key.
  Future<Device> replaceOnetimePrekey(int id) async {
    opks[id] = await OmemoKeyPair.generateNewPair(KeyPairType.x25519);
    
    return Device(
      id,
      ik,
      spk,
      spkId,
      spkSignature,
      opks,
    );
  }

  /// This replaces the Signed-Prekey with a completely new one. Returns a new Device object
  /// that copies over everything but replaces the Signed-Prekey and its signature.
  Future<Device> replaceSignedPrekey() async {
    final newSpk = await OmemoKeyPair.generateNewPair(KeyPairType.x25519);
    final newSpkId = generateRandom32BitNumber();
    final newSignature = await sig(ik, await newSpk.pk.getBytes());

    return Device(
      id,
      ik,
      newSpk,
      newSpkId,
      newSignature,
      opks,
    );
  }

  Future<OmemoBundle> toBundle() async {
    final encodedOpks = <int, String>{};

    for (final opkKey in opks.keys) {
      encodedOpks[opkKey] = base64.encode(await opks[opkKey]!.pk.getBytes());
    }

    return OmemoBundle(
      id,
      base64.encode(await spk.pk.getBytes()),
      spkId,
      base64.encode(spkSignature),
      base64.encode(await ik.pk.getBytes()),
      encodedOpks,
    );
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
      'id': id,
      'ik': base64.encode(await ik.sk.getBytes()),
      'ik_pub': base64.encode(await ik.pk.getBytes()),
      'spk': base64.encode(await spk.sk.getBytes()),
      'spk_pub': base64.encode(await spk.pk.getBytes()),
      'spk_id': spkId,
      'spk_sig': base64.encode(spkSignature),
      'opks': serialisedOpks,
    };
  }
}
