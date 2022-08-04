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
    final newOpk = await OmemoKeyPair.generateNewPair(KeyPairType.x25519);

    return Device(
      id,
      ik,
      spk,
      spkId,
      spkSignature,
      opks.map((keyId, opk) {
        if (keyId == id) {
          return MapEntry(id, newOpk);
        }

        return MapEntry(id, opk);
      }),
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
}
