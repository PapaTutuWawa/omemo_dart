import 'dart:async';
import 'dart:convert';
import 'package:collection/collection.dart';
import 'package:cryptography/cryptography.dart';
import 'package:meta/meta.dart';
import 'package:omemo_dart/src/crypto.dart';
import 'package:omemo_dart/src/double_ratchet/double_ratchet.dart';
import 'package:omemo_dart/src/errors.dart';
import 'package:omemo_dart/src/events.dart';
import 'package:omemo_dart/src/helpers.dart';
import 'package:omemo_dart/src/keys.dart';
import 'package:omemo_dart/src/omemo/bundle.dart';
import 'package:omemo_dart/src/omemo/device.dart';
import 'package:omemo_dart/src/protobuf/omemo_authenticated_message.dart';
import 'package:omemo_dart/src/protobuf/omemo_key_exchange.dart';
import 'package:omemo_dart/src/protobuf/omemo_message.dart';
import 'package:omemo_dart/src/x3dh/x3dh.dart';
import 'package:synchronized/synchronized.dart';

/// The info used for when encrypting the AES key for the actual payload.
const omemoPayloadInfoString = 'OMEMO Payload';

@immutable
class EncryptionResult {

  const EncryptionResult(this.ciphertext, this.encryptedKeys);
  
  /// The actual message that was encrypted
  final List<int> ciphertext;

  /// Mapping of the device Id to the key for decrypting ciphertext, encrypted
  /// for the ratchet with said device Id
  final List<EncryptedKey> encryptedKeys;
}

@immutable
class EncryptedKey {

  const EncryptedKey(this.rid, this.value, this.kex);
  final int rid;
  final String value;
  final bool kex;
}

@immutable
class RatchetMapKey {

  const RatchetMapKey(this.jid, this.deviceId);
  final String jid;
  final int deviceId;

  @override
  bool operator ==(Object other) {
    return other is RatchetMapKey && jid == other.jid && deviceId == other.deviceId;
  }

  @override
  int get hashCode => jid.hashCode ^ deviceId.hashCode;
}

class OmemoSessionManager {

  OmemoSessionManager(this._device, this._deviceMap, this._ratchetMap)
    : _lock = Lock(),
      _deviceLock = Lock(),
      _eventStreamController = StreamController<OmemoEvent>.broadcast();

  /// Deserialise the OmemoSessionManager from JSON data [data].
  factory OmemoSessionManager.fromJson(Map<String, dynamic> data) {
    final ratchetMap = <RatchetMapKey, OmemoDoubleRatchet>{};
    for (final rawRatchet in data['sessions']! as List<Map<String, dynamic>>) {
      final key = RatchetMapKey(rawRatchet['jid']! as String, rawRatchet['deviceId']! as int);
      final ratchet = OmemoDoubleRatchet.fromJson(rawRatchet['ratchet']! as Map<String, dynamic>);
      ratchetMap[key] = ratchet;
    }

    // TODO(PapaTutuWawa): Handle Trust behaviour
    return OmemoSessionManager(
      Device.fromJson(data['device']! as Map<String, dynamic>),
      data['devices']! as Map<String, List<int>>,
      ratchetMap,
    );
  }
      
  /// Generate a new cryptographic identity.
  static Future<OmemoSessionManager> generateNewIdentity({ int opkAmount = 100 }) async {
    assert(opkAmount > 0, 'opkAmount must be bigger than 0.');
    final device = await Device.generateNewDevice(opkAmount: opkAmount);

    return OmemoSessionManager(device, {}, {});
  }
  
  /// Lock for _ratchetMap and _bundleMap
  final Lock _lock;

  /// Mapping of the Device Id to its OMEMO session
  final Map<RatchetMapKey, OmemoDoubleRatchet> _ratchetMap;

  /// Mapping of a bare Jid to its Device Ids
  final Map<String, List<int>> _deviceMap;

  /// The event bus of the session manager
  final StreamController<OmemoEvent> _eventStreamController;
  
  /// Our own keys...
  // ignore: prefer_final_fields
  Device _device;
  /// and its lock
  final Lock _deviceLock;

  /// A stream that receives events regarding the session
  Stream<OmemoEvent> get eventStream => _eventStreamController.stream;

  Future<Device> getDevice() async {
    Device? dev;
    await _deviceLock.synchronized(() async {
      dev = _device;
    });

    return dev!;
  }
  
  /// Add a session [ratchet] with the [deviceId] to the internal tracking state.
  Future<void> _addSession(String jid, int deviceId, OmemoDoubleRatchet ratchet) async {
    await _lock.synchronized(() async {
      // Add the bundle Id
      if (!_deviceMap.containsKey(jid)) {
        _deviceMap[jid] = [deviceId];
      } else {
        _deviceMap[jid]!.add(deviceId);
      }

      // Commit the device map
      _eventStreamController.add(DeviceMapModifiedEvent(_deviceMap));

      // Add the ratchet session
      final key = RatchetMapKey(jid, deviceId);
      if (!_ratchetMap.containsKey(key)) {
        _ratchetMap[key] = ratchet;
      } else {
        // TODO(PapaTutuWawa): What do we do now?
        throw Exception();
      }

      // Commit the ratchet
      _eventStreamController.add(RatchetModifiedEvent(jid, deviceId, ratchet));
    });
  }

  /// Create a ratchet session initiated by Alice to the user with Jid [jid] and the device
  /// [deviceId] from the bundle [bundle].
  @visibleForTesting
  Future<OmemoKeyExchange> addSessionFromBundle(String jid, int deviceId, OmemoBundle bundle) async {
    final device = await getDevice();
    final kexResult = await x3dhFromBundle(
      bundle,
      device.ik,
    );
    final ratchet = await OmemoDoubleRatchet.initiateNewSession(
      bundle.spk,
      kexResult.sk,
      kexResult.ad,
    );

    await _addSession(jid, deviceId, ratchet);

    return OmemoKeyExchange()
      ..pkId = kexResult.opkId
      ..spkId = 0
      ..ik = await device.ik.pk.getBytes()
      ..ek = await kexResult.ek.pk.getBytes();
  }

  /// Build a new session with the user at [jid] with the device [deviceId] using data
  /// from the key exchange [kex].
  Future<void> _addSessionFromKeyExchange(String jid, int deviceId, OmemoKeyExchange kex) async {
    final device = await getDevice();
    final kexResult = await x3dhFromInitialMessage(
      X3DHMessage(
        OmemoPublicKey.fromBytes(kex.ik!, KeyPairType.ed25519),
        OmemoPublicKey.fromBytes(kex.ek!, KeyPairType.x25519),
        kex.pkId!,
      ),
      device.spk,
      device.opks.values.elementAt(kex.pkId!),
      device.ik,
    );
    final ratchet = await OmemoDoubleRatchet.acceptNewSession(
      device.spk,
      kexResult.sk,
      kexResult.ad,
    );

    await _addSession(jid, deviceId, ratchet);
  }
  
  /// Encrypt the key [plaintext] for all known bundles of [jid]. Returns a map that
  /// maps the Bundle Id to the ciphertext of [plaintext].
  Future<EncryptionResult> encryptToJid(String jid, String plaintext, { List<OmemoBundle>? newSessions }) async {
    final encryptedKeys = List<EncryptedKey>.empty(growable: true);

    // Generate the key and encrypt the plaintext
    final key = generateRandomBytes(32);
    final keys = await deriveEncryptionKeys(key, omemoPayloadInfoString);
    final ciphertext = await aes256CbcEncrypt(
      utf8.encode(plaintext),
      keys.encryptionKey,
      keys.iv,
    );
    final hmac = await truncatedHmac(ciphertext, keys.authenticationKey);
    final concatKey = concat([key, hmac]);

    final kex = <int, OmemoKeyExchange>{};
    if (newSessions != null) {
      for (final newSession in newSessions) {
        kex[newSession.id] = await addSessionFromBundle(jid, newSession.id, newSession);
      }
    }
    
    await _lock.synchronized(() async {
      // We assume that the user already checked if the session exists
      for (final deviceId in _deviceMap[jid]!) {
        final ratchetKey = RatchetMapKey(jid, deviceId);
        final ratchet = _ratchetMap[ratchetKey]!;
        final ciphertext = (await ratchet.ratchetEncrypt(concatKey)).ciphertext;

        // Commit the ratchet
        _eventStreamController.add(RatchetModifiedEvent(jid, deviceId, ratchet));
        
        if (kex.isNotEmpty && kex.containsKey(deviceId)) {
          final k = kex[deviceId]!
            ..message = OmemoAuthenticatedMessage.fromBuffer(ciphertext);
          encryptedKeys.add(
            EncryptedKey(
              deviceId,
              base64.encode(k.writeToBuffer()),
              true,
            ),
          );
        } else {
          encryptedKeys.add(
            EncryptedKey(
              deviceId,
              base64.encode(ciphertext),
              false,
            ),
          );
        }
      }
    });

    return EncryptionResult(
      ciphertext,
      encryptedKeys,
    );
  }

  /// Attempt to decrypt [ciphertext]. [keys] refers to the <key /> elements inside the
  /// <keys /> element with a "jid" attribute matching our own. [senderJid] refers to the
  /// bare Jid of the sender. [senderDeviceId] refers to the "sid" attribute of the
  /// <encrypted /> element.
  Future<String> decryptMessage(List<int> ciphertext, String senderJid, int senderDeviceId, List<EncryptedKey> keys) async {
    // Try to find a session we can decrypt with.
    var device = await getDevice();
    final rawKey = keys.firstWhereOrNull((key) => key.rid == device.id);
    if (rawKey == null) {
      throw NotEncryptedForDeviceException();
    }

    final decodedRawKey = base64.decode(rawKey.value);
    OmemoAuthenticatedMessage authMessage;
    if (rawKey.kex) {
      // TODO(PapaTutuWawa): Only do this when we should
      final kex = OmemoKeyExchange.fromBuffer(decodedRawKey);
      await _addSessionFromKeyExchange(
        senderJid,
        senderDeviceId,
        kex,
      );

      authMessage = kex.message!;

      // Replace the OPK
      await _deviceLock.synchronized(() async {
        device = await device.replaceOnetimePrekey(kex.pkId!);

        // Commit the device
        _eventStreamController.add(DeviceModifiedEvent(device));
      });
    } else {
      authMessage = OmemoAuthenticatedMessage.fromBuffer(decodedRawKey);
    }
    
    final devices = _deviceMap[senderJid];
    if (devices == null) {
      throw NoDecryptionKeyException();
    }
    if (!devices.contains(senderDeviceId)) {
      throw NoDecryptionKeyException();
    }

    final message = OmemoMessage.fromBuffer(authMessage.message!);
    final ratchetKey = RatchetMapKey(senderJid, senderDeviceId);
    List<int>? keyAndHmac;
    await _lock.synchronized(() async {
      final ratchet = _ratchetMap[ratchetKey]!;
      if (rawKey.kex) {
        keyAndHmac = await ratchet.ratchetDecrypt(message, authMessage.writeToBuffer());
      } else {
        keyAndHmac = await ratchet.ratchetDecrypt(message, decodedRawKey);
      }

      // Commit the ratchet
      _eventStreamController.add(RatchetModifiedEvent(senderJid, senderDeviceId, ratchet));
    });

    final key = keyAndHmac!.sublist(0, 32);
    final hmac = keyAndHmac!.sublist(32, 48);
    final derivedKeys = await deriveEncryptionKeys(key, omemoPayloadInfoString);

    final computedHmac = await truncatedHmac(ciphertext, derivedKeys.authenticationKey);
    if (!listsEqual(hmac, computedHmac)) {
      throw InvalidMessageHMACException();
    }

    final plaintext = await aes256CbcDecrypt(ciphertext, derivedKeys.encryptionKey, derivedKeys.iv);
    return utf8.decode(plaintext);
  }

  @visibleForTesting
  OmemoDoubleRatchet getRatchet(String jid, int deviceId) => _ratchetMap[RatchetMapKey(jid, deviceId)]!;

  @visibleForTesting
  Map<String, List<int>> getDeviceMap() => _deviceMap;

  @visibleForTesting
  Map<RatchetMapKey, OmemoDoubleRatchet> getRatchetMap() => _ratchetMap;

  /// Serialise the entire session manager into a JSON object.
  Future<Map<String, dynamic>> toJson() async {
    /*
    {
      'devices': {
        'alice@...': [1, 2, ...],
        'bob@...': [1],
        ...
      },
      'device': { ... },
      'sessions': [
        {
          'jid': 'alice@...',
          'deviceId': 1,
          'ratchet': { ... },
        },
        ...
      ],
      'trust': { ... }
    }
    */

    final sessions = List<Map<String, dynamic>>.empty(growable: true);
    for (final entry in _ratchetMap.entries) {
      sessions.add({
        'jid': entry.key.jid,
        'deviceId': entry.key.deviceId,
        'ratchet': await entry.value.toJson(),
      });
    }
    return {
      'devices': _deviceMap,
      'device': await (await getDevice()).toJson(),
      'sessions': sessions,
      // TODO(PapaTutuWawa): Implement
      'trust': <String, dynamic>{},
    };
  }
}
