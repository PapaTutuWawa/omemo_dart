import 'dart:async';
import 'dart:convert';
import 'package:collection/collection.dart';
import 'package:cryptography/cryptography.dart';
import 'package:hex/hex.dart';
import 'package:logging/logging.dart';
import 'package:meta/meta.dart';
import 'package:omemo_dart/src/crypto.dart';
import 'package:omemo_dart/src/double_ratchet/double_ratchet.dart';
import 'package:omemo_dart/src/errors.dart';
import 'package:omemo_dart/src/helpers.dart';
import 'package:omemo_dart/src/keys.dart';
import 'package:omemo_dart/src/omemo/bundle.dart';
import 'package:omemo_dart/src/omemo/device.dart';
import 'package:omemo_dart/src/omemo/encrypted_key.dart';
import 'package:omemo_dart/src/omemo/encryption_result.dart';
import 'package:omemo_dart/src/omemo/events.dart';
import 'package:omemo_dart/src/omemo/fingerprint.dart';
import 'package:omemo_dart/src/omemo/ratchet_map_key.dart';
import 'package:omemo_dart/src/protobuf/omemo_authenticated_message.dart';
import 'package:omemo_dart/src/protobuf/omemo_key_exchange.dart';
import 'package:omemo_dart/src/protobuf/omemo_message.dart';
import 'package:omemo_dart/src/trust/base.dart';
import 'package:omemo_dart/src/x3dh/x3dh.dart';
import 'package:synchronized/synchronized.dart';

/// The info used for when encrypting the AES key for the actual payload.
const omemoPayloadInfoString = 'OMEMO Payload';

class OmemoSessionManager {

  OmemoSessionManager(this._device, this._deviceMap, this._ratchetMap, this._trustManager)
    : _lock = Lock(),
      _deviceLock = Lock(),
      _eventStreamController = StreamController<OmemoEvent>.broadcast(),
      _log = Logger('OmemoSessionManager');

  /// Deserialise the OmemoSessionManager from JSON data [data] that does not contain
  /// the ratchet sessions.
  factory OmemoSessionManager.fromJsonWithoutSessions(
    Map<String, dynamic> data,
    Map<RatchetMapKey, OmemoDoubleRatchet> ratchetMap,
    TrustManager trustManager,
  ) {
    // NOTE: Dart has some issues with just casting a List<dynamic> to List<Map<...>>, as
    //       such we need to convert the items by hand.
    return OmemoSessionManager(
      Device.fromJson(data['device']! as Map<String, dynamic>),
      (data['devices']! as Map<String, dynamic>).map<String, List<int>>(
        (key, value) {
          return MapEntry(
            key,
            (value as List<dynamic>).map<int>((i) => i as int).toList(),
          );
        }
      ),
      ratchetMap,
      trustManager,
    );
  }
  
  /// Generate a new cryptographic identity.
  static Future<OmemoSessionManager> generateNewIdentity(String jid, TrustManager trustManager, { int opkAmount = 100 }) async {
    assert(opkAmount > 0, 'opkAmount must be bigger than 0.');
    final device = await Device.generateNewDevice(jid, opkAmount: opkAmount);

    return OmemoSessionManager(device, {}, {}, trustManager);
  }

  /// Logging
  Logger _log;
  
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

  /// The trust manager
  final TrustManager _trustManager;
  TrustManager get trustManager => _trustManager;
  
  /// A stream that receives events regarding the session
  Stream<OmemoEvent> get eventStream => _eventStreamController.stream;

  /// Returns our own device.
  Future<Device> getDevice() async {
    return _deviceLock.synchronized(() => _device);
  }

  /// Returns the id attribute of our own device. This is just a short-hand for
  /// ```await (session.getDevice()).id```.
  Future<int> getDeviceId() async {
    return _deviceLock.synchronized(() => _device.id);
  }

  /// Returns the device as an OmemoBundle. This is just a short-hand for
  /// ```await (await session.getDevice()).toBundle()```.
  Future<OmemoBundle> getDeviceBundle() async {
    return _deviceLock.synchronized(() async => _device.toBundle());
  }
  
  /// Add a session [ratchet] with the [deviceId] to the internal tracking state.
  Future<void> _addSession(String jid, int deviceId, OmemoDoubleRatchet ratchet) async {
    await _lock.synchronized(() async {
      // Add the bundle Id
      if (!_deviceMap.containsKey(jid)) {
        _deviceMap[jid] = [deviceId];

        // Commit the device map
        _eventStreamController.add(DeviceMapModifiedEvent(_deviceMap));
      } else {
        // Prevent having the same device multiple times in the list
        if (!_deviceMap[jid]!.contains(deviceId)) {
          _deviceMap[jid]!.add(deviceId);

          // Commit the device map
          _eventStreamController.add(DeviceMapModifiedEvent(_deviceMap));
        }
      }

      // Add the ratchet session
      final key = RatchetMapKey(jid, deviceId);
      _ratchetMap[key] = ratchet;

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
      bundle.ik,
      kexResult.sk,
      kexResult.ad,
    );

    await _trustManager.onNewSession(jid, deviceId);
    await _addSession(jid, deviceId, ratchet);

    return OmemoKeyExchange()
      ..pkId = kexResult.opkId
      ..spkId = bundle.spkId
      ..ik = await device.ik.pk.getBytes()
      ..ek = await kexResult.ek.pk.getBytes();
  }

  /// Build a new session with the user at [jid] with the device [deviceId] using data
  /// from the key exchange [kex]. In case [kex] contains an unknown Signed Prekey
  /// identifier an UnknownSignedPrekeyException will be thrown.
  Future<void> _addSessionFromKeyExchange(String jid, int deviceId, OmemoKeyExchange kex) async {
    // Pick the correct SPK
    final device = await getDevice();
    final spk = await _lock.synchronized(() async {
      if (kex.spkId == _device.spkId) {
        return _device.spk;
      } else if (kex.spkId == _device.oldSpkId) {
        return _device.oldSpk;
      }

      return null;
    });
    if (spk == null) {
      throw UnknownSignedPrekeyException();
    }
    
    final kexResult = await x3dhFromInitialMessage(
      X3DHMessage(
        OmemoPublicKey.fromBytes(kex.ik!, KeyPairType.ed25519),
        OmemoPublicKey.fromBytes(kex.ek!, KeyPairType.x25519),
        kex.pkId!,
      ),
      spk,
      device.opks.values.elementAt(kex.pkId!),
      device.ik,
    );
    final ratchet = await OmemoDoubleRatchet.acceptNewSession(
      spk,
      OmemoPublicKey.fromBytes(kex.ik!, KeyPairType.ed25519),
      kexResult.sk,
      kexResult.ad,
    );

    await _trustManager.onNewSession(jid, deviceId);
    await _addSession(jid, deviceId, ratchet);
  }

  /// Like [encryptToJids] but only for one Jid [jid].
  Future<EncryptionResult> encryptToJid(String jid, String? plaintext, { List<OmemoBundle>? newSessions }) {
    return encryptToJids([jid], plaintext, newSessions: newSessions);
  }
  
  /// Encrypt the key [plaintext] for all known bundles of the Jids in [jids]. Returns a
  /// map that maps the device Id to the ciphertext of [plaintext].
  ///
  /// If [plaintext] is null, then the result will be an empty OMEMO message, i.e. one that
  /// does not contain a <payload /> element. This means that the ciphertext attribute of
  /// the result will be null as well.
  Future<EncryptionResult> encryptToJids(List<String> jids, String? plaintext, { List<OmemoBundle>? newSessions }) async {
    final encryptedKeys = List<EncryptedKey>.empty(growable: true);

    var ciphertext = const <int>[];
    var keyPayload = const <int>[];
    if (plaintext != null) {
      // Generate the key and encrypt the plaintext
      final key = generateRandomBytes(32);
      final keys = await deriveEncryptionKeys(key, omemoPayloadInfoString);
      ciphertext = await aes256CbcEncrypt(
        utf8.encode(plaintext),
        keys.encryptionKey,
        keys.iv,
      );
      final hmac = await truncatedHmac(ciphertext, keys.authenticationKey);
      keyPayload = concat([key, hmac]);
    } else {
      keyPayload = List<int>.filled(32, 0x0);
    }

    final kex = <int, OmemoKeyExchange>{};
    if (newSessions != null) {
      for (final newSession in newSessions) {
        kex[newSession.id] = await addSessionFromBundle(newSession.jid, newSession.id, newSession);
      }
    }
    
    await _lock.synchronized(() async {
      // We assume that the user already checked if the session exists
      for (final jid in jids) {
        for (final deviceId in _deviceMap[jid]!) {
          // Empty OMEMO messages are allowed to bypass trust
          if (plaintext != null) {
            // Only encrypt to devices that are trusted
            if (!(await _trustManager.isTrusted(jid, deviceId))) continue;

            // Onyl encrypt to devices that are enabled
            if (!(await _trustManager.isEnabled(jid, deviceId))) continue;
          }

          final ratchetKey = RatchetMapKey(jid, deviceId);
          final ratchet = _ratchetMap[ratchetKey]!;
          final ciphertext = (await ratchet.ratchetEncrypt(keyPayload)).ciphertext;

          // Commit the ratchet
          _eventStreamController.add(RatchetModifiedEvent(jid, deviceId, ratchet));
          
          if (kex.isNotEmpty && kex.containsKey(deviceId)) {
            final k = kex[deviceId]!
              ..message = OmemoAuthenticatedMessage.fromBuffer(ciphertext);
            encryptedKeys.add(
              EncryptedKey(
                jid,
                deviceId,
                base64.encode(k.writeToBuffer()),
                true,
              ),
            );
          } else {
            encryptedKeys.add(
              EncryptedKey(
                jid,
                deviceId,
                base64.encode(ciphertext),
                false,
              ),
            );
          }
        }
      }
    });

    return EncryptionResult(
      plaintext != null ? ciphertext : null,
      encryptedKeys,
    );
  }

  /// In case a decryption error occurs, the Double Ratchet spec says to just restore
  /// the ratchet to its old state. As such, this function restores the ratchet at
  /// [mapKey] with [oldRatchet].
  Future<void> _restoreRatchet(RatchetMapKey mapKey, OmemoDoubleRatchet oldRatchet) async {
    await _lock.synchronized(() {
      _log.finest('Restoring ratchet ${mapKey.jid}:${mapKey.deviceId}');
      _ratchetMap[mapKey] = oldRatchet;

      // Commit the ratchet
      _eventStreamController.add(
        RatchetModifiedEvent(
          mapKey.jid,
          mapKey.deviceId,
          oldRatchet,
        ),
      );
    });
  }
  
  /// Attempt to decrypt [ciphertext]. [keys] refers to the <key /> elements inside the
  /// <keys /> element with a "jid" attribute matching our own. [senderJid] refers to the
  /// bare Jid of the sender. [senderDeviceId] refers to the "sid" attribute of the
  /// <encrypted /> element.
  ///
  /// If the received message is an empty OMEMO message, i.e. there is no <payload />
  /// element, then [ciphertext] must be set to null. In this case, this function
  /// will return null as there is no message to be decrypted. This, however, is used
  /// to set up sessions or advance the ratchets.
  Future<String?> decryptMessage(List<int>? ciphertext, String senderJid, int senderDeviceId, List<EncryptedKey> keys) async {
    // Try to find a session we can decrypt with.
    var device = await getDevice();
    final rawKey = keys.firstWhereOrNull((key) => key.rid == device.id);
    if (rawKey == null) {
      throw NotEncryptedForDeviceException();
    }

    final ratchetKey = RatchetMapKey(senderJid, senderDeviceId);
    final decodedRawKey = base64.decode(rawKey.value);
    OmemoAuthenticatedMessage authMessage;
    OmemoDoubleRatchet? oldRatchet;
    if (rawKey.kex) {
      // If the ratchet already existed, we store it. If it didn't, oldRatchet will stay
      // null.
      oldRatchet = await _getRatchet(ratchetKey);

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
    List<int>? keyAndHmac;
    // We can guarantee that the ratchet exists at this point in time
    final ratchet = (await _getRatchet(ratchetKey))!;
    oldRatchet ??= ratchet ;

    try {
      if (rawKey.kex) {
        keyAndHmac = await ratchet.ratchetDecrypt(message, authMessage.writeToBuffer());
      } else {
        keyAndHmac = await ratchet.ratchetDecrypt(message, decodedRawKey);
      }
    } catch (_) {
      await _restoreRatchet(ratchetKey, oldRatchet);
      rethrow;
    }

    // Commit the ratchet
    _eventStreamController.add(RatchetModifiedEvent(senderJid, senderDeviceId, ratchet));

    // Empty OMEMO messages should just have the key decrypted and/or session set up.
    if (ciphertext == null) {
      return null;
    }
    
    final key = keyAndHmac.sublist(0, 32);
    final hmac = keyAndHmac.sublist(32, 48);
    final derivedKeys = await deriveEncryptionKeys(key, omemoPayloadInfoString);

    final computedHmac = await truncatedHmac(ciphertext, derivedKeys.authenticationKey);
    if (!listsEqual(hmac, computedHmac)) {
      // TODO(PapaTutuWawa): I am unsure if we should restore the ratchet here
      await _restoreRatchet(ratchetKey, oldRatchet);
      throw InvalidMessageHMACException();
    }
    
    final plaintext = await aes256CbcDecrypt(ciphertext, derivedKeys.encryptionKey, derivedKeys.iv);
    return utf8.decode(plaintext);
  }

  /// Returns the list of hex-encoded fingerprints we have for sessions with [jid].
  Future<List<DeviceFingerprint>> getHexFingerprintsForJid(String jid) async {
    final fingerprints = List<DeviceFingerprint>.empty(growable: true);

    await _lock.synchronized(() async {
      // Get devices for jid
      final devices = _deviceMap[jid] ?? [];

      for (final deviceId in devices) {
        final ratchet = _ratchetMap[RatchetMapKey(jid, deviceId)]!;

        fingerprints.add(
          DeviceFingerprint(
            deviceId,
            HEX.encode(await ratchet.ik.getBytes()),
          ),
        );
      }
    });

    return fingerprints;
  }

  /// Returns the hex-encoded fingerprint of the current device.
  Future<DeviceFingerprint> getHexFingerprintForDevice() async {
    final device = await getDevice();

    return DeviceFingerprint(
      device.id,
      HEX.encode(await device.ik.pk.getBytes()),
    );
  }

  /// Replaces the Signed Prekey and its signature in our own device bundle. Triggers
  /// a DeviceModifiedEvent when done.
  /// See https://xmpp.org/extensions/xep-0384.html#protocol-key_exchange under the point
  /// "signed PreKey rotation period" for recommendations.
  Future<void> rotateSignedPrekey() async {
    await _deviceLock.synchronized(() async {
      _device = await _device.replaceSignedPrekey();

      // Commit the new device
      _eventStreamController.add(DeviceModifiedEvent(_device));
    });
  }

  /// Returns the device map, i.e. the mapping of bare Jid to its device identifiers
  /// we have built sessions with.
  Future<Map<String, List<int>>> getDeviceMap() async {
    return _lock.synchronized(() => _deviceMap);
  }

  /// Removes the ratchet identified by [jid] and [deviceId] from the session manager.
  /// Also triggers events for commiting the new device map to storage and removing
  /// the old ratchet.
  Future<void> removeRatchet(String jid, int deviceId) async {
    await _lock.synchronized(() async {
      // Remove the ratchet
      _ratchetMap.remove(RatchetMapKey(jid, deviceId));
      // Commit it
      _eventStreamController.add(RatchetRemovedEvent(jid, deviceId));

      // Remove the device from jid
      _deviceMap[jid]!.remove(deviceId);
      if (_deviceMap[jid]!.isEmpty) {
        _deviceMap.remove(jid);
      }
      // Commit it
      _eventStreamController.add(DeviceMapModifiedEvent(_deviceMap));
    });
  }

  /// Removes all ratchets for Jid [jid]. Triggers a DeviceMapModified event at the end and an
  /// RatchetRemovedEvent for each ratchet.
  Future<void> removeAllRatchets(String jid) async {
    await _lock.synchronized(() async {
      for (final deviceId in _deviceMap[jid]!) {
        // Remove the ratchet
        _ratchetMap.remove(RatchetMapKey(jid, deviceId));
        // Commit it
        _eventStreamController.add(RatchetRemovedEvent(jid, deviceId));
      }

      // Remove the device from jid
      _deviceMap.remove(jid);
      // Commit it
      _eventStreamController.add(DeviceMapModifiedEvent(_deviceMap));
    });
  }
  
  /// Returns the list of device identifiers belonging to [jid] that are yet unacked, i.e.
  /// we have not yet received an empty OMEMO message from.
  Future<List<int>?> getUnacknowledgedRatchets(String jid) async {
    return _lock.synchronized(() async {
      final ret = List<int>.empty(growable: true);
      final devices = _deviceMap[jid];
      if (devices == null) return null;

      for (final device in devices) {
        final ratchet = _ratchetMap[RatchetMapKey(jid, device)]!;
        if (!ratchet.acknowledged) ret.add(device);
      }

      return ret;
    });
  }

  /// Returns true if the ratchet for [jid] with device identifier [deviceId] is
  /// acknowledged. Returns false if not.
  Future<bool> isRatchetAcknowledged(String jid, int deviceId) async {
    return _lock.synchronized(() => _ratchetMap[RatchetMapKey(jid, deviceId)]!.acknowledged);
  }
  
  /// Mark the ratchet for device [deviceId] from [jid] as acked.
  Future<void> ratchetAcknowledged(String jid, int deviceId) async {
    await _lock.synchronized(() async {
      final ratchet = _ratchetMap[RatchetMapKey(jid, deviceId)]!
        ..acknowledged = true;

      // Commit it
      _eventStreamController.add(RatchetModifiedEvent(jid, deviceId, ratchet));
    });
  }

  /// Generates an entirely new device. May be useful when the user wants to reset their cryptographic
  /// identity. Triggers an event to commit it to storage.
  Future<void> regenerateDevice({ int opkAmount = 100 }) async {
    await _deviceLock.synchronized(() async {
      _device = await Device.generateNewDevice(_device.jid, opkAmount: opkAmount);

      // Commit it
      _eventStreamController.add(DeviceModifiedEvent(_device));
    });
  }

  /// Make our device have a new identifier. Only useful before publishing it as a bundle
  /// to make sure that our device has a id that is account unique.
  Future<void> regenerateDeviceId() async {
    await _deviceLock.synchronized(() async {
      _device = _device.withNewId();

      // Commit it
      _eventStreamController.add(DeviceModifiedEvent(_device));
    });
  }

  Future<OmemoDoubleRatchet?> _getRatchet(RatchetMapKey key) async {
    return _lock.synchronized(() async {
      return _ratchetMap[key];
    });
  }
  
  @visibleForTesting
  OmemoDoubleRatchet getRatchet(String jid, int deviceId) => _ratchetMap[RatchetMapKey(jid, deviceId)]!;

  @visibleForTesting
  Map<RatchetMapKey, OmemoDoubleRatchet> getRatchetMap() => _ratchetMap;

  /// Serialise the entire session manager into a JSON object.
  Future<Map<String, dynamic>> toJsonWithoutSessions() async {
    /*
    {
      'devices': {
        'alice@...': [1, 2, ...],
        'bob@...': [1],
        ...
      },
      'device': { ... },
    }
    */

    return {
      'devices': _deviceMap,
      'device': await (await getDevice()).toJson(),
    };
  }
}
