import 'dart:async';
import 'dart:convert';
import 'package:collection/collection.dart';
import 'package:cryptography/cryptography.dart';
import 'package:hex/hex.dart';
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
      _eventStreamController = StreamController<OmemoEvent>.broadcast();

  /// Deserialise the OmemoSessionManager from JSON data [data].
  factory OmemoSessionManager.fromJson(Map<String, dynamic> data, TrustManager trustManager) {
    final ratchetMap = <RatchetMapKey, OmemoDoubleRatchet>{};
    for (final rawRatchet in data['sessions']! as List<Map<String, dynamic>>) {
      final key = RatchetMapKey(rawRatchet['jid']! as String, rawRatchet['deviceId']! as int);
      final ratchet = OmemoDoubleRatchet.fromJson(rawRatchet['ratchet']! as Map<String, dynamic>);
      ratchetMap[key] = ratchet;
    }

    return OmemoSessionManager(
      Device.fromJson(data['device']! as Map<String, dynamic>),
      data['devices']! as Map<String, List<int>>,
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
    OmemoKeyPair? spk;
    if (kex.spkId == device.spkId) {
      spk = device.spk;
    } else if (kex.spkId == device.oldSpkId) {
      spk = device.oldSpk;
    } else {
      throw UnknownSignedPrekeyException();
    }

    assert(spk != null, 'The used SPK must be found');
    
    final kexResult = await x3dhFromInitialMessage(
      X3DHMessage(
        OmemoPublicKey.fromBytes(kex.ik!, KeyPairType.ed25519),
        OmemoPublicKey.fromBytes(kex.ek!, KeyPairType.x25519),
        kex.pkId!,
      ),
      spk!,
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

    // Empty OMEMO messages should just have the key decrypted and/or session set up.
    if (ciphertext == null) {
      return null;
    }
    
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

  /// Returns the list of hex-encoded fingerprints we have for sessions with [jid].
  Future<List<DeviceFingerprint>> getHexFingerprintsForJid(String jid) async {
    final fingerprints = List<DeviceFingerprint>.empty(growable: true);

    await _lock.synchronized(() async {
      // Get devices for jid
      final devices = _deviceMap[jid]!;

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
