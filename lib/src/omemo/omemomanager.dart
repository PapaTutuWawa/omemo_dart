import 'dart:async';
import 'dart:collection';
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
import 'package:omemo_dart/src/omemo/decryption_result.dart';
import 'package:omemo_dart/src/omemo/device.dart';
import 'package:omemo_dart/src/omemo/encrypted_key.dart';
import 'package:omemo_dart/src/omemo/encryption_result.dart';
import 'package:omemo_dart/src/omemo/events.dart';
import 'package:omemo_dart/src/omemo/fingerprint.dart';
import 'package:omemo_dart/src/omemo/ratchet_map_key.dart';
import 'package:omemo_dart/src/omemo/stanza.dart';
import 'package:omemo_dart/src/protobuf/omemo_authenticated_message.dart';
import 'package:omemo_dart/src/protobuf/omemo_key_exchange.dart';
import 'package:omemo_dart/src/protobuf/omemo_message.dart';
import 'package:omemo_dart/src/trust/base.dart';
import 'package:omemo_dart/src/x3dh/x3dh.dart';
import 'package:synchronized/synchronized.dart';

/// The info used for when encrypting the AES key for the actual payload.
const omemoPayloadInfoString = 'OMEMO Payload';

class OmemoManager {
  OmemoManager(
    this._device,
    this._trustManager,
    this.sendEmptyOmemoMessage,
    this.fetchDeviceList,
    this.fetchDeviceBundle,
  );

  final Logger _log = Logger('OmemoManager');

  /// Functions for connecting with the OMEMO library

  /// Send an empty OMEMO:2 message using the encrypted payload [result] to [recipientJid].
  final Future<void> Function(EncryptionResult result, String recipientJid) sendEmptyOmemoMessage;

  /// Fetch the list of device ids associated with [jid].
  final Future<List<int>> Function(String jid) fetchDeviceList;

  /// Fetch the device bundle for the device with id [id] of [jid]. If it cannot be fetched, return null.
  final Future<OmemoBundle?> Function(String jid, int id) fetchDeviceBundle;
  
  /// Map bare JID to its known devices
  Map<String, List<int>> _deviceList = {};
  /// Map bare JIDs to whether we already requested the device list once
  final Map<String, bool> _deviceListRequested = {};
  /// Map bare a ratchet key to its ratchet. Note that this is also locked by
  /// _ratchetCriticalSectionLock.
  Map<RatchetMapKey, OmemoDoubleRatchet> _ratchetMap = {};
  /// For preventing a race condition in encryption/decryption
  final Map<String, Queue<Completer<void>>> _ratchetCriticalSectionQueue = {};
  final Lock _ratchetCriticalSectionLock = Lock();

  /// The OmemoManager's trust management
  final TrustManager _trustManager;
  TrustManager get trustManager => _trustManager;
  
  /// Our own keys...
  final Lock _deviceLock = Lock();
  // ignore: prefer_final_fields
  Device _device;
  
  /// The event bus of the session manager
  final StreamController<OmemoEvent> _eventStreamController = StreamController<OmemoEvent>.broadcast();

  /// Enter the critical section for performing cryptographic operations on the ratchets
  Future<void> _enterRatchetCriticalSection(String jid) async {
    final completer = await _ratchetCriticalSectionLock.synchronized(() {
      if (_ratchetCriticalSectionQueue.containsKey(jid)) {
        final c = Completer<void>();
        _ratchetCriticalSectionQueue[jid]!.addLast(c);
        return c;
      }

      _ratchetCriticalSectionQueue[jid] = Queue();
      return null;
    });

    if (completer != null) {
      await completer.future;
    }
  }
  
  /// Leave the critical section for the ratchets.
  Future<void> _leaveRatchetCriticalSection(String jid) async {
    await _ratchetCriticalSectionLock.synchronized(() {
      if (_ratchetCriticalSectionQueue.containsKey(jid)) {
        if (_ratchetCriticalSectionQueue[jid]!.isEmpty) {
          _ratchetCriticalSectionQueue.remove(jid);
        } else {
          _ratchetCriticalSectionQueue[jid]!.removeFirst().complete();
        }
      }
    });
  }

  Future<String?> _decryptAndVerifyHmac(List<int>? ciphertext, List<int> keyAndHmac) async {
    // Empty OMEMO messages should just have the key decrypted and/or session set up.
    if (ciphertext == null) {
      return null;
    }
    
    final key = keyAndHmac.sublist(0, 32);
    final hmac = keyAndHmac.sublist(32, 48);
    final derivedKeys = await deriveEncryptionKeys(key, omemoPayloadInfoString);
    final computedHmac = await truncatedHmac(ciphertext, derivedKeys.authenticationKey);
    if (!listsEqual(hmac, computedHmac)) {
      throw InvalidMessageHMACException();
    }
    
    return utf8.decode(
      await aes256CbcDecrypt(ciphertext, derivedKeys.encryptionKey, derivedKeys.iv),
    );
  }

  /// Add a session [ratchet] with the [deviceId] to the internal tracking state.
  /// NOTE: Must be called from within the ratchet critical section.
  void _addSession(String jid, int deviceId, OmemoDoubleRatchet ratchet) {
    // Add the bundle Id
    if (!_deviceList.containsKey(jid)) {
      _deviceList[jid] = [deviceId];

      // Commit the device map
      _eventStreamController.add(DeviceListModifiedEvent(_deviceList));
    } else {
      // Prevent having the same device multiple times in the list
      if (!_deviceList[jid]!.contains(deviceId)) {
        _deviceList[jid]!.add(deviceId);

        // Commit the device map
        _eventStreamController.add(DeviceListModifiedEvent(_deviceList));
      }
    }

    // Add the ratchet session
    final key = RatchetMapKey(jid, deviceId);
    _ratchetMap[key] = ratchet;

    // Commit the ratchet
    _eventStreamController.add(RatchetModifiedEvent(jid, deviceId, ratchet, true));
  }

  /// Build a new session with the user at [jid] with the device [deviceId] using data
  /// from the key exchange [kex]. In case [kex] contains an unknown Signed Prekey
  /// identifier an UnknownSignedPrekeyException will be thrown.
  Future<OmemoDoubleRatchet> _addSessionFromKeyExchange(String jid, int deviceId, OmemoKeyExchange kex) async {
    // Pick the correct SPK
    final device = await getDevice();
    OmemoKeyPair spk;
    if (kex.spkId == _device.spkId) {
      spk = _device.spk;
    } else if (kex.spkId == _device.oldSpkId) {
      spk = _device.oldSpk!;
    } else {
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
      getTimestamp(),
    );

    return ratchet;
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
      getTimestamp(),
    );

    await _trustManager.onNewSession(jid, deviceId);
    _addSession(jid, deviceId, ratchet);

    return OmemoKeyExchange()
      ..pkId = kexResult.opkId
      ..spkId = bundle.spkId
      ..ik = await device.ik.pk.getBytes()
      ..ek = await kexResult.ek.pk.getBytes();
  }
  
  /// In case a decryption error occurs, the Double Ratchet spec says to just restore
  /// the ratchet to its old state. As such, this function restores the ratchet at
  /// [mapKey] with [oldRatchet].
  /// NOTE: Must be called from within the ratchet critical section
  void _restoreRatchet(RatchetMapKey mapKey, OmemoDoubleRatchet oldRatchet) {
    _log.finest('Restoring ratchet ${mapKey.jid}:${mapKey.deviceId} to ${oldRatchet.nr}');
    _ratchetMap[mapKey] = oldRatchet;

    // Commit the ratchet
    _eventStreamController.add(
      RatchetModifiedEvent(
        mapKey.jid,
        mapKey.deviceId,
        oldRatchet,
        false,
      ),
    );
  }
  
  /// Attempt to decrypt [ciphertext]. [keys] refers to the <key /> elements inside the
  /// <keys /> element with a "jid" attribute matching our own. [senderJid] refers to the
  /// bare Jid of the sender. [senderDeviceId] refers to the "sid" attribute of the
  /// <encrypted /> element.
  /// [timestamp] refers to the time the message was sent. This might be either what the
  /// server tells you via "XEP-0203: Delayed Delivery" or the point in time at which
  /// you received the stanza, if no Delayed Delivery element was found.
  ///
  /// If the received message is an empty OMEMO message, i.e. there is no <payload />
  /// element, then [ciphertext] must be set to null. In this case, this function
  /// will return null as there is no message to be decrypted. This, however, is used
  /// to set up sessions or advance the ratchets.
  Future<String?> _decryptMessage(List<int>? ciphertext, String senderJid, int senderDeviceId, List<EncryptedKey> keys, int timestamp) async {
    // Try to find a session we can decrypt with.
    var device = await getDevice();
    final rawKey = keys.firstWhereOrNull((key) => key.rid == device.id);
    if (rawKey == null) {
      throw NotEncryptedForDeviceException();
    }

    final ratchetKey = RatchetMapKey(senderJid, senderDeviceId);
    final decodedRawKey = base64.decode(rawKey.value);
    List<int>? keyAndHmac;
    OmemoAuthenticatedMessage authMessage;
    OmemoDoubleRatchet? oldRatchet;
    OmemoMessage? message;
    if (rawKey.kex) {
      // If the ratchet already existed, we store it. If it didn't, oldRatchet will stay
      // null.
      final oldRatchet = _getRatchet(ratchetKey)?.clone();
      final kex = OmemoKeyExchange.fromBuffer(decodedRawKey);
      authMessage = kex.message!;
      message = OmemoMessage.fromBuffer(authMessage.message!);

      // Guard against old key exchanges
      if (oldRatchet != null) {
        _log.finest('KEX for existent ratchet ${ratchetKey.toJsonKey()}. ${oldRatchet.kexTimestamp} > $timestamp: ${oldRatchet.kexTimestamp > timestamp}');
        if (oldRatchet.kexTimestamp > timestamp) {
          throw InvalidKeyExchangeException();
        }
        
        // Try to decrypt it
        try {
          final decrypted = await oldRatchet.ratchetDecrypt(message, authMessage.writeToBuffer());

          // Commit the ratchet
          _eventStreamController.add(
            RatchetModifiedEvent(
              senderJid,
              senderDeviceId,
              oldRatchet,
              false,
            ),
          );
          
          final plaintext = await _decryptAndVerifyHmac(
            ciphertext,
            decrypted,
          );
          _addSession(senderJid, senderDeviceId, oldRatchet);
          return plaintext;
        } catch (_) {
          _log.finest('Failed to use old ratchet with KEX for existing ratchet');
        }
      }

      final r = await _addSessionFromKeyExchange(senderJid, senderDeviceId, kex);
      await _trustManager.onNewSession(senderJid, senderDeviceId);
      _addSession(senderJid, senderDeviceId, r);

      // Replace the OPK
      // TODO(PapaTutuWawa): Replace the OPK when we know that the KEX worked
      await _deviceLock.synchronized(() async {
        device = await device.replaceOnetimePrekey(kex.pkId!);

        // Commit the device
        _eventStreamController.add(DeviceModifiedEvent(device));
      });
    } else {
      authMessage = OmemoAuthenticatedMessage.fromBuffer(decodedRawKey);
      message = OmemoMessage.fromBuffer(authMessage.message!);
    }
    
    final devices = _deviceList[senderJid];
    if (devices == null) {
      throw NoDecryptionKeyException();
    }
    if (!devices.contains(senderDeviceId)) {
      throw NoDecryptionKeyException();
    }

    // We can guarantee that the ratchet exists at this point in time
    final ratchet = _getRatchet(ratchetKey)!;
    oldRatchet ??= ratchet.clone();

    try {
      if (rawKey.kex) {
        keyAndHmac = await ratchet.ratchetDecrypt(message, authMessage.writeToBuffer());
      } else {
        keyAndHmac = await ratchet.ratchetDecrypt(message, decodedRawKey);
      }
    } catch (_) {
      _restoreRatchet(ratchetKey, oldRatchet);
      rethrow;
    }

    // Commit the ratchet
    _eventStreamController.add(
      RatchetModifiedEvent(
        senderJid,
        senderDeviceId,
        ratchet,
        false,
      ),
    );

    try {
      return _decryptAndVerifyHmac(ciphertext, keyAndHmac);
    } catch (_) { 
      _restoreRatchet(ratchetKey, oldRatchet);
      rethrow;
    }
  }

  /// Returns, if it exists, the ratchet associated with [key].
  /// NOTE: Must be called from within the ratchet critical section.
  OmemoDoubleRatchet? _getRatchet(RatchetMapKey key) => _ratchetMap[key];

  /// Figure out what bundles we have to still build a session with.
  Future<List<OmemoBundle>> _fetchNewBundles(String jid) async {
    // Check if we already requested the device list for [jid]
    List<int> bundlesToFetch;
    if (!_deviceListRequested.containsKey(jid) || !_deviceList.containsKey(jid)) {
      // We don't have an up-to-date version of the device list
      final newDeviceList = await fetchDeviceList(jid);
      _deviceList[jid] = newDeviceList;
      bundlesToFetch = newDeviceList
        .where((id) {
          return !_ratchetMap.containsKey(RatchetMapKey(jid, id)) ||
                 _deviceList[jid]?.contains(id) == false;
        }).toList();

      // Trigger an event with the new device list
      _eventStreamController.add(DeviceListModifiedEvent(_deviceList));
    } else {
      // We already have an up-to-date version of the device list
      bundlesToFetch = _deviceList[jid]!
        .where((id) => !_ratchetMap.containsKey(RatchetMapKey(jid, id)))
        .toList();
    }

    final newBundles = List<OmemoBundle>.empty(growable: true);
    for (final id in bundlesToFetch) {
      final bundle = await fetchDeviceBundle(jid, id);
      if (bundle != null) newBundles.add(bundle);
    }

    return newBundles;
  }
  
  /// Encrypt the key [plaintext] for all known bundles of the Jids in [jids]. Returns a
  /// map that maps the device Id to the ciphertext of [plaintext].
  ///
  /// If [plaintext] is null, then the result will be an empty OMEMO message, i.e. one that
  /// does not contain a <payload /> element. This means that the ciphertext attribute of
  /// the result will be null as well.
  /// NOTE: Must be called within the ratchet critical section
  Future<EncryptionResult> _encryptToJids(List<String> jids, String? plaintext) async {
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
    for (final jid in jids) {
      for (final newSession in await _fetchNewBundles(jid)) {
        kex[newSession.id] = await addSessionFromBundle(
          newSession.jid,
          newSession.id,
          newSession,
        );
      }
    }

    // We assume that the user already checked if the session exists
    for (final jid in jids) {
      for (final deviceId in _deviceList[jid]!) {
        // Empty OMEMO messages are allowed to bypass trust
        if (plaintext != null) {
          // Only encrypt to devices that are trusted
          if (!(await _trustManager.isTrusted(jid, deviceId))) continue;

          // Only encrypt to devices that are enabled
          if (!(await _trustManager.isEnabled(jid, deviceId))) continue;
        }

        final ratchetKey = RatchetMapKey(jid, deviceId);
        var ratchet = _ratchetMap[ratchetKey]!;
        final ciphertext = (await ratchet.ratchetEncrypt(keyPayload)).ciphertext;
 
        if (kex.isNotEmpty && kex.containsKey(deviceId)) {
          // The ratchet did not exist
          final k = kex[deviceId]!
            ..message = OmemoAuthenticatedMessage.fromBuffer(ciphertext);
          final buffer = base64.encode(k.writeToBuffer());
          encryptedKeys.add(
            EncryptedKey(
              jid,
              deviceId,
              buffer,
              true,
            ),
          );

          ratchet = ratchet.cloneWithKex(buffer);
          _ratchetMap[ratchetKey] = ratchet;
        } else if (!ratchet.acknowledged) {
          // The ratchet exists but is not acked
          if (ratchet.kex != null) {
            final oldKex = OmemoKeyExchange.fromBuffer(base64.decode(ratchet.kex!))
            ..message = OmemoAuthenticatedMessage.fromBuffer(ciphertext);
            
            encryptedKeys.add(
              EncryptedKey(
                jid,
                deviceId,
                base64.encode(oldKex.writeToBuffer()),
                true,
              ),
            );
          } else {
            // The ratchet is not acked but we don't have the old key exchange
            _log.warning('Ratchet for $jid:$deviceId is not acked but the kex attribute is null');
            encryptedKeys.add(
              EncryptedKey(
                jid,
                deviceId,
                base64.encode(ciphertext),
                false,
              ),
            );
          }
        } else {
          // The ratchet exists and is acked
          encryptedKeys.add(
            EncryptedKey(
              jid,
              deviceId,
              base64.encode(ciphertext),
              false,
            ),
          );
        }

        // Commit the ratchet
        _eventStreamController.add(RatchetModifiedEvent(jid, deviceId, ratchet, false));
      }
    }

    return EncryptionResult(
      plaintext != null ? ciphertext : null,
      encryptedKeys,
    );
  }

  /// Call when receiving an OMEMO:2 encrypted stanza. Will handle everything and
  /// decrypt it.
  Future<DecryptionResult> onIncomingStanza(OmemoIncomingStanza stanza) async {
    await _enterRatchetCriticalSection(stanza.bareSenderJid);

    final ratchetKey = RatchetMapKey(stanza.bareSenderJid, stanza.senderDeviceId);
    final ratchetCreated = !_ratchetMap.containsKey(ratchetKey);
    String? payload;
    try {
      payload = await _decryptMessage(
        base64.decode(stanza.payload),
        stanza.bareSenderJid,
        stanza.senderDeviceId,
        stanza.keys,
        stanza.timestamp,
      );
    } on OmemoException catch (ex) {
      await _leaveRatchetCriticalSection(stanza.bareSenderJid);
      return DecryptionResult(
        null,
        ex,
      );
    }

    // Check if the ratchet is acked
    final ratchet = _getRatchet(ratchetKey);
    assert(ratchet != null, 'We decrypted the message, so the ratchet must exist');

    if (ratchet!.nr > 53) {
      await sendEmptyOmemoMessage(
        await _encryptToJids(
          [stanza.bareSenderJid],
          null,
        ),
        stanza.bareSenderJid,
      );
    }
    
    // Ratchet is acked
    if (!ratchetCreated && ratchet.acknowledged) {
      await _leaveRatchetCriticalSection(stanza.bareSenderJid);
      return DecryptionResult(
        payload,
        null,
      );
    }

    // Ratchet is not acked. Mark as acked and send an empty OMEMO message.
    await ratchetAcknowledged(
      stanza.bareSenderJid,
      stanza.senderDeviceId,
      enterCriticalSection: false,
    );
    await sendEmptyOmemoMessage(
      await _encryptToJids(
        [stanza.bareSenderJid],
        null,
      ),
      stanza.bareSenderJid,
    );

    await _leaveRatchetCriticalSection(stanza.bareSenderJid);
    return DecryptionResult(
      payload,
      null,
    );
  }

  /// Call when sending out an encrypted stanza. Will handle everything and
  /// encrypt it.
  Future<EncryptionResult?> onOutgoingStanza(OmemoOutgoingStanza stanza) async {
    return _encryptToJids(
      stanza.recipientJids,
      stanza.payload,
    );
  }
  
  /// Mark the ratchet for device [deviceId] from [jid] as acked.
  Future<void> ratchetAcknowledged(String jid, int deviceId, { bool enterCriticalSection = true }) async {
    if (enterCriticalSection) await _enterRatchetCriticalSection(jid);

    final key = RatchetMapKey(jid, deviceId);
    if (_ratchetMap.containsKey(key)) {
      final ratchet = _ratchetMap[key]!
        ..acknowledged = true;

      // Commit it
      _eventStreamController.add(RatchetModifiedEvent(jid, deviceId, ratchet, false));
    } else {
      _log.severe('Attempted to acknowledge ratchet ${key.toJsonKey()}, even though it does not exist');
    }

    if (enterCriticalSection) await _leaveRatchetCriticalSection(jid);
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
  
  /// Returns the device used for encryption and decryption.
  Future<Device> getDevice() => _deviceLock.synchronized(() => _device);

  /// Returns the fingerprints for all devices of [jid] that we have a session with.
  /// If there are not sessions with [jid], then returns null.
  Future<List<DeviceFingerprint>?> getFingerprintsForJid(String jid) async {
    if (!_deviceList.containsKey(jid)) return null;

    await _enterRatchetCriticalSection(jid);
    
    final fingerprintKeys = _deviceList[jid]!
      .map((id) => RatchetMapKey(jid, id))
      .where((key) => _ratchetMap.containsKey(key));

    final fingerprints = List<DeviceFingerprint>.empty(growable: true);
    for (final key in fingerprintKeys) {
      fingerprints.add(
        DeviceFingerprint(
          key.deviceId,
          HEX.encode(await _ratchetMap[key]!.ik.getBytes()),
        ),
      );
    }

    await _leaveRatchetCriticalSection(jid);
    return fingerprints;
  }
  
  /// Ensures that the device list is fetched again on the next message sending.
  void onNewConnection() {
    _deviceListRequested.clear();
  }

  /// Sets the device list for [jid] to [devices]. Triggers a DeviceListModifiedEvent.
  void onDeviceListUpdate(String jid, List<int> devices) {
    _deviceList[jid] = devices;
    _deviceListRequested[jid] = true;

    // Trigger an event
    _eventStreamController.add(DeviceListModifiedEvent(_deviceList));
  }

  void initialize(Map<RatchetMapKey, OmemoDoubleRatchet> ratchetMap, Map<String, List<int>> deviceList) {
    _deviceList = deviceList;
    _ratchetMap = ratchetMap;
  }
}
