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
import 'package:omemo_dart/src/omemo/constants.dart';
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

class _InternalDecryptionResult {
  const _InternalDecryptionResult(
    this.ratchetCreated,
    this.ratchetReplaced,
    this.payload,
  ) : assert(!ratchetCreated || !ratchetReplaced, 'Ratchet must be either replaced or created');
  final bool ratchetCreated;
  final bool ratchetReplaced;
  final String? payload;
}

class OmemoManager {
  OmemoManager(
    this._device,
    this._trustManager,
    this.sendEmptyOmemoMessageImpl,
    this.fetchDeviceListImpl,
    this.fetchDeviceBundleImpl,
    this.subscribeToDeviceListNodeImpl,
  );

  final Logger _log = Logger('OmemoManager');

  /// Functions for connecting with the OMEMO library

  /// Send an empty OMEMO:2 message using the encrypted payload @result to
  /// @recipientJid.
  final Future<void> Function(EncryptionResult result, String recipientJid) sendEmptyOmemoMessageImpl;

  /// Fetch the list of device ids associated with @jid. If the device list cannot be
  /// fetched, return null.
  final Future<List<int>?> Function(String jid) fetchDeviceListImpl;

  /// Fetch the device bundle for the device with id @id of jid. If it cannot be fetched, return null.
  final Future<OmemoBundle?> Function(String jid, int id) fetchDeviceBundleImpl;

  /// Subscribe to the device list PEP node of @jid.
  final Future<void> Function(String jid) subscribeToDeviceListNodeImpl;
  
  /// Map bare JID to its known devices
  Map<String, List<int>> _deviceList = {};
  /// Map bare JIDs to whether we already requested the device list once
  final Map<String, bool> _deviceListRequested = {};
  /// Map bare a ratchet key to its ratchet. Note that this is also locked by
  /// _ratchetCriticalSectionLock.
  Map<RatchetMapKey, OmemoDoubleRatchet> _ratchetMap = {};
  /// Map bare JID to whether we already tried to subscribe to the device list node.
  final Map<String, bool> _subscriptionMap = {};
  /// For preventing a race condition in encryption/decryption
  final Map<String, Queue<Completer<void>>> _ratchetCriticalSectionQueue = {};
  final Lock _ratchetCriticalSectionLock = Lock();

  /// The OmemoManager's trust management
  final TrustManager _trustManager;
  TrustManager get trustManager => _trustManager;
  
  /// Our own keys...
  final Lock _deviceLock = Lock();
  // ignore: prefer_final_fields
  OmemoDevice _device;
  
  /// The event bus of the session manager
  final StreamController<OmemoEvent> _eventStreamController = StreamController<OmemoEvent>.broadcast();
  Stream<OmemoEvent> get eventStream => _eventStreamController.stream;

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
    _eventStreamController.add(RatchetModifiedEvent(jid, deviceId, ratchet, true, false));
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
  Future<_InternalDecryptionResult> _decryptMessage(List<int>? ciphertext, String senderJid, int senderDeviceId, List<EncryptedKey> keys, int timestamp) async {
    // Try to find a session we can decrypt with.
    var device = await getDevice();
    final rawKey = keys.firstWhereOrNull((key) => key.rid == device.id);
    if (rawKey == null) {
      throw NotEncryptedForDeviceException();
    }
 
    final decodedRawKey = base64.decode(rawKey.value);
    List<int>? keyAndHmac;
    OmemoAuthenticatedMessage authMessage;
    OmemoMessage? message;

    // If the ratchet already existed, we store it. If it didn't, oldRatchet will stay
    // null.
    final ratchetKey = RatchetMapKey(senderJid, senderDeviceId);
    final oldRatchet = getRatchet(ratchetKey)?.clone();
    if (rawKey.kex) {
      final kex = OmemoKeyExchange.fromBuffer(decodedRawKey);
      authMessage = kex.message!;
      message = OmemoMessage.fromBuffer(authMessage.message!);

      // Guard against old key exchanges
      if (oldRatchet != null) {
        _log.finest('KEX for existent ratchet ${ratchetKey.toJsonKey()}. ${oldRatchet.kexTimestamp} > $timestamp: ${oldRatchet.kexTimestamp > timestamp}');
        if (oldRatchet.kexTimestamp > timestamp) {
          throw InvalidKeyExchangeException();
        }
      }

      final r = await _addSessionFromKeyExchange(senderJid, senderDeviceId, kex);

      // Try to decrypt with the new ratchet r
      try {
        keyAndHmac = await r.ratchetDecrypt(message, authMessage.writeToBuffer());
        final result = await _decryptAndVerifyHmac(ciphertext, keyAndHmac);

        // Add the new ratchet
        _addSession(senderJid, senderDeviceId, r);

        // Replace the OPK
        await _deviceLock.synchronized(() async {
          device = await device.replaceOnetimePrekey(kex.pkId!);

          // Commit the device
          _eventStreamController.add(DeviceModifiedEvent(device));
        });

        // Commit the ratchet
        _eventStreamController.add(
          RatchetModifiedEvent(
            senderJid,
            senderDeviceId,
            r,
            oldRatchet == null,
            oldRatchet != null,
          ),
        );

        return _InternalDecryptionResult(
          oldRatchet == null,
          oldRatchet != null,
          result,
        );
      } catch (ex) {
        _log.finest('Kex failed due to $ex. Not proceeding with kex.');
      }
    } else {
      authMessage = OmemoAuthenticatedMessage.fromBuffer(decodedRawKey);
      message = OmemoMessage.fromBuffer(authMessage.message!);
    }
    
    final devices = _deviceList[senderJid];
    if (devices?.contains(senderDeviceId) != true) {
      throw NoDecryptionKeyException();
    }

    // TODO(PapaTutuWawa): When receiving a message that is not an OMEMOKeyExchange from a device there is no session with, clients SHOULD create a session with that device and notify it about the new session by responding with an empty OMEMO message as per Sending a message.
    
    // We can guarantee that the ratchet exists at this point in time
    final ratchet = getRatchet(ratchetKey)!;

    try {
      if (rawKey.kex) {
        keyAndHmac = await ratchet.ratchetDecrypt(message, authMessage.writeToBuffer());
      } else {
        keyAndHmac = await ratchet.ratchetDecrypt(message, decodedRawKey);
      }
    } catch (_) {
      _restoreRatchet(ratchetKey, oldRatchet!);
      rethrow;
    }

    // Commit the ratchet
    _eventStreamController.add(
      RatchetModifiedEvent(
        senderJid,
        senderDeviceId,
        ratchet,
        false,
        false,
      ),
    );

    try {
      return _InternalDecryptionResult(
        false,
        false,
        await _decryptAndVerifyHmac(ciphertext, keyAndHmac),
      );
    } catch (_) { 
      _restoreRatchet(ratchetKey, oldRatchet!);
      rethrow;
    }
  }

  /// Returns, if it exists, the ratchet associated with [key].
  /// NOTE: Must be called from within the ratchet critical section.
  @visibleForTesting
  OmemoDoubleRatchet? getRatchet(RatchetMapKey key) => _ratchetMap[key];

  /// Figure out what bundles we have to still build a session with.
  Future<List<OmemoBundle>> _fetchNewBundles(String jid) async {
    // Check if we already requested the device list for [jid]
    List<int> bundlesToFetch;
    if (!_deviceListRequested.containsKey(jid) || !_deviceList.containsKey(jid)) {
      // We don't have an up-to-date version of the device list
      final newDeviceList = await fetchDeviceListImpl(jid);
      if (newDeviceList == null) return [];

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

    if (bundlesToFetch.isNotEmpty) {
      _log.finest('Fetching bundles $bundlesToFetch for $jid');
    }

    final device = await getDevice();
    final newBundles = List<OmemoBundle>.empty(growable: true);
    for (final id in bundlesToFetch) {
      if (jid == device.jid && id == device.id) continue;

      final bundle = await fetchDeviceBundleImpl(jid, id);
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

    final kex = <RatchetMapKey, OmemoKeyExchange>{};
    for (final jid in jids) {
      for (final newSession in await _fetchNewBundles(jid)) {
        kex[RatchetMapKey(jid, newSession.id)] = await addSessionFromBundle(
          newSession.jid,
          newSession.id,
          newSession,
        );
      }
    }

    // We assume that the user already checked if the session exists
    final deviceEncryptionErrors = <RatchetMapKey, OmemoException>{};
    final jidEncryptionErrors = <String, OmemoException>{};
    for (final jid in jids) {
      final devices = _deviceList[jid];
      if (devices == null) {
        _log.severe('Device list does not exist for $jid.');
        jidEncryptionErrors[jid] = NoKeyMaterialAvailableException();
        continue;
      }

      if (!_subscriptionMap.containsKey(jid)) {
        unawaited(subscribeToDeviceListNodeImpl(jid));
        _subscriptionMap[jid] = true;
      }

      for (final deviceId in devices) {
        // Empty OMEMO messages are allowed to bypass trust
        if (plaintext != null) {
          // Only encrypt to devices that are trusted
          if (!(await _trustManager.isTrusted(jid, deviceId))) continue;

          // Only encrypt to devices that are enabled
          if (!(await _trustManager.isEnabled(jid, deviceId))) continue;
        }

        final ratchetKey = RatchetMapKey(jid, deviceId);
        var ratchet = _ratchetMap[ratchetKey];
        if (ratchet == null) {
          _log.severe('Ratchet ${ratchetKey.toJsonKey()} does not exist.');
          deviceEncryptionErrors[ratchetKey] = NoKeyMaterialAvailableException();
          continue;
        }

        final ciphertext = (await ratchet.ratchetEncrypt(keyPayload)).ciphertext;
 
        if (kex.containsKey(ratchetKey)) {
          // The ratchet did not exist
          final k = kex[ratchetKey]!
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
        _eventStreamController.add(RatchetModifiedEvent(jid, deviceId, ratchet, false, false));
      }
    }

    return EncryptionResult(
      plaintext != null ?
        ciphertext : null,
      encryptedKeys,
      deviceEncryptionErrors,
      jidEncryptionErrors,
    );
  }

  /// Call when receiving an OMEMO:2 encrypted stanza. Will handle everything and
  /// decrypt it.
  Future<DecryptionResult> onIncomingStanza(OmemoIncomingStanza stanza) async {
    await _enterRatchetCriticalSection(stanza.bareSenderJid);

    if (!_subscriptionMap.containsKey(stanza.bareSenderJid)) {
      unawaited(subscribeToDeviceListNodeImpl(stanza.bareSenderJid));
      _subscriptionMap[stanza.bareSenderJid] = true;
    }
    
    final ratchetKey = RatchetMapKey(stanza.bareSenderJid, stanza.senderDeviceId);
    final _InternalDecryptionResult result;
    try {
      result = await _decryptMessage(
        stanza.payload != null ?
          base64.decode(stanza.payload!) :
          null,
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
    final ratchet = getRatchet(ratchetKey);
    assert(ratchet != null, 'We decrypted the message, so the ratchet must exist');

    if (ratchet!.acknowledged) {
      // Ratchet is acknowledged
      if (ratchet.nr > 53 || result.ratchetCreated || result.ratchetReplaced) {
        await sendEmptyOmemoMessageImpl(
          await _encryptToJids(
            [stanza.bareSenderJid],
            null,
          ),
          stanza.bareSenderJid,
        );
      }

      // Ratchet is acked
      await _leaveRatchetCriticalSection(stanza.bareSenderJid);
      return DecryptionResult(
        result.payload,
        null,
      );
    } else {
      // Ratchet is not acked.
      // Mark as acked and send an empty OMEMO message.
      await ratchetAcknowledged(
        stanza.bareSenderJid,
        stanza.senderDeviceId,
        enterCriticalSection: false,
      );
      await sendEmptyOmemoMessageImpl(
        await _encryptToJids(
          [stanza.bareSenderJid],
          null,
        ),
        stanza.bareSenderJid,
      );

      await _leaveRatchetCriticalSection(stanza.bareSenderJid);
      return DecryptionResult(
        result.payload,
        null,
      );
    }
  }

  /// Call when sending out an encrypted stanza. Will handle everything and
  /// encrypt it.
  Future<EncryptionResult> onOutgoingStanza(OmemoOutgoingStanza stanza) async {
    _log.finest('Waiting to enter critical section');
    await _enterRatchetCriticalSection(stanza.recipientJids.first);
    _log.finest('Entered critical section');

    final result = _encryptToJids(
      stanza.recipientJids,
      stanza.payload,
    );

    await _leaveRatchetCriticalSection(stanza.recipientJids.first);

    return result;
  }

  // Sends a hearbeat message as specified by XEP-0384 to [jid].
  Future<void> sendOmemoHeartbeat(String jid) async {
    // TODO(Unknown): Include some error handling
    final result = await _encryptToJids(
      [jid],
      null,
    );
    await sendEmptyOmemoMessageImpl(result, jid);
  }
  
  /// Mark the ratchet for device [deviceId] from [jid] as acked.
  Future<void> ratchetAcknowledged(String jid, int deviceId, { bool enterCriticalSection = true }) async {
    if (enterCriticalSection) await _enterRatchetCriticalSection(jid);

    final key = RatchetMapKey(jid, deviceId);
    if (_ratchetMap.containsKey(key)) {
      final ratchet = _ratchetMap[key]!
        ..acknowledged = true;

      // Commit it
      _eventStreamController.add(RatchetModifiedEvent(jid, deviceId, ratchet, false, false));
    } else {
      _log.severe('Attempted to acknowledge ratchet ${key.toJsonKey()}, even though it does not exist');
    }

    if (enterCriticalSection) await _leaveRatchetCriticalSection(jid);
  }

  /// Generates an entirely new device. May be useful when the user wants to reset their cryptographic
  /// identity. Triggers an event to commit it to storage.
  Future<void> regenerateDevice() async {
    await _deviceLock.synchronized(() async {
      _device = await OmemoDevice.generateNewDevice(_device.jid);

      // Commit it
      _eventStreamController.add(DeviceModifiedEvent(_device));
    });
  }
  
  /// Returns the device used for encryption and decryption.
  Future<OmemoDevice> getDevice() => _deviceLock.synchronized(() => _device);

  /// Returns the id of the device used for encryption and decryption.
  Future<int> getDeviceId() async => (await getDevice()).id;

  /// Directly aquire the current device as a OMEMO device bundle.
  Future<OmemoBundle> getDeviceBundle() async => (await getDevice()).toBundle();

  /// Directly aquire the current device's fingerprint.
  Future<String> getDeviceFingerprint() async => (await getDevice()).getFingerprint();
  
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
      final curveKey = await _ratchetMap[key]!.ik.toCurve25519();
      fingerprints.add(
        DeviceFingerprint(
          key.deviceId,
          HEX.encode(await curveKey.getBytes()),
        ),
      );
    }

    await _leaveRatchetCriticalSection(jid);
    return fingerprints;
  }
  
  /// Ensures that the device list is fetched again on the next message sending.
  void onNewConnection() {
    _deviceListRequested.clear();
    _subscriptionMap.clear();
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

  /// Removes all ratchets for JID [jid]. This also removes all trust decisions for
  /// [jid] from the trust manager. This function triggers a RatchetRemovedEvent for
  /// every removed ratchet and a DeviceListModifiedEvent afterwards. Behaviour for
  /// the trust manager is dependent on its implementation.
  Future<void> removeAllRatchets(String jid) async {
    await _enterRatchetCriticalSection(jid);

    for (final deviceId in _deviceList[jid]!) {
      // Remove the ratchet and commit it
      _ratchetMap.remove(RatchetMapKey(jid, deviceId));
      _eventStreamController.add(RatchetRemovedEvent(jid, deviceId));
    }

    // Remove the devices from the device list cache and commit it
    _deviceList.remove(jid);
    _deviceListRequested.remove(jid);
    _eventStreamController.add(DeviceListModifiedEvent(_deviceList));

    // Remove trust decisions
    await _trustManager.removeTrustDecisionsForJid(jid);
    
    await _leaveRatchetCriticalSection(jid);
  }

  /// Replaces the internal device with [newDevice]. Does not trigger an event.
  Future<void> replaceDevice(OmemoDevice newDevice) async {
    await _deviceLock.synchronized(() {
      _device = newDevice;
    });
  }
}
