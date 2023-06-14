import 'dart:async';
import 'dart:collection';
import 'dart:convert';
import 'package:collection/collection.dart';
import 'package:cryptography/cryptography.dart';
import 'package:hex/hex.dart';
import 'package:logging/logging.dart';
import 'package:meta/meta.dart';
import 'package:omemo_dart/src/common/result.dart';
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
import 'package:omemo_dart/src/omemo/errors.dart';
import 'package:omemo_dart/src/omemo/events.dart';
import 'package:omemo_dart/src/omemo/fingerprint.dart';
import 'package:omemo_dart/src/omemo/ratchet_map_key.dart';
import 'package:omemo_dart/src/omemo/stanza.dart';
import 'package:omemo_dart/src/protobuf/schema.pb.dart';
import 'package:omemo_dart/src/trust/base.dart';
import 'package:omemo_dart/src/x3dh/x3dh.dart';
import 'package:synchronized/synchronized.dart';

class _InternalDecryptionResult {
  const _InternalDecryptionResult(
    this.ratchetCreated,
    this.ratchetReplaced,
    this.payload,
  ) : assert(
          !ratchetCreated || !ratchetReplaced,
          'Ratchet must be either replaced or created',
        );
  final bool ratchetCreated;
  final bool ratchetReplaced;
  final String? payload;
}

extension AppendToListOrCreateExtension<K, V> on Map<K, List<V>> {
  void appendOrCreate(K key, V value) {
    if (containsKey(key)) {
      this[key]!.add(value);
    } else {
      this[key] = [value];
    }
  }
}

extension StringFromBase64Extension on String {
  List<int> fromBase64() => base64Decode(this);
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
  final Future<void> Function(EncryptionResult result, String recipientJid)
      sendEmptyOmemoMessageImpl;

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
  final StreamController<OmemoEvent> _eventStreamController =
      StreamController<OmemoEvent>.broadcast();
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

  Future<Result<OmemoError, String?>> _decryptAndVerifyHmac(
    List<int>? ciphertext,
    List<int> keyAndHmac,
  ) async {
    // Empty OMEMO messages should just have the key decrypted and/or session set up.
    if (ciphertext == null) {
      return const Result(null);
    }

    final key = keyAndHmac.sublist(0, 32);
    final hmac = keyAndHmac.sublist(32, 48);
    final derivedKeys = await deriveEncryptionKeys(key, omemoPayloadInfoString);
    final computedHmac =
        await truncatedHmac(ciphertext, derivedKeys.authenticationKey);
    if (!listsEqual(hmac, computedHmac)) {
      return Result(InvalidMessageHMACError());
    }

    // TODO: Handle an exception from the crypto implementation
    return Result(
      utf8.decode(
        await aes256CbcDecrypt(
          ciphertext,
          derivedKeys.encryptionKey,
          derivedKeys.iv,
        ),
      ),
    );
  }

  /// Fetches the device list from the server for [jid] and downloads OMEMO bundles
  /// for devices we have no session with.
  /// 
  /// Returns a list of new bundles, that may be empty.
  Future<List<OmemoBundle>> _fetchNewOmemoBundles(String jid) async {
    // Do we have to request the device list or are we already up-to-date?
    if (_deviceListRequested.containsKey(jid) && _deviceList.containsKey(jid)) {
      return [];
    }

    final newDeviceList = await fetchDeviceListImpl(jid);
    if (newDeviceList == null) {
      return [];
    }

    // Figure out what bundles we must fetch
    _deviceList[jid] = newDeviceList;
    _deviceListRequested[jid] = true;

    // TODO: Maybe do this per JID?
    _eventStreamController.add(
      DeviceListModifiedEvent(_deviceList),
    );

    final ownDevice = await getDevice();
    final bundlesToFetch = newDeviceList.where((device) {
      // Do not include our current device, if we request bundles for our own JID.
      if (ownDevice.jid == jid && device == ownDevice.id) {
        return false;
      }

      return !_ratchetMap.containsKey(RatchetMapKey(jid, device));
    });
    if (bundlesToFetch.isEmpty) {
      return [];
    }

    // Fetch the new bundles
    _log.finest('Fetching bundles $bundlesToFetch for $jid');
    final bundles = <OmemoBundle>[];
    for (final device in bundlesToFetch) {
      final bundle = await fetchDeviceBundleImpl(jid, device);
      if (bundle != null) {
        bundles.add(bundle);
      } else {
        _log.warning('Failed to fetch bundle $jid:$device');
      }
    }

    return bundles;
  }

  /// 
  Future<DecryptionResult> onIncomingStanza(OmemoIncomingStanza stanza) async {
    // NOTE: We do this so that we cannot forget to acquire and free the critical
    //       section.
    await _enterRatchetCriticalSection(stanza.bareSenderJid);
    final result = await _onIncomingStanzaImpl(stanza);
    await _leaveRatchetCriticalSection(stanza.bareSenderJid);

    return result;
  }

  Future<DecryptionResult> _onIncomingStanzaImpl(OmemoIncomingStanza stanza) async {
    // Find the correct key for our device
    final deviceId = await getDeviceId();
    final key = stanza.keys.firstWhereOrNull((key) => key.rid == deviceId);
    if (key == null) {
      return DecryptionResult(
        null,
        NotEncryptedForDeviceError(),
      );
    }

    final ratchetKey = RatchetMapKey(stanza.bareSenderJid, stanza.senderDeviceId);
    if (key.kex) {
      final kexMessage = OMEMOKeyExchange.fromBuffer(base64Decode(key.value));

      // TODO: Check if we already have such a session and if we can build it
      // See XEP-0384 4.3

      // Find the correct SPK
      final device = await getDevice();
      OmemoKeyPair spk;
      if (kexMessage.spkId == device.spkId) {
        spk = device.spk;
      } else if (kexMessage.spkId == device.oldSpkId) {
        spk = device.oldSpk!;
      } else {
        return DecryptionResult(
          null,
          UnknownSignedPrekeyError(),
        );
      }

      // Build the new ratchet session
      final kexIk = OmemoPublicKey.fromBytes(
        kexMessage.ik,
        KeyPairType.ed25519,
      );
      final kex = await x3dhFromInitialMessage(
        X3DHMessage(
          kexIk, 
          OmemoPublicKey.fromBytes(
            kexMessage.ek,
            KeyPairType.x25519,
          ),
          kexMessage.pkId,
        ),
        spk,
        device.opks[kexMessage.pkId]!,
        device.ik,
      );
      final ratchet = await OmemoDoubleRatchet.acceptNewSession(
        spk,
        kexIk,
        kex.sk,
        kex.ad,
        getTimestamp(),
      );

      final keyAndHmac = await ratchet.ratchetDecrypt(
        kexMessage.message,
      );
      if (keyAndHmac.isType<OmemoError>()) {
        final error = keyAndHmac.get<OmemoError>();
        _log.warning('Failed to decrypt symmetric key: $error');

        return DecryptionResult(null, error);
      }

      final result = await _decryptAndVerifyHmac(
        stanza.payload != null ? base64Decode(stanza.payload!) : null,
        keyAndHmac.get<List<int>>(),
      );
      if (result.isType<OmemoError>()) {
        final error = result.get<OmemoError>();
        _log.warning('Decrypting payload failed: $error');

        return DecryptionResult(
          null,
          error,
        );
      }

      // Notify the trust manager
      await trustManager.onNewSession(
        stanza.bareSenderJid,
        stanza.senderDeviceId,
      );

      // Commit the ratchet
      _ratchetMap[ratchetKey] = ratchet;
      _deviceList.appendOrCreate(stanza.bareSenderJid, stanza.senderDeviceId);
      _eventStreamController.add(
        RatchetModifiedEvent(
          stanza.bareSenderJid,
          stanza.senderDeviceId,
          ratchet,
          true,
          false,
        ),
      );

      // Replace the OPK if we're not doing a catchup.
      if (!stanza.isCatchup) {
        await _deviceLock.synchronized(() async {
          await _device.replaceOnetimePrekey(kexMessage.pkId);

          _eventStreamController.add(
            DeviceModifiedEvent(_device),
          );
        });
      }

      return DecryptionResult(
        result.get<String?>(),
        null,
      );
    } else {
      // Check if we even have a ratchet
      if (!_ratchetMap.containsKey(ratchetKey)) {
        // TODO: Build a session with the device

        return DecryptionResult(
          null,
          NoSessionWithDeviceError(),
        );
      }

      final ratchet = _ratchetMap[key]!.clone();
      final authMessage = OMEMOAuthenticatedMessage.fromBuffer(base64Decode(key.value));
      final keyAndHmac = await ratchet.ratchetDecrypt(authMessage);
      if (keyAndHmac.isType<OmemoError>()) {
        final error = keyAndHmac.get<OmemoError>();
        _log.warning('Failed to decrypt symmetric key: $error');
        return DecryptionResult(null, error);
      }

      final result = await _decryptAndVerifyHmac(
        stanza.payload?.fromBase64(),
        keyAndHmac.get<List<int>>(),
      );
      if (result.isType<OmemoError>()) {
        final error = result.get<OmemoError>();
        _log.warning('Failed to decrypt message: $error');
        return DecryptionResult(
          null,
          error,
        );
      }

      // Message was successfully decrypted, so commit the ratchet
      _eventStreamController.add(
        RatchetModifiedEvent(
          stanza.bareSenderJid,
          stanza.senderDeviceId,
          ratchet,
          false,
          false,
        ),
      );

      return DecryptionResult(
        result.get<String?>(),
        null,
      );
    }
  }

  Future<EncryptionResult> onOutgoingStanza(OmemoOutgoingStanza stanza) async {
    // TODO: Be more smart about the locking
    // TODO: Do we even need to lock?
    await _enterRatchetCriticalSection(stanza.recipientJids.first);
    final result = await _onOutgoingStanzaImpl(stanza);
    await _leaveRatchetCriticalSection(stanza.recipientJids.first);

    return result;
  }

  Future<EncryptionResult> _onOutgoingStanzaImpl(OmemoOutgoingStanza stanza) async {
    // Encrypt the payload, if we have any
    final List<int> payloadKey;
    final List<int> ciphertext;
    if (stanza.payload != null) {
      // Generate the key and encrypt the plaintext
      final rawKey = generateRandomBytes(32);
      final keys = await deriveEncryptionKeys(rawKey, omemoPayloadInfoString);
      ciphertext = await aes256CbcEncrypt(
        utf8.encode(stanza.payload!),
        keys.encryptionKey,
        keys.iv,
      );
      final hmac = await truncatedHmac(ciphertext, keys.authenticationKey);
      payloadKey = concat([rawKey, hmac]);
    } else {
      payloadKey = List<int>.filled(32, 0x0);
      ciphertext = [];
    }

    final addedRatchetKeys = List<RatchetMapKey>.empty(growable: true);
    final kex = <RatchetMapKey, OMEMOKeyExchange>{};
    for (final jid in stanza.recipientJids) {
      final newBundles = await _fetchNewOmemoBundles(jid);
      if (newBundles.isEmpty) {
        continue;
      }

      for (final bundle in newBundles) {
        final ratchetKey = RatchetMapKey(jid, bundle.id);
        final ownDevice = await getDevice();
        final kexResult = await x3dhFromBundle(
          bundle,
          ownDevice.ik,
        );
        final newRatchet = await OmemoDoubleRatchet.initiateNewSession(
          bundle.spk,
          bundle.ik,
          kexResult.ek.pk,
          kexResult.sk,
          kexResult.ad,
          getTimestamp(),
          kexResult.opkId,
          bundle.spkId,
        );

        // Track the ratchet
        _ratchetMap[ratchetKey] = newRatchet;
        addedRatchetKeys.add(ratchetKey);

        // Initiate trust
        await trustManager.onNewSession(jid, bundle.id);

        // Track the KEX for later
        kex[ratchetKey] = OMEMOKeyExchange()
          ..pkId = kexResult.opkId
          ..spkId = bundle.spkId
          ..ik = await ownDevice.ik.pk.getBytes()
          ..ek = await kexResult.ek.pk.getBytes();
      }
    }

    // Commit the newly created ratchets, if we created any.
    if (addedRatchetKeys.isNotEmpty) {
      _eventStreamController.add(
        RatchetsAddedEvent(
          Map<RatchetMapKey, OmemoDoubleRatchet>.fromEntries(
            addedRatchetKeys.map((key) => MapEntry(key, _ratchetMap[key]!)).toList(),
          ),
        ),
      );
    }

    // Encrypt the symmetric key for all devices.
    final encryptionErrors = <String, List<EncryptToJidError>>{};
    final encryptedKeys = <String, List<EncryptedKey>>{};
    for (final jid in stanza.recipientJids) {
      // Check if we know about any devices to use
      final devices = _deviceList[jid];
      if (devices == null) {
        _log.info('No devices for $jid known. Skipping in encryption');
        encryptionErrors.appendOrCreate(
          jid,
          EncryptToJidError(
            null,
            NoKeyMaterialAvailableError(),
          ),
        );
        continue;
      }

      // Check if we have to subscribe to the device list
      if (!_subscriptionMap.containsKey(jid)) {
        unawaited(subscribeToDeviceListNodeImpl(jid));
        _subscriptionMap[jid] = true;
      }

      for (final device in devices) {
        // Check if we should encrypt for this device
        // NOTE: Empty OMEMO messages are allowed to bypass trust decisions
        if (stanza.payload != null) {
          // Only encrypt to devices that are trusted
          if (!(await _trustManager.isTrusted(jid, device))) continue;

          // Only encrypt to devices that are enabled
          if (!(await _trustManager.isEnabled(jid, device))) continue;
        }

        // Check if the ratchet exists
        final ratchetKey = RatchetMapKey(jid, device);
        if (!_ratchetMap.containsKey(ratchetKey)) {
          // NOTE: The earlier loop should have created a new ratchet
          _log.warning('No ratchet for $jid:$device found.');
          encryptionErrors.appendOrCreate(
            jid,
            EncryptToJidError(
              device,
              NoSessionWithDeviceError(),
            ),
          );
          continue;
        }

        // Encrypt
        final ratchet = _ratchetMap[ratchetKey]!.clone();
        final authMessage = await ratchet.ratchetEncrypt(payloadKey);

        // Package
        if (kex.containsKey(ratchetKey)) {
          final kexMessage = kex[ratchetKey]!..message = authMessage;
        encryptedKeys.appendOrCreate(
          jid,
          EncryptedKey(
            jid,
            device,
            base64Encode(kexMessage.writeToBuffer()),
            true,
          ),
        );
        } else if (!ratchet.acknowledged) {
          // The ratchet as not yet been acked
          if (ratchet.kex == null) {
            // The ratchet is not acked but we also don't have an old KEX to send with it
            _log.warning('Ratchet $jid:$device is not acked but has no previous KEX.');

            encryptedKeys.appendOrCreate(
              jid,
              EncryptedKey(
                jid,
                device,
                base64Encode(authMessage.writeToBuffer()),
                false,
              ),
            );
            continue;
          }

          // Keep sending the old KEX
          final kexMessage = OMEMOKeyExchange()
            ..pkId = ratchet.kex!.pkId
            ..spkId = ratchet.kex!.spkId
            ..ik = await ratchet.kex!.ik.getBytes()
            ..ek = await ratchet.kex!.ek.getBytes()
            ..message = authMessage;
          encryptedKeys.appendOrCreate(
            jid,
            EncryptedKey(
              jid,
              device,
              base64Encode(kexMessage.writeToBuffer()),
              true,
            ),
          );
        } else {
          // The ratchet exists and is acked
          encryptedKeys.appendOrCreate(
            jid,
            EncryptedKey(
              jid,
              device,
              base64Encode(authMessage.writeToBuffer()),
              false,
            ),
          );
        }
      }
    }

    return EncryptionResult(
      ciphertext,
      encryptedKeys,
      encryptionErrors,
    );
  }

  // TODO
  Future<void> sendOmemoHeartbeat(String jid) async {}

  // TODO
  Future<void> removeAllRatchets(String jid) async {}

  // TODO
  Future<void> onDeviceListUpdate(String jid, List<int> devices) async {}

  // TODO
  Future<void> onNewConnection() async {}

  // TODO
  Future<void> ratchetAcknowledged(String jid, int device) async {}

  // TODO
  Future<List<DeviceFingerprint>> getFingerprintsForJid(String jid) async => [];

  /// Returns the device used for encryption and decryption.
  Future<OmemoDevice> getDevice() => _deviceLock.synchronized(() => _device);

  /// Returns the id of the device used for encryption and decryption.
  Future<int> getDeviceId() async => (await getDevice()).id;

  @visibleForTesting
  OmemoDoubleRatchet getRatchet(RatchetMapKey key) => _ratchetMap[key]!;
}
