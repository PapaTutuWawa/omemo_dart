import 'dart:async';
import 'dart:convert';
import 'package:collection/collection.dart';
import 'package:cryptography/cryptography.dart';
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
import 'package:omemo_dart/src/omemo/fingerprint.dart';
import 'package:omemo_dart/src/omemo/queue.dart';
import 'package:omemo_dart/src/omemo/ratchet_data.dart';
import 'package:omemo_dart/src/omemo/ratchet_map_key.dart';
import 'package:omemo_dart/src/omemo/stanza.dart';
import 'package:omemo_dart/src/protobuf/schema.pb.dart';
import 'package:omemo_dart/src/trust/base.dart';
import 'package:omemo_dart/src/x3dh/x3dh.dart';
import 'package:synchronized/synchronized.dart';

class OmemoDataPackage {
  const OmemoDataPackage(this.devices, this.ratchets);

  /// The device list for the given JID.
  final List<int> devices;

  /// The ratchets for the JID.
  final Map<RatchetMapKey, OmemoDoubleRatchet> ratchets;
}

/// Callback type definitions

/// Directly "package" [result] into an OMEMO message and send it to [recipientJid].
typedef SendEmptyOmemoMessageFunction = Future<void> Function(
  EncryptionResult result,
  String recipientJid,
);

/// Fetches the device list for [jid]. If no device list could be fetched, returns null.
typedef FetchDeviceListFunction = Future<List<int>?> Function(String jid);

/// Fetch the device bundle for the device with id @id of jid. If it cannot be fetched, return null.
typedef FetchDeviceBundleFunction = Future<OmemoBundle?> Function(
  String jid,
  int id,
);

/// Subscribes to the device list node of [jid].
typedef DeviceListSubscribeFunction = Future<void> Function(String jid);

/// Commits the device list for [jid] to persistent storage. [added] will be the list of
/// devices added and [removed] will be the list of removed devices.
typedef CommitDeviceListCallback = Future<void> Function(
  String jid,
  List<int> added,
  List<int> removed,
);

/// A stub implementation of [CommitDeviceListCallback].
Future<void> commitDeviceListStub(
  String _,
  List<int> __,
  List<int> ___,
) async {}

/// Commits the mapping of the (new) ratchets in [ratchets] to persistent storage.
typedef CommitRatchetsCallback = Future<void> Function(
  List<OmemoRatchetData> ratchets,
);

/// A stub implementation of [CommitRatchetsCallback];
Future<void> commitRatchetsStub(List<OmemoRatchetData> _) async {}

/// Commits the device [device] to persistent storage.
typedef CommitDeviceCallback = Future<void> Function(OmemoDevice device);

/// A stub implementation of [CommitDeviceCallback].
Future<void> commitDeviceStub(OmemoDevice device) async {}

/// Removes the ratchets identified by their keys in [ratchets] from persistent storage.
typedef RemoveRatchetsFunction = Future<void> Function(
  List<RatchetMapKey> ratchets,
);

/// A stub implementation of [RemoveRatchetsFunction].
Future<void> removeRatchetsStub(List<RatchetMapKey> ratchets) async {}

/// Loads all the required data for the ratchets of [jid].
typedef LoadRatchetsCallback = Future<OmemoDataPackage?> Function(String jid);

/// A stub implementation of [LoadRatchetsCallback].
Future<OmemoDataPackage?> loadRatchetsStub(String _) async => null;

class OmemoManager {
  OmemoManager(
    this._device,
    this._trustManager,
    this.sendEmptyOmemoMessageImpl,
    this.fetchDeviceListImpl,
    this.fetchDeviceBundleImpl,
    this.subscribeToDeviceListNodeImpl, {
    this.commitRatchets = commitRatchetsStub,
    this.commitDeviceList = commitDeviceListStub,
    this.commitDevice = commitDeviceStub,
    this.removeRatchets = removeRatchetsStub,
    this.loadRatchets = loadRatchetsStub,
  });

  final Logger _log = Logger('OmemoManager');

  /// Functions for connecting with the OMEMO library

  /// Send an empty OMEMO:2 message using the encrypted payload @result to
  /// @recipientJid.
  final SendEmptyOmemoMessageFunction sendEmptyOmemoMessageImpl;

  /// Fetch the list of device ids associated with @jid. If the device list cannot be
  /// fetched, return null.
  final FetchDeviceListFunction fetchDeviceListImpl;

  /// Fetch the device bundle for the device with id @id of jid. If it cannot be fetched, return null.
  final FetchDeviceBundleFunction fetchDeviceBundleImpl;

  /// Subscribe to the device list PEP node of @jid.
  final DeviceListSubscribeFunction subscribeToDeviceListNodeImpl;

  /// Callback to commit the ratchet to persistent storage.
  final CommitRatchetsCallback commitRatchets;

  /// Callback to commit the device list to persistent storage.
  final CommitDeviceListCallback commitDeviceList;

  /// Callback to commit the device to persistent storage.
  final CommitDeviceCallback commitDevice;

  /// Callback to remove ratchets from persistent storage.
  final RemoveRatchetsFunction removeRatchets;

  /// Callback to load ratchets from persistent storage.
  final LoadRatchetsCallback loadRatchets;

  /// Map bare JID to its known devices
  final Map<String, List<int>> _deviceList = {};

  /// Map bare JIDs to whether we already requested the device list once
  final Map<String, bool> _deviceListRequested = {};

  /// Map bare a ratchet key to its ratchet. Note that this is also locked by
  /// _ratchetCriticalSectionLock.
  final Map<RatchetMapKey, OmemoDoubleRatchet> _ratchetMap = {};

  /// Map bare JID to whether we already tried to subscribe to the device list node.
  final Map<String, bool> _subscriptionMap = {};

  /// List of JIDs for which we cached trust data, the device list, and the ratchets.
  final List<String> _cachedJids = [];

  /// For preventing a race condition in encryption/decryption
  final RatchetAccessQueue _ratchetQueue = RatchetAccessQueue();

  /// The OmemoManager's trust management
  final TrustManager _trustManager;
  TrustManager get trustManager => _trustManager;

  /// Our own keys...
  final Lock _deviceLock = Lock();
  // ignore: prefer_final_fields
  OmemoDevice _device;

  Future<void> _cacheJidsIfNeccessary(List<String> jids) async {
    for (final jid in jids) {
      await _cacheJidIfNeccessary(jid);
    }
  }

  Future<void> _cacheJidIfNeccessary(String jid) async {
    // JID is already cached. We don't have to do anything.
    if (_cachedJids.contains(jid)) {
      return;
    }

    _cachedJids.add(jid);
    final result = await loadRatchets(jid);
    if (result == null) {
      _log.fine('Did not load ratchet data for $jid. Assuming there is none.');
      return;
    }

    // Cache the data
    _deviceList[jid] = result.devices;
    _ratchetMap.addAll(result.ratchets);

    // Load trust data
    await trustManager.loadTrustData(jid);
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

    final result = await aes256CbcDecrypt(
      ciphertext,
      derivedKeys.encryptionKey,
      derivedKeys.iv,
    );
    if (result.isType<MalformedCiphertextError>()) {
      return Result(
        result.get<MalformedCiphertextError>(),
      );
    }

    return Result(
      utf8.decode(
        result.get<List<int>>(),
      ),
    );
  }

  /// Fetches the device list from the server for [jid] and downloads OMEMO bundles
  /// for devices we have no session with.
  ///
  /// Returns a list of new bundles, that may be empty.
  Future<List<OmemoBundle>> _fetchNewOmemoBundles(String jid) async {
    // Do we have to request the device list or are we already up-to-date?
    if (!_deviceListRequested.containsKey(jid) ||
        !_deviceList.containsKey(jid)) {
      final newDeviceList = await fetchDeviceListImpl(jid);
      if (newDeviceList != null) {
        // Figure out what bundles we must fetch
        _deviceList[jid] = newDeviceList;
        _deviceListRequested[jid] = true;

        await commitDeviceList(
          jid,
          newDeviceList,
          [],
        );
      }
    }

    // Check that we have the device list
    if (!_deviceList.containsKey(jid)) {
      _log.warning('$jid not tracked in device list.');
      return [];
    }

    final ownDevice = await getDevice();
    final bundlesToFetch = _deviceList[jid]!.where((device) {
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

  Future<void> _maybeSendEmptyMessage(
    RatchetMapKey key,
    bool created,
    bool replaced,
  ) async {
    final ratchet = _ratchetMap[key]!;
    if (ratchet.acknowledged) {
      // The ratchet is acknowledged
      _log.finest(
        'Checking whether to heartbeat to ${key.jid}, ratchet.nr (${ratchet.nr}) >= 53: ${ratchet.nr >= 53}, created: $created, replaced: $replaced',
      );
      if (ratchet.nr >= 53 || created || replaced) {
        await sendEmptyOmemoMessageImpl(
          await _onOutgoingStanzaImpl(
            OmemoOutgoingStanza(
              [key.jid],
              null,
            ),
          ),
          key.jid,
        );
      }
    } else {
      // Ratchet is not acknowledged
      _log.finest('Sending acknowledgement heartbeat to ${key.jid}');
      await _ratchetAcknowledged(key.jid, key.deviceId);
      await sendEmptyOmemoMessageImpl(
        await _onOutgoingStanzaImpl(
          OmemoOutgoingStanza(
            [key.jid],
            null,
          ),
        ),
        key.jid,
      );
    }
  }

  ///
  Future<DecryptionResult> onIncomingStanza(OmemoIncomingStanza stanza) async {
    return _ratchetQueue.synchronized(
      [stanza.bareSenderJid],
      () => _onIncomingStanzaImpl(stanza),
    );
  }

  Future<DecryptionResult> _onIncomingStanzaImpl(
    OmemoIncomingStanza stanza,
  ) async {
    // Populate the cache
    await _cacheJidIfNeccessary(stanza.bareSenderJid);

    // Find the correct key for our device
    final deviceId = await getDeviceId();
    final key = stanza.keys.firstWhereOrNull((key) => key.rid == deviceId);
    if (key == null) {
      return DecryptionResult(
        null,
        NotEncryptedForDeviceError(),
      );
    }

    // Check how we should process the message
    final ratchetKey =
        RatchetMapKey(stanza.bareSenderJid, stanza.senderDeviceId);
    var processAsKex = key.kex;
    if (key.kex && _ratchetMap.containsKey(ratchetKey)) {
      final ratchet = _ratchetMap[ratchetKey]!;
      final kexMessage = OMEMOKeyExchange.fromBuffer(key.data);
      final ratchetEk = await ratchet.kex.ek.getBytes();
      final sameEk = listsEqual(kexMessage.ek, ratchetEk);

      if (sameEk) {
        processAsKex = false;
      } else {
        processAsKex = true;
      }
      _log.finest('kexMessage.ek == ratchetEk: $sameEk');
    }

    // Process the message
    if (processAsKex) {
      _log.finest('Decoding message as OMEMOKeyExchange');
      final kexMessage = OMEMOKeyExchange.fromBuffer(key.data);

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
      final kexEk = OmemoPublicKey.fromBytes(
        kexMessage.ek,
        KeyPairType.x25519,
      );
      final kex = await x3dhFromInitialMessage(
        X3DHMessage(
          kexIk,
          kexEk,
          kexMessage.pkId,
        ),
        spk,
        device.opks[kexMessage.pkId]!,
        device.ik,
      );
      final ratchet = await OmemoDoubleRatchet.acceptNewSession(
        spk,
        kexMessage.spkId,
        kexIk,
        kexMessage.pkId,
        kexEk,
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
        stanza.payload?.fromBase64(),
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

      // If we received an empty OMEMO message, mark the ratchet as acknowledged
      if (result.get<String?>() == null) {
        if (!ratchet.acknowledged) {
          ratchet.acknowledged = true;
        }
      }

      // Commit the ratchet
      _ratchetMap[ratchetKey] = ratchet;
      _deviceList.appendOrCreate(stanza.bareSenderJid, stanza.senderDeviceId);
      await commitRatchets([
        OmemoRatchetData(
          stanza.bareSenderJid,
          stanza.senderDeviceId,
          ratchet,
          true,
          false,
        ),
      ]);

      // Replace the OPK if we're not doing a catchup.
      if (!stanza.isCatchup) {
        await _deviceLock.synchronized(() async {
          await _device.replaceOnetimePrekey(kexMessage.pkId);
          await commitDevice(_device);
        });
      }

      // Send the hearbeat, if we have to
      await _maybeSendEmptyMessage(
        ratchetKey,
        true,
        _ratchetMap.containsKey(ratchetKey),
      );

      return DecryptionResult(
        result.get<String?>(),
        null,
      );
    } else {
      // Check if we even have a ratchet
      if (!_ratchetMap.containsKey(ratchetKey)) {
        // TODO(Unknown): Check if we recently failed to build a session with the device
        // This causes omemo_dart to build a session with the device.
        if (!_deviceList[stanza.bareSenderJid]!
            .contains(stanza.senderDeviceId)) {
          _deviceList[stanza.bareSenderJid]!.add(stanza.senderDeviceId);
        }
        await _sendOmemoHeartbeat(stanza.bareSenderJid);

        return DecryptionResult(
          null,
          NoSessionWithDeviceError(),
        );
      }

      _log.finest('Decoding message as OMEMOAuthenticatedMessage');
      final ratchet = _ratchetMap[ratchetKey]!.clone();

      // Correctly decode the message
      OMEMOAuthenticatedMessage authMessage;
      if (key.kex) {
        _log.finest(
          'Extracting OMEMOAuthenticatedMessage from OMEMOKeyExchange',
        );
        authMessage = OMEMOKeyExchange.fromBuffer(key.data).message;
      } else {
        authMessage = OMEMOAuthenticatedMessage.fromBuffer(key.data);
      }

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

      // If we received an empty OMEMO message, mark the ratchet as acknowledged
      if (result.get<String?>() == null) {
        if (!ratchet.acknowledged) {
          ratchet.acknowledged = true;
        }
      }

      // Message was successfully decrypted, so commit the ratchet
      _ratchetMap[ratchetKey] = ratchet;
      await commitRatchets([
        OmemoRatchetData(
          stanza.bareSenderJid,
          stanza.senderDeviceId,
          ratchet,
          false,
          false,
        ),
      ]);

      // Send a heartbeat, if required.
      await _maybeSendEmptyMessage(ratchetKey, false, false);

      return DecryptionResult(
        result.get<String?>(),
        null,
      );
    }
  }

  Future<EncryptionResult> onOutgoingStanza(OmemoOutgoingStanza stanza) async {
    return _ratchetQueue.synchronized(
      stanza.recipientJids,
      () => _onOutgoingStanzaImpl(stanza),
    );
  }

  Future<EncryptionResult> _onOutgoingStanzaImpl(
    OmemoOutgoingStanza stanza,
  ) async {
    // Populate the cache
    await _cacheJidsIfNeccessary(stanza.recipientJids);

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

    final encryptionErrors = <String, List<EncryptToJidError>>{};
    final addedRatchetKeys = List<RatchetMapKey>.empty(growable: true);
    final kex = <RatchetMapKey, OMEMOKeyExchange>{};
    for (final jid in stanza.recipientJids) {
      final newBundles = await _fetchNewOmemoBundles(jid);
      if (newBundles.isEmpty) {
        continue;
      }

      for (final bundle in newBundles) {
        _log.finest('Building new ratchet $jid:${bundle.id}');
        final ratchetKey = RatchetMapKey(jid, bundle.id);
        final ownDevice = await getDevice();
        final kexResultRaw = await x3dhFromBundle(
          bundle,
          ownDevice.ik,
        );
        // TODO(Unknown): Track the failure and do not attempt to encrypt to this device
        //                on every send.
        if (kexResultRaw.isType<InvalidKeyExchangeSignatureError>()) {
          encryptionErrors.appendOrCreate(
            jid,
            EncryptToJidError(
              bundle.id,
              kexResultRaw.get<InvalidKeyExchangeSignatureError>(),
            ),
          );
          continue;
        }

        final kexResult = kexResultRaw.get<X3DHAliceResult>();
        final newRatchet = await OmemoDoubleRatchet.initiateNewSession(
          bundle.spk,
          bundle.spkId,
          bundle.ik,
          ownDevice.ik.pk,
          kexResult.ek.pk,
          kexResult.sk,
          kexResult.ad,
          getTimestamp(),
          kexResult.opkId,
        );

        // Track the ratchet
        _ratchetMap[ratchetKey] = newRatchet;
        addedRatchetKeys.add(ratchetKey);

        // Initiate trust
        await trustManager.onNewSession(jid, bundle.id);

        // Track the KEX for later
        final ik = await ownDevice.ik.pk.getBytes();
        final ek = await kexResult.ek.pk.getBytes();
        kex[ratchetKey] = OMEMOKeyExchange()
          ..pkId = newRatchet.kex.pkId
          ..spkId = newRatchet.kex.spkId
          ..ik = ik
          ..ek = ek;
      }
    }

    // Commit the newly created ratchets, if we created any.
    if (addedRatchetKeys.isNotEmpty) {
      await commitRatchets(
        addedRatchetKeys.map((key) {
          return OmemoRatchetData(
            key.jid,
            key.deviceId,
            _ratchetMap[key]!,
            true,
            false,
          );
        }).toList(),
      );
    }

    // Encrypt the symmetric key for all devices.
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
        final ratchet = _ratchetMap[ratchetKey]!;
        final authMessage = await ratchet.ratchetEncrypt(payloadKey);

        // Package
        if (kex.containsKey(ratchetKey)) {
          final kexMessage = kex[ratchetKey]!..message = authMessage;
          encryptedKeys.appendOrCreate(
            jid,
            EncryptedKey(
              device,
              base64Encode(kexMessage.writeToBuffer()),
              true,
            ),
          );
        } else if (!ratchet.acknowledged) {
          // The ratchet as not yet been acked.
          // Keep sending the old KEX
          _log.finest('Using old KEX data for OMEMOKeyExchange');
          final kexMessage = OMEMOKeyExchange()
            ..pkId = ratchet.kex.pkId
            ..spkId = ratchet.kex.spkId
            ..ik = await ratchet.kex.ik.getBytes()
            ..ek = await ratchet.kex.ek.getBytes()
            ..message = authMessage;

          encryptedKeys.appendOrCreate(
            jid,
            EncryptedKey(
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

  /// Sends an empty OMEMO message (heartbeat) to [jid].
  Future<void> sendOmemoHeartbeat(String jid) async {
    await _ratchetQueue.synchronized(
      [jid],
      () => _sendOmemoHeartbeat(jid),
    );
  }

  /// Like [sendOmemoHeartbeat], but does not acquire the lock for [jid].
  Future<void> _sendOmemoHeartbeat(String jid) async {
    final result = await _onOutgoingStanzaImpl(
      OmemoOutgoingStanza(
        [jid],
        null,
      ),
    );
    await sendEmptyOmemoMessageImpl(result, jid);
  }

  /// Removes all ratchets associated with [jid].
  Future<void> removeAllRatchets(String jid) async {
    await _ratchetQueue.synchronized(
      [jid],
      () async {
        // Remove the ratchet and commit
        final keys = (_deviceList[jid] ?? <int>[])
            .map((device) => RatchetMapKey(jid, device));
        for (final key in keys) {
          _ratchetMap.remove(key);
        }
        await removeRatchets(keys.toList());

        // TODO: Do we have to tell the trust manager?

        // Clear the device list
        await commitDeviceList(
          jid,
          [],
          _deviceList[jid]!,
        );
        _deviceList.remove(jid);
        _deviceListRequested.remove(jid);
      },
    );
  }

  /// To be called when a update to the device list of [jid] is returned.
  /// [devices] is the list of device identifiers contained in the update.
  Future<void> onDeviceListUpdate(String jid, List<int> devices) async {
    await _ratchetQueue.synchronized(
      [jid],
      () async {
        // Compute the delta
        ListDiff<int> delta;
        if (_deviceList.containsKey(jid)) {
          delta = _deviceList[jid]!.diff(devices);
        } else {
          delta = ListDiff(devices, []);
        }

        // Update our state
        _deviceList[jid] = devices;
        _deviceListRequested[jid] = true;

        // Commit the device list
        await commitDeviceList(jid, delta.added, delta.removed);
      },
    );
  }

  /// To be called when a new connection is made, i.e. when the previous stream could
  /// previous stream could not be resumed using XEP-0198.
  Future<void> onNewConnection() async {
    _deviceListRequested.clear();
    _subscriptionMap.clear();
  }

  // Mark the ratchet [jid]:[device] as acknowledged.
  Future<void> ratchetAcknowledged(String jid, int device) async {
    await _ratchetQueue.synchronized(
      [jid],
      () => _ratchetAcknowledged(jid, device),
    );
  }

  /// Like [ratchetAcknowledged], but does not acquire the lock for [jid].
  Future<void> _ratchetAcknowledged(String jid, int device) async {
    final ratchetKey = RatchetMapKey(jid, device);
    if (!_ratchetMap.containsKey(ratchetKey)) {
      _log.warning(
        'Cannot mark $jid:$device as acknowledged as the ratchet does not exist',
      );
    } else {
      // Commit
      final ratchet = _ratchetMap[ratchetKey]!..acknowledged = true;
      await commitRatchets([
        OmemoRatchetData(
          jid,
          device,
          ratchet,
          false,
          false,
        ),
      ]);
    }
  }

  /// If ratchets with [jid] exists, returns a list of fingerprints for each
  /// ratchet.
  ///
  /// If not ratchets exists, returns null.
  Future<List<DeviceFingerprint>?> getFingerprintsForJid(String jid) async {
    return _ratchetQueue.synchronized(
      [jid],
      () => _getFingerprintsForJidImpl(jid),
    );
  }

  /// Same as [getFingerprintsForJid], but without acquiring the lock for [jid].
  Future<List<DeviceFingerprint>?> _getFingerprintsForJidImpl(
    String jid,
  ) async {
    // Check if we know of the JID.
    if (!_deviceList.containsKey(jid)) {
      return null;
    }

    final devices = _deviceList[jid]!;
    final fingerprints = List<DeviceFingerprint>.empty(growable: true);
    for (final device in devices) {
      final ratchet = _ratchetMap[RatchetMapKey(jid, device)];
      if (ratchet == null) {
        _log.warning('getFingerprintsForJid: Ratchet $jid:$device not found.');
        continue;
      }

      fingerprints.add(
        DeviceFingerprint(
          device,
          await ratchet.fingerprint,
        ),
      );
    }

    return fingerprints;
  }

  /// Returns the device used for encryption and decryption.
  Future<OmemoDevice> getDevice() => _deviceLock.synchronized(() => _device);

  /// Returns the id of the device used for encryption and decryption.
  Future<int> getDeviceId() async => (await getDevice()).id;

  @visibleForTesting
  OmemoDoubleRatchet? getRatchet(RatchetMapKey key) => _ratchetMap[key];
}
