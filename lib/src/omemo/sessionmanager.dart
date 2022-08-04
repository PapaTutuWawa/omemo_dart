import 'dart:convert';
import 'package:collection/collection.dart';
import 'package:omemo_dart/protobuf/schema.pb.dart';
import 'package:omemo_dart/src/crypto.dart';
import 'package:omemo_dart/src/double_ratchet/double_ratchet.dart';
import 'package:omemo_dart/src/errors.dart';
import 'package:omemo_dart/src/helpers.dart';
import 'package:omemo_dart/src/omemo/bundle.dart';
import 'package:omemo_dart/src/omemo/device.dart';
import 'package:omemo_dart/src/x3dh/x3dh.dart';
import 'package:synchronized/synchronized.dart';

/// The info used for when encrypting the AES key for the actual payload.
const omemoPayloadInfoString = 'OMEMO Payload';

class EncryptionResult {

  const EncryptionResult(this.ciphertext, this.encryptedKeys);
  
  /// The actual message that was encrypted
  final List<int> ciphertext;

  /// Mapping of the device Id to the key for decrypting ciphertext, encrypted
  /// for the ratchet with said device Id
  final Map<String, List<int>> encryptedKeys;
}

class EncryptedKey {

  const EncryptedKey(this.rid, this.value);
  final String rid;
  final String value;
}

class OmemoSessionManager {

  OmemoSessionManager(this.device) : _ratchetMap = {}, _deviceMap = {}, _lock = Lock();

  /// Generate a new cryptographic identity.
  static Future<OmemoSessionManager> generateNewIdentity({ int opkAmount = 100 }) async {
    assert(opkAmount > 0, 'opkAmount must be bigger than 0.');
    final device = await Device.generateNewDevice(opkAmount: opkAmount);

    return OmemoSessionManager(device);
  }
  
  /// Lock for _ratchetMap and _bundleMap
  final Lock _lock;
  
  /// Mapping of the Device Id to its OMEMO session
  final Map<String, OmemoDoubleRatchet> _ratchetMap;

  /// Mapping of a bare Jid to its Device Ids
  final Map<String, List<String>> _deviceMap;

  /// Our own keys
  Device device;

  /// Add a session [ratchet] with the [deviceId] to the internal tracking state.
  Future<void> addSession(String jid, String deviceId, OmemoDoubleRatchet ratchet) async {
    await _lock.synchronized(() async {
      // Add the bundle Id
      if (!_deviceMap.containsKey(jid)) {
        _deviceMap[jid] = [deviceId];
      } else {
        _deviceMap[jid]!.add(deviceId);
      }

      // Add the ratchet session
      if (!_ratchetMap.containsKey(deviceId)) {
        _ratchetMap[deviceId] = ratchet;
      } else {
        // TODO(PapaTutuWawa): What do we do now?
        throw Exception();
      }
    });
  }

  /// Create a ratchet session initiated by Alice to the user with Jid [jid] and the device
  /// [deviceId] from the bundle [bundle].
  Future<X3DHAliceResult> addSessionFromBundle(String jid, String deviceId, OmemoBundle bundle) async {
    final kexResult = await x3dhFromBundle(
      bundle,
      device.ik,
    );
    final ratchet = await OmemoDoubleRatchet.initiateNewSession(
      bundle.spk,
      kexResult.sk,
      kexResult.ad,
    );

    await addSession(jid, deviceId, ratchet);

    return kexResult;
  }

  /// Build a new session with the user at [jid] with the device [deviceId] using data
  /// from the key exchange [kex].
  // TODO(PapaTutuWawa): Use OMEMOKeyExchange
  // TODO(PapaTutuWawa): Replace the OPK
  Future<void> addSessionFromKeyExchange(String jid, String deviceId, X3DHMessage kex) async {
    final kexResult = await x3dhFromInitialMessage(
      kex,
      device.spk,
      // TODO(PapaTutuWawa): Fix
      device.opks.values.elementAt(0),
      device.ik,
    );
    final ratchet = await OmemoDoubleRatchet.acceptNewSession(
      device.spk,
      kexResult.sk,
      kexResult.ad,
    );

    await addSession(jid, deviceId, ratchet);
  }
  
  /// Encrypt the key [plaintext] for all known bundles of [jid]. Returns a map that
  /// maps the Bundle Id to the ciphertext of [plaintext].
  Future<EncryptionResult> encryptToJid(String jid, String plaintext) async {
    final encryptedKeys = <String, List<int>>{};

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

    await _lock.synchronized(() async {
      // We assume that the user already checked if the session exists
      for (final deviceId in _deviceMap[jid]!) {
        final ratchet = _ratchetMap[deviceId]!;
        encryptedKeys[deviceId] = (await ratchet.ratchetEncrypt(concatKey)).ciphertext;
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
  Future<String> decryptMessage(List<int> ciphertext, String senderJid, String senderDeviceId, List<EncryptedKey> keys) async {
    // Try to find a session we can decrypt with.
    final rawKey = keys.firstWhereOrNull((key) => key.rid == device.id);
    if (rawKey == null) {
      throw NotEncryptedForDeviceException();
    }

    final devices = _deviceMap[senderJid];
    if (devices == null) {
      throw NoDecryptionKeyException();
    }
    if (!devices.contains(senderDeviceId)) {
      throw NoDecryptionKeyException();
    }
    
    final decodedRawKey = base64.decode(rawKey.value);
    final authMessage = OMEMOAuthenticatedMessage.fromBuffer(decodedRawKey);
    final message = OMEMOMessage.fromBuffer(authMessage.message);
    
    final ratchet = _ratchetMap[senderDeviceId]!;
    final keyAndHmac = await ratchet.ratchetDecrypt(message, decodedRawKey);
    final key = keyAndHmac.sublist(0, 32);
    final hmac = keyAndHmac.sublist(32, 48);
    final derivedKeys = await deriveEncryptionKeys(key, omemoPayloadInfoString);

    final computedHmac = await truncatedHmac(ciphertext, derivedKeys.authenticationKey);
    if (!listsEqual(hmac, computedHmac)) {
      throw InvalidMessageHMACException();
    }

    final plaintext = await aes256CbcDecrypt(ciphertext, derivedKeys.encryptionKey, derivedKeys.iv);
    return utf8.decode(plaintext);
  }
}
