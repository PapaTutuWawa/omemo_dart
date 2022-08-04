import 'dart:convert';
import 'package:omemo_dart/src/crypto.dart';
import 'package:omemo_dart/src/double_ratchet/double_ratchet.dart';
import 'package:omemo_dart/src/helpers.dart';
import 'package:omemo_dart/src/omemo/device.dart';
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

class OmemoSessionManager {

  OmemoSessionManager(this.device) : _ratchetMap = {}, _deviceMap = {}, _lock = Lock();

  /// Generate a new cryptographic identity.
  static Future<OmemoSessionManager> generateNewIdentity({ int opkAmount = 100 }) async {
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
    final concatKey = concat([keys.encryptionKey, hmac]);
    
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
}
