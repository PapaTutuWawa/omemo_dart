import 'package:meta/meta.dart';
import 'package:omemo_dart/src/omemo/encrypted_key.dart';

@immutable
class EncryptionResult {
  const EncryptionResult(this.ciphertext, this.encryptedKeys);
  
  /// The actual message that was encrypted
  final List<int>? ciphertext;

  /// Mapping of the device Id to the key for decrypting ciphertext, encrypted
  /// for the ratchet with said device Id
  final List<EncryptedKey> encryptedKeys;
}
