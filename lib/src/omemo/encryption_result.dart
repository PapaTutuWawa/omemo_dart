import 'package:meta/meta.dart';
import 'package:omemo_dart/src/errors.dart';
import 'package:omemo_dart/src/omemo/encrypted_key.dart';
import 'package:omemo_dart/src/omemo/ratchet_map_key.dart';

@immutable
class EncryptionResult {
  const EncryptionResult(
    this.ciphertext,
    this.encryptedKeys,
    this.deviceEncryptionErrors,
    this.jidEncryptionErrors,
  );

  /// The actual message that was encrypted.
  final List<int>? ciphertext;

  /// Mapping of the device Id to the key for decrypting ciphertext, encrypted
  /// for the ratchet with said device Id.
  final List<EncryptedKey> encryptedKeys;

  /// Mapping of a ratchet map keys to a possible exception.
  final Map<RatchetMapKey, OmemoException> deviceEncryptionErrors;

  /// Mapping of a JID to a possible exception.
  final Map<String, OmemoException> jidEncryptionErrors;

  /// True if the encryption was a success. This means that we could encrypt for
  /// at least one ratchet.
  bool isSuccess(int numberOfRecipients) =>
      encryptedKeys.isNotEmpty &&
      jidEncryptionErrors.length < numberOfRecipients;
}
