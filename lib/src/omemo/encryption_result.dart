import 'package:meta/meta.dart';
import 'package:omemo_dart/src/omemo/encrypted_key.dart';
import 'package:omemo_dart/src/omemo/errors.dart';

@immutable
class EncryptionResult {
  const EncryptionResult(
    this.ciphertext,
    this.encryptedKeys,
    this.deviceEncryptionErrors,
    this.canSend,
  );

  /// The actual message that was encrypted.
  final List<int>? ciphertext;

  /// Mapping of the device Id to the key for decrypting ciphertext, encrypted
  /// for the ratchet with said device Id.
  final Map<String, List<EncryptedKey>> encryptedKeys;

  /// Mapping of a JID to
  final Map<String, List<EncryptToJidError>> deviceEncryptionErrors;

  /// A flag indicating that the message could be sent like that, i.e. we were able
  /// to encrypt to at-least one device per recipient.
  final bool canSend;
}
