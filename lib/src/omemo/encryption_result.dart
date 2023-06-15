import 'package:meta/meta.dart';
import 'package:omemo_dart/src/errors.dart';
import 'package:omemo_dart/src/omemo/encrypted_key.dart';
import 'package:omemo_dart/src/omemo/errors.dart';
import 'package:omemo_dart/src/omemo/ratchet_map_key.dart';

@immutable
class EncryptionResult {
  const EncryptionResult(
    this.ciphertext,
    this.encryptedKeys,
    this.deviceEncryptionErrors,
  );

  /// The actual message that was encrypted.
  final List<int>? ciphertext;

  /// Mapping of the device Id to the key for decrypting ciphertext, encrypted
  /// for the ratchet with said device Id.
  final Map<String, List<EncryptedKey>> encryptedKeys;

  /// Mapping of a JID to 
  final Map<String, List<EncryptToJidError>> deviceEncryptionErrors;

  // TODO: Turn this into a property that is computed in [onOutgoingStanza].
  /// True if the encryption was a success. This means that we could encrypt for
  /// at least one ratchet per recipient. [recipients] is the number of recipients
  /// that the message should've been encrypted for.
  bool isSuccess(int recipients) => encryptedKeys.length == recipients;
}
