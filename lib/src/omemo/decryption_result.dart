import 'package:meta/meta.dart';
import 'package:omemo_dart/src/errors.dart';

@immutable
class DecryptionResult {
  const DecryptionResult(this.payload, this.usedOpkId, this.error);

  /// The decrypted payload or null, if it was an empty OMEMO message.
  final String? payload;

  /// In case a key exchange has been performed: The id of the used OPK. Useful for
  /// replacing the OPK after a message catch-up.
  final int? usedOpkId;

  /// The error that occurred during decryption or null, if no error occurred.
  final OmemoError? error;
}
