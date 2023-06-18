import 'package:omemo_dart/src/errors.dart';

/// Returned on encryption, if encryption failed for some reason.
class EncryptToJidError extends OmemoError {
  EncryptToJidError(this.device, this.error);

  /// The device the error occurred with
  final int? device;

  /// The actual error.
  final OmemoError error;
}
