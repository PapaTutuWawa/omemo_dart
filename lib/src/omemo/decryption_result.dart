import 'package:meta/meta.dart';
import 'package:omemo_dart/src/errors.dart';

@immutable
class DecryptionResult {
  const DecryptionResult(this.payload, this.error);
  final String? payload;
  final OmemoError? error;
}
