import 'dart:convert';

import 'package:meta/meta.dart';

/// EncryptedKey is the intermediary format of a <key /> element in the OMEMO message's
/// <keys /> header.
@immutable
class EncryptedKey {
  const EncryptedKey(this.rid, this.value, this.kex);

  /// The id of the device the key is encrypted for.
  final int rid;

  /// The base64-encoded payload.
  final String value;

  /// Flag indicating whether the payload is a OMEMOKeyExchange (true) or
  /// an OMEMOAuthenticatedMessage (false).
  final bool kex;

  /// The base64-decoded payload.
  List<int> get data => base64Decode(value);
}
