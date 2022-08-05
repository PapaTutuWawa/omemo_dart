import 'dart:convert';
import 'package:cryptography/cryptography.dart';
import 'package:omemo_dart/src/keys.dart';

OmemoPublicKey? decodeKeyIfNotNull(Map<String, dynamic> map, String key, KeyPairType type) {
  if (map[key] == null) return null;

  return OmemoPublicKey.fromBytes(
    base64.decode(map[key]! as String),
    type,
  );
}

List<int>? base64DecodeIfNotNull(Map<String, dynamic> map, String key) {
  if (map[key] == null) return null;

  return base64.decode(map[key]! as String);
}
