import 'dart:convert';
import 'package:cryptography/cryptography.dart';

/// Info string for KDF_RK
const kdfRkInfoString = 'OMEMO Root Chain';

/// Flags for KDF_CK
const kdfCkNextMessageKey = 0x01;
const kdfCkNextChainKey = 0x02;

/// Signals KDF_CK function as specified by OMEMO 0.8.0.
Future<List<int>> kdfCk(List<int> ck, int constant) async {
  final hkdf = Hkdf(hmac: Hmac(Sha256()), outputLength: 32);
  final result = await hkdf.deriveKey(
    secretKey: SecretKey(ck),
    nonce: [constant],
  );

  return result.extractBytes();
}

/// Signals KDF_RK function as specified by OMEMO 0.8.0.
Future<List<int>> kdfRk(List<int> rk, List<int> dhOut) async {
  final algorithm = Hkdf(
    hmac: Hmac(Sha256()),
    outputLength: 32,
  );
  final result = await algorithm.deriveKey(
    secretKey: SecretKey(dhOut),
    nonce: rk,
    info: utf8.encode(kdfRkInfoString),
  );

  return result.extractBytes();
}
