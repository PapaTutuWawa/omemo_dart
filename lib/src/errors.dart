/// Triggered during X3DH if the signature if the SPK does verify to the actual SPK.
class InvalidSignatureException implements Exception {
  String errMsg() => 'The signature of the SPK does not match the provided signature';
}

/// Triggered by the Double Ratchet if the computet HMAC does not match the attached HMAC.
class InvalidMessageHMACException implements Exception {
  String errMsg() => 'The computed HMAC does not match the provided HMAC';
}
