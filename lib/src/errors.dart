class InvalidSignatureException implements Exception {
  String errMsg() => 'The signature of the SPK does not match the provided signature';
}
