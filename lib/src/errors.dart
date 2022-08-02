class InvalidSignatureException implements Exception {
  @override
  String errMsg() => 'The signature of the SPK does not match the provided signature';
}
