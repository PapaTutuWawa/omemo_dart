/// Triggered during X3DH if the signature if the SPK does verify to the actual SPK.
class InvalidSignatureException implements Exception {
  String errMsg() => 'The signature of the SPK does not match the provided signature';
}

/// Triggered by the Double Ratchet if the computed HMAC does not match the attached HMAC.
/// Triggered by the Session Manager if the computed HMAC does not match the attached HMAC.
class InvalidMessageHMACException implements Exception {
  String errMsg() => 'The computed HMAC does not match the provided HMAC';
}

/// Triggered by the Double Ratchet if skipping messages would cause skipping more than
/// MAXSKIP messages
class SkippingTooManyMessagesException implements Exception {
  String errMsg() => 'Skipping messages would cause a skip bigger than MAXSKIP';
}

/// Triggered by the Session Manager if the message key is not encrypted for the device.
class NotEncryptedForDeviceException implements Exception {
  String errMsg() => 'Not encrypted for this device';
}

/// Triggered by the Session Manager when there is no key for decrypting the message.
class NoDecryptionKeyException implements Exception {
  String errMsg() => 'No key available for decrypting the message';
}

/// Triggered by the Session Manager when the identifier of the used Signed Prekey
/// is neither the current SPK's identifier nor the old one's.
class UnknownSignedPrekeyException implements Exception {
  String errMsg() => 'Unknown Signed Prekey used.';
}

/// Triggered by the Session Manager when the received Key Exchange message does not meet
/// the requirement that a key exchange, given that the ratchet already exists, must be
/// sent after its creation.
class InvalidKeyExchangeException implements Exception {
  String errMsg() => 'The key exchange was sent before the last kex finished';
}

/// Triggered by the Session Manager when a message's sequence number is smaller than we
/// expect it to be.
class MessageAlreadyDecryptedException implements Exception {
  String errMsg() => 'The message has already been decrypted';
}
