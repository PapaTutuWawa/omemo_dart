abstract class OmemoError {}

/// Triggered during X3DH if the signature if the SPK does verify to the actual SPK.
class InvalidKeyExchangeSignatureError extends OmemoError {}

/// Triggered by the Double Ratchet if the computed HMAC does not match the attached HMAC.
class InvalidMessageHMACError extends OmemoError {}

/// Triggered by the Double Ratchet if skipping messages would cause skipping more than
/// MAXSKIP messages
class SkippingTooManyKeysError extends OmemoError {}

/// Triggered by the Session Manager if the message key is not encrypted for the device.
class NotEncryptedForDeviceError extends OmemoError {}

/// Triggered by the Session Manager when the identifier of the used Signed Prekey
/// is neither the current SPK's identifier nor the old one's.
class UnknownSignedPrekeyError extends OmemoError {}

/// Triggered by the OmemoManager when we could not encrypt a message as we have
/// no key material available. That happens, for example, when we want to create a
/// ratchet session with a JID we had no session with but fetching the device bundle
/// failed.
class NoKeyMaterialAvailableError extends OmemoError {}

/// A non-key-exchange message was received that was encrypted for our device, but we have no ratchet with
/// the device that sent the message.
class NoSessionWithDeviceError extends OmemoError {}

/// Caused when the AES-256 CBC decryption failed.
class MalformedCiphertextError extends OmemoError {
  MalformedCiphertextError(this.ex);

  /// The exception that was raised while decryption.
  final Object ex;
}

/// Caused by an empty <key /> element
class MalformedEncryptedKeyError extends OmemoError {}
