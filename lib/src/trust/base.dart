/// The base class for managing trust in OMEMO sessions.
// ignore: one_member_abstracts
abstract class TrustManager {
  /// Return true when the device with id [deviceId] of Jid [jid] is trusted, i.e. if an
  /// encrypted message should be sent to this device. If not, return false.
  Future<bool> isTrusted(String jid, int deviceId);
}
