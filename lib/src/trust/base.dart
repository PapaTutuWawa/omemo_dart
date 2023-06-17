import 'package:meta/meta.dart';

/// The base class for managing trust in OMEMO sessions.
// ignore: one_member_abstracts
abstract class TrustManager {
  /// Return true when the device with id [deviceId] of Jid [jid] is trusted, i.e. if an
  /// encrypted message should be sent to this device. If not, return false.
  Future<bool> isTrusted(String jid, int deviceId);

  /// Called by the OmemoSessionManager when a new session has been built. Should set
  /// a default trust state to [jid]'s device with identifier [deviceId].
  Future<void> onNewSession(String jid, int deviceId);

  /// Return true if the device with id [deviceId] of Jid [jid] should be used for encryption.
  /// If not, return false.
  Future<bool> isEnabled(String jid, int deviceId);

  /// Mark the device with id [deviceId] of Jid [jid] as enabled if [enabled] is true or as disabled
  /// if [enabled] is false.
  Future<void> setEnabled(String jid, int deviceId, bool enabled);

  /// Removes all trust decisions for [jid].
  Future<void> removeTrustDecisionsForJid(String jid);

  // ignore: comment_references
  /// Called from within the [OmemoManager].
  /// Loads the trust data for the JID [jid] from persistent storage
  /// into the internal cache, if applicable.
  @internal
  Future<void> loadTrustData(String jid);
}
