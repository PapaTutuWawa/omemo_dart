import 'package:meta/meta.dart';
import 'package:omemo_dart/src/omemo/ratchet_map_key.dart';
import 'package:omemo_dart/src/trust/base.dart';
import 'package:synchronized/synchronized.dart';

@immutable
class BTBVTrustData {
  const BTBVTrustData(
    this.jid,
    this.device,
    this.state,
    this.enabled,
  );

  /// The JID in question.
  final String jid;

  /// The device (ratchet) in question.
  final int device;

  /// The trust state of the ratchet.
  final BTBVTrustState state;

  /// Flag indicating whether the ratchet is enabled (true) or not (false).
  final bool enabled;
}

/// A callback for when a trust decision is to be commited to persistent storage.
typedef BTBVTrustCommitCallback = Future<void> Function(BTBVTrustData data);

/// A stub-implementation of [BTBVTrustCommitCallback].
Future<void> btbvCommitStub(BTBVTrustData _) async {}

/// A callback for when all trust decisions for a JID should be removed from persistent storage.
typedef BTBVRemoveTrustForJidCallback = Future<void> Function(String jid);

/// A stub-implementation of [BTBVRemoveTrustForJidCallback].
Future<void> btbvRemoveTrustStub(String _) async {}

/// Every device is in either of those two trust states:
/// - notTrusted: The device is absolutely not trusted
/// - blindTrust: The fingerprint is not verified using OOB means
/// - verified: The fingerprint has been verified using OOB means
enum BTBVTrustState {
  notTrusted(1),
  blindTrust(2),
  verified(3);

  const BTBVTrustState(this.value);

  /// The value backing the trust state.
  final int value;
}

/// A TrustManager that implements the idea of Blind Trust Before Verification.
/// See https://gultsch.de/trust.html for more details.
class BlindTrustBeforeVerificationTrustManager extends TrustManager {
  BlindTrustBeforeVerificationTrustManager({
    Map<RatchetMapKey, BTBVTrustState>? trustCache,
    Map<RatchetMapKey, bool>? enablementCache,
    Map<String, List<int>>? devices,
    this.commit = btbvCommitStub,
    this.removeTrust = btbvRemoveTrustStub,
  })  : trustCache = trustCache ?? {},
        enablementCache = enablementCache ?? {},
        devices = devices ?? {},
        _lock = Lock();

  /// The cache for mapping a RatchetMapKey to its trust state
  @visibleForTesting
  @protected
  final Map<RatchetMapKey, BTBVTrustState> trustCache;

  /// The cache for mapping a RatchetMapKey to whether it is enabled or not
  @visibleForTesting
  @protected
  final Map<RatchetMapKey, bool> enablementCache;

  /// Mapping of Jids to their device identifiers
  @visibleForTesting
  @protected
  final Map<String, List<int>> devices;

  /// The lock for devices and trustCache
  final Lock _lock;

  /// Callback for commiting trust data to persistent storage.
  final BTBVTrustCommitCallback commit;

  /// Callback for removing trust data for a JID.
  final BTBVRemoveTrustForJidCallback removeTrust;

  /// Returns true if [jid] has at least one device that is verified. If not, returns false.
  /// Note that this function accesses devices and trustCache, which requires that the
  /// lock for those two maps (_lock) has been aquired before calling.
  bool _hasAtLeastOneVerifiedDevice(String jid) {
    if (!devices.containsKey(jid)) return false;

    return devices[jid]!.any((id) {
      return trustCache[RatchetMapKey(jid, id)]! == BTBVTrustState.verified;
    });
  }

  @override
  Future<bool> isTrusted(String jid, int deviceId) async {
    var returnValue = false;
    await _lock.synchronized(() async {
      final trustCacheValue = trustCache[RatchetMapKey(jid, deviceId)];
      if (trustCacheValue == BTBVTrustState.notTrusted) {
        returnValue = false;
        return;
      } else if (trustCacheValue == BTBVTrustState.verified) {
        // The key is verified, so it's safe.
        returnValue = true;
        return;
      } else {
        if (_hasAtLeastOneVerifiedDevice(jid)) {
          // Do not trust if there is at least one device with full trust
          returnValue = false;
          return;
        } else {
          // We have not verified a key from [jid], so it is blind trust all the way.
          returnValue = true;
          return;
        }
      }
    });

    return returnValue;
  }

  @override
  Future<void> onNewSession(String jid, int deviceId) async {
    await _lock.synchronized(() async {
      final key = RatchetMapKey(jid, deviceId);
      if (_hasAtLeastOneVerifiedDevice(jid)) {
        trustCache[key] = BTBVTrustState.notTrusted;
        enablementCache[key] = false;
      } else {
        trustCache[key] = BTBVTrustState.blindTrust;
        enablementCache[key] = true;
      }

      if (devices.containsKey(jid)) {
        devices[jid]!.add(deviceId);
      } else {
        devices[jid] = List<int>.from([deviceId]);
      }

      // Commit the state
      await commit(
        BTBVTrustData(
          jid,
          deviceId,
          trustCache[key]!,
          enablementCache[key]!,
        ),
      );
    });
  }

  /// Returns a mapping from the device identifiers of [jid] to their trust state. If
  /// there are no devices known for [jid], then an empty map is returned.
  Future<Map<int, BTBVTrustState>> getDevicesTrust(String jid) async {
    return _lock.synchronized(() async {
      final map = <int, BTBVTrustState>{};

      if (!devices.containsKey(jid)) return map;

      for (final deviceId in devices[jid]!) {
        map[deviceId] = trustCache[RatchetMapKey(jid, deviceId)]!;
      }

      return map;
    });
  }

  /// Sets the trust of [jid]'s device with identifier [deviceId] to [state].
  Future<void> setDeviceTrust(
    String jid,
    int deviceId,
    BTBVTrustState state,
  ) async {
    await _lock.synchronized(() async {
      final key = RatchetMapKey(jid, deviceId);
      trustCache[key] = state;

      // Commit the state
      await commit(
        BTBVTrustData(
          jid,
          deviceId,
          state,
          enablementCache[key]!,
        ),
      );
    });
  }

  @override
  Future<bool> isEnabled(String jid, int deviceId) async {
    return _lock.synchronized(() async {
      final value = enablementCache[RatchetMapKey(jid, deviceId)];

      if (value == null) return false;
      return value;
    });
  }

  @override
  Future<void> setEnabled(String jid, int deviceId, bool enabled) async {
    final key = RatchetMapKey(jid, deviceId);
    await _lock.synchronized(() async {
      enablementCache[key] = enabled;

      // Commit the state
      await commit(
        BTBVTrustData(
          jid,
          deviceId,
          trustCache[key]!,
          enabled,
        ),
      );
    });
  }

  @override
  Future<void> removeTrustDecisionsForJid(String jid) async {
    await _lock.synchronized(() async {
      // Clear the caches
      for (final device in devices[jid]!) {
        final key = RatchetMapKey(jid, device);
        trustCache.remove(key);
        enablementCache.remove(key);
      }
      devices.remove(jid);

      // Commit the state
      await removeTrust(jid);
    });
  }

  @visibleForTesting
  BTBVTrustState getDeviceTrust(String jid, int deviceId) =>
      trustCache[RatchetMapKey(jid, deviceId)]!;
}
