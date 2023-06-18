import 'package:meta/meta.dart';
import 'package:omemo_dart/src/helpers.dart';
import 'package:omemo_dart/src/omemo/ratchet_map_key.dart';
import 'package:omemo_dart/src/trust/base.dart';

@immutable
class BTBVTrustData {
  const BTBVTrustData(
    this.jid,
    this.device,
    this.state,
    this.enabled,
    this.trusted,
  );

  /// The JID in question.
  final String jid;

  /// The device (ratchet) in question.
  final int device;

  /// The trust state of the ratchet.
  final BTBVTrustState state;

  /// Flag indicating whether the ratchet is enabled (true) or not (false).
  final bool enabled;

  /// Flag indicating whether the ratchet is trusted. For loading and commiting a ratchet, this field
  /// contains an arbitrary value.
  /// When using [BlindTrustBeforeVerificationTrustManager.getDevicesTrust], this flag will be true if
  /// the ratchet is trusted and false if not.
  final bool trusted;
}

/// A callback for when a trust decision is to be commited to persistent storage.
typedef BTBVTrustCommitCallback = Future<void> Function(BTBVTrustData data);

/// A stub-implementation of [BTBVTrustCommitCallback].
Future<void> btbvCommitStub(BTBVTrustData _) async {}

/// A callback for when all trust decisions for a JID should be removed from persistent storage.
typedef BTBVRemoveTrustForJidCallback = Future<void> Function(String jid);

/// A stub-implementation of [BTBVRemoveTrustForJidCallback].
Future<void> btbvRemoveTrustStub(String _) async {}

/// A callback for when trust data should be loaded.
typedef BTBVLoadDataCallback = Future<List<BTBVTrustData>> Function(String jid);

/// A stub-implementation for [BTBVLoadDataCallback].
Future<List<BTBVTrustData>> btbvLoadDataStub(String _) async => [];

/// Every device is in either of those two trust states:
/// - notTrusted: The device is absolutely not trusted
/// - blindTrust: The fingerprint is not verified using OOB means
/// - verified: The fingerprint has been verified using OOB means
enum BTBVTrustState {
  notTrusted(1),
  blindTrust(2),
  verified(3);

  const BTBVTrustState(this.value);

  factory BTBVTrustState.fromInt(int value) {
    switch (value) {
      case 1:
        return BTBVTrustState.notTrusted;
      case 2:
        return BTBVTrustState.blindTrust;
      case 3:
        return BTBVTrustState.verified;
      // TODO(Unknown): Should we handle this better?
      default:
        return BTBVTrustState.notTrusted;
    }
  }

  /// The value backing the trust state.
  final int value;
}

/// A TrustManager that implements the idea of Blind Trust Before Verification.
/// See https://gultsch.de/trust.html for more details.
class BlindTrustBeforeVerificationTrustManager extends TrustManager {
  BlindTrustBeforeVerificationTrustManager({
    this.loadData = btbvLoadDataStub,
    this.commit = btbvCommitStub,
    this.removeTrust = btbvRemoveTrustStub,
  });

  /// The cache for mapping a RatchetMapKey to its trust state
  @visibleForTesting
  @protected
  final Map<RatchetMapKey, BTBVTrustState> trustCache = {};

  /// The cache for mapping a RatchetMapKey to whether it is enabled or not
  @visibleForTesting
  @protected
  final Map<RatchetMapKey, bool> enablementCache = {};

  /// Mapping of Jids to their device identifiers
  @visibleForTesting
  @protected
  final Map<String, List<int>> devices = {};

  /// Callback for loading trust data.
  final BTBVLoadDataCallback loadData;

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
    final trustCacheValue = trustCache[RatchetMapKey(jid, deviceId)];
    if (trustCacheValue == BTBVTrustState.notTrusted) {
      return false;
    } else if (trustCacheValue == BTBVTrustState.verified) {
      // The key is verified, so it's safe.
      return true;
    } else {
      if (_hasAtLeastOneVerifiedDevice(jid)) {
        // Do not trust if there is at least one device with full trust
        return false;
      } else {
        // We have not verified a key from [jid], so it is blind trust all the way.
        return true;
      }
    }
  }

  @override
  Future<void> onNewSession(String jid, int deviceId) async {
    final key = RatchetMapKey(jid, deviceId);
    if (_hasAtLeastOneVerifiedDevice(jid)) {
      trustCache[key] = BTBVTrustState.notTrusted;
      enablementCache[key] = false;
    } else {
      trustCache[key] = BTBVTrustState.blindTrust;
      enablementCache[key] = true;
    }

    // Append to the device list
    devices.appendOrCreate(jid, deviceId, checkExistence: true);

    // Commit the state
    await commit(
      BTBVTrustData(
        jid,
        deviceId,
        trustCache[key]!,
        enablementCache[key]!,
        false,
      ),
    );
  }

  /// Returns a mapping from the device identifiers of [jid] to their trust state. If
  /// there are no devices known for [jid], then an empty map is returned.
  Future<Map<int, BTBVTrustData>> getDevicesTrust(String jid) async {
    final map = <int, BTBVTrustData>{};

    if (!devices.containsKey(jid)) return map;

    for (final deviceId in devices[jid]!) {
      final key = RatchetMapKey(jid, deviceId);
      if (!trustCache.containsKey(key) || !enablementCache.containsKey(key)) {
        continue;
      }

      map[deviceId] = BTBVTrustData(
        jid,
        deviceId,
        trustCache[key]!,
        enablementCache[key]!,
        await isTrusted(jid, deviceId),
      );
    }

    return map;
  }

  /// Sets the trust of [jid]'s device with identifier [deviceId] to [state].
  Future<void> setDeviceTrust(
    String jid,
    int deviceId,
    BTBVTrustState state,
  ) async {
    final key = RatchetMapKey(jid, deviceId);
    trustCache[key] = state;

    // Commit the state
    await commit(
      BTBVTrustData(
        jid,
        deviceId,
        state,
        enablementCache[key]!,
        false,
      ),
    );
  }

  @override
  Future<bool> isEnabled(String jid, int deviceId) async {
    final value = enablementCache[RatchetMapKey(jid, deviceId)];

    if (value == null) return false;
    return value;
  }

  @override
  Future<void> setEnabled(String jid, int deviceId, bool enabled) async {
    final key = RatchetMapKey(jid, deviceId);
    enablementCache[key] = enabled;

    // Commit the state
    await commit(
      BTBVTrustData(
        jid,
        deviceId,
        trustCache[key]!,
        enabled,
        false,
      ),
    );
  }

  @override
  Future<void> removeTrustDecisionsForJid(String jid) async {
    // Clear the caches
    for (final device in devices[jid]!) {
      final key = RatchetMapKey(jid, device);
      trustCache.remove(key);
      enablementCache.remove(key);
    }
    devices.remove(jid);

    // Commit the state
    await removeTrust(jid);
  }

  @override
  Future<void> loadTrustData(String jid) async {
    for (final result in await loadData(jid)) {
      final key = RatchetMapKey(jid, result.device);
      trustCache[key] = result.state;
      enablementCache[key] = result.enabled;
      devices.appendOrCreate(jid, result.device, checkExistence: true);
    }
  }

  @visibleForTesting
  BTBVTrustState getDeviceTrust(String jid, int deviceId) =>
      trustCache[RatchetMapKey(jid, deviceId)]!;
}
