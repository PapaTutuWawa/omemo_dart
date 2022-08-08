import 'package:meta/meta.dart';
import 'package:omemo_dart/src/omemo/ratchet_map_key.dart';
import 'package:omemo_dart/src/trust/base.dart';
import 'package:synchronized/synchronized.dart';

/// Every device is in either of those two trust states:
/// - notTrusted: The device is absolutely not trusted
/// - blindTrust: The fingerprint is not verified using OOB means
/// - verified: The fingerprint has been verified using OOB means
enum BTBVTrustState {
  notTrusted,
  blindTrust,
  verified,
}

/// A TrustManager that implements the idea of Blind Trust Before Verification.
/// See https://gultsch.de/trust.html for more details.
abstract class BlindTrustBeforeVerificationTrustManager extends TrustManager {
  BlindTrustBeforeVerificationTrustManager()
    : trustCache = {},
      devices = {},
      _lock = Lock();

  /// The cache for Mapping a RatchetMapKey to its trust state
  @protected
  final Map<RatchetMapKey, BTBVTrustState> trustCache;

  /// Mapping of Jids to their device identifiers
  @protected
  final Map<String, List<int>> devices;

  /// The lock for devices and trustCache
  final Lock _lock;

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
      if (_hasAtLeastOneVerifiedDevice(jid)) {
        trustCache[RatchetMapKey(jid, deviceId)] = BTBVTrustState.notTrusted;
      } else {
        trustCache[RatchetMapKey(jid, deviceId)] = BTBVTrustState.blindTrust;
      }

      if (devices.containsKey(jid)) {
        devices[jid]!.add(deviceId);
      } else {
        devices[jid] = List<int>.from([deviceId]);
      }

      // Commit the state
      await commitState();
    });
  }
  
  /// Returns a mapping from the device identifiers of [jid] to their trust state.
  Future<Map<int, BTBVTrustState>> getDevicesTrust(String jid) async {
    final map = <int, BTBVTrustState>{};

    await _lock.synchronized(() async {
      for (final deviceId in devices[jid]!) {
        map[deviceId] = trustCache[RatchetMapKey(jid, deviceId)]!;
      }
    });

    return map;
  }

  /// Sets the trust of [jid]'s device with identifier [deviceId] to [state].
  Future<void> setDeviceTrust(String jid, int deviceId, BTBVTrustState state) async {
    await _lock.synchronized(() async {
      trustCache[RatchetMapKey(jid, deviceId)] = state;

      // Commit the state
      await commitState();
    });
  }

  /// Called when the state of the trust manager has been changed. Allows the user to
  /// commit the trust state to persistent storage.
  @visibleForOverriding
  Future<void> commitState();

  /// Called when the user wants to restore the state of the trust manager. The format
  /// and actual storage mechanism is left to the user.
  @visibleForOverriding
  Future<void> loadState();
  
  @visibleForTesting
  BTBVTrustState getDeviceTrust(String jid, int deviceId) => trustCache[RatchetMapKey(jid, deviceId)]!;
}

/// A BTBV TrustManager that does not commit its state to persistent storage. Well suited
/// for testing.
class MemoryBTBVTrustManager extends BlindTrustBeforeVerificationTrustManager {
  @override
  Future<void> commitState() async {}

  @override
  Future<void> loadState() async {}
}
