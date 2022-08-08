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

class BlindTrustBeforeVerificationTrustManager extends TrustManager {
  BlindTrustBeforeVerificationTrustManager()
    : _trustCache = {},
      _devices = {},
      _lock = Lock();

  /// The cache for Mapping a RatchetMapKey to its trust state
  final Map<RatchetMapKey, BTBVTrustState> _trustCache;

  /// Mapping of Jids to their device identifiers
  final Map<String, List<int>> _devices;

  /// The lock for _devices and _trustCache
  final Lock _lock;

  /// Returns true if [jid] has at least one device that is verified. If not, returns false.
  /// Note that this function accesses _devices and _trustCache, which requires that the
  /// lock for those two maps (_lock) has been aquired before calling.
  bool _hasAtLeastOneVerifiedDevice(String jid) {
    if (!_devices.containsKey(jid)) return false;

    return _devices[jid]!.any((id) {
      return _trustCache[RatchetMapKey(jid, id)]! == BTBVTrustState.verified;
    });
  }
  
  @override
  Future<bool> isTrusted(String jid, int deviceId) async {
    var returnValue = false;
    await _lock.synchronized(() async {
      final trustCacheValue = _trustCache[RatchetMapKey(jid, deviceId)];
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
        _trustCache[RatchetMapKey(jid, deviceId)] = BTBVTrustState.notTrusted;
      } else {
        _trustCache[RatchetMapKey(jid, deviceId)] = BTBVTrustState.blindTrust;
      }

      if (_devices.containsKey(jid)) {
        _devices[jid]!.add(deviceId);
      } else {
        _devices[jid] = List<int>.from([deviceId]);
      }
    });
  }
  
  /// Returns a mapping from the device identifiers of [jid] to their trust state.
  Future<Map<int, BTBVTrustState>> getDevicesTrust(String jid) async {
    final map = <int, BTBVTrustState>{};

    await _lock.synchronized(() async {
      for (final deviceId in _devices[jid]!) {
        map[deviceId] = _trustCache[RatchetMapKey(jid, deviceId)]!;
      }
    });

    return map;
  }

  /// Sets the trust of [jid]'s device with identifier [deviceId] to [state].
  Future<void> setDeviceTrust(String jid, int deviceId, BTBVTrustState state) async {
    await _lock.synchronized(() async {
      _trustCache[RatchetMapKey(jid, deviceId)] = state;
    });
  }

  @visibleForTesting
  BTBVTrustState getDeviceTrust(String jid, int deviceId) => _trustCache[RatchetMapKey(jid, deviceId)]!;
}
