import 'package:meta/meta.dart';
import 'package:omemo_dart/src/omemo/ratchet_map_key.dart';
import 'package:omemo_dart/src/trust/base.dart';
import 'package:synchronized/synchronized.dart';

/// Every device is in either of those two trust states:
/// - notTrusted: The device is absolutely not trusted
/// - blindTrust: The fingerprint is not verified using OOB means
/// - verified: The fingerprint has been verified using OOB means
enum BTBVTrustState {
  notTrusted, // = 1
  blindTrust, // = 2
  verified,   // = 3
}

int _trustToInt(BTBVTrustState state) {
  switch (state) {
    case BTBVTrustState.notTrusted: return 1;
    case BTBVTrustState.blindTrust: return 2;
    case BTBVTrustState.verified:   return 3;
  }
}

BTBVTrustState _trustFromInt(int i) {
  switch (i) {
    case 1: return BTBVTrustState.notTrusted;
    case 2: return BTBVTrustState.blindTrust;
    case 3: return BTBVTrustState.verified;
    default: return BTBVTrustState.notTrusted;
  }
}

/// A TrustManager that implements the idea of Blind Trust Before Verification.
/// See https://gultsch.de/trust.html for more details.
abstract class BlindTrustBeforeVerificationTrustManager extends TrustManager {
  BlindTrustBeforeVerificationTrustManager()
    : trustCache = {},
      enablementCache = {},
      devices = {},
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
    await _lock.synchronized(() async {
      enablementCache[RatchetMapKey(jid, deviceId)] = enabled;
    });

    // Commit the state
    await commitState();
  }

  @override
  Future<Map<String, dynamic>> toJson() async {
    return {
      'devices': devices,
      'trust': trustCache.map((key, value) => MapEntry(
        key.toJsonKey(), _trustToInt(value),
      ),),
      'enable': enablementCache.map((key, value) => MapEntry(key.toJsonKey(), value)),
    };
  }

  /// From a serialized version of a BTBV trust manager, extract the device list.
  /// NOTE: This is needed as Dart cannot just cast a List<dynamic> to List<int> and so on.
  static Map<String, List<int>> deviceListFromJson(Map<String, dynamic> json) {
    return (json['devices']! as Map<String, dynamic>).map<String, List<int>>(
      (key, value) => MapEntry(
        key,
        (value as List<dynamic>).map<int>((i) => i as int).toList(),
      ),
    );
  }

  /// From a serialized version of a BTBV trust manager, extract the trust cache.
  /// NOTE: This is needed as Dart cannot just cast a List<dynamic> to List<int> and so on.
  static Map<RatchetMapKey, BTBVTrustState> trustCacheFromJson(Map<String, dynamic> json) {
    return (json['trust']! as Map<String, dynamic>).map<RatchetMapKey, BTBVTrustState>(
      (key, value) => MapEntry(
        RatchetMapKey.fromJsonKey(key),
        _trustFromInt(value as int),
      ),
    );
  }

  /// From a serialized version of a BTBV trust manager, extract the enable cache.
  /// NOTE: This is needed as Dart cannot just cast a List<dynamic> to List<int> and so on.
  static Map<RatchetMapKey, bool> enableCacheFromJson(Map<String, dynamic> json) {
    return (json['enable']! as Map<String, dynamic>).map<RatchetMapKey, bool>(
      (key, value) => MapEntry(
        RatchetMapKey.fromJsonKey(key),
        value as bool,
      ),
    );
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
