import 'package:meta/meta.dart';

@immutable
class DeviceFingerprint {

  const DeviceFingerprint(this.deviceId, this.fingerprint);
  final String fingerprint;
  final int deviceId;

  @override
  bool operator ==(Object other) {
    return other is DeviceFingerprint &&
      fingerprint == other.fingerprint &&
      deviceId == other.deviceId;
  }

  @override
  int get hashCode => fingerprint.hashCode ^ deviceId.hashCode;
}
