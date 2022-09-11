import 'package:meta/meta.dart';

@immutable
class RatchetMapKey {

  const RatchetMapKey(this.jid, this.deviceId);

  factory RatchetMapKey.fromJsonKey(String key) {
    final parts = key.split(':');
    final deviceId = int.parse(parts.first);

    return RatchetMapKey(
      parts.sublist(1).join(':'),
      deviceId,
    );
  }

  final String jid;
  final int deviceId;

  String toJsonKey() {
    return '$deviceId:$jid';
  }
  
  @override
  bool operator ==(Object other) {
    return other is RatchetMapKey && jid == other.jid && deviceId == other.deviceId;
  }

  @override
  int get hashCode => jid.hashCode ^ deviceId.hashCode;
}
