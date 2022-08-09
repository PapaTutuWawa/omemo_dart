import 'package:meta/meta.dart';

@immutable
class RatchetMapKey {

  const RatchetMapKey(this.jid, this.deviceId);
  final String jid;
  final int deviceId;

  @override
  bool operator ==(Object other) {
    return other is RatchetMapKey && jid == other.jid && deviceId == other.deviceId;
  }

  @override
  int get hashCode => jid.hashCode ^ deviceId.hashCode;
}
