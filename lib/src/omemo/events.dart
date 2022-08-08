import 'package:omemo_dart/src/double_ratchet/double_ratchet.dart';
import 'package:omemo_dart/src/omemo/device.dart';

abstract class OmemoEvent {}

/// Triggered when a ratchet has been modified
class RatchetModifiedEvent extends OmemoEvent {

  RatchetModifiedEvent(this.jid, this.deviceId, this.ratchet);
  final String jid;
  final int deviceId;
  final OmemoDoubleRatchet ratchet;
}

/// Triggered when the device map has been modified
class DeviceMapModifiedEvent extends OmemoEvent {

  DeviceMapModifiedEvent(this.map);
  final Map<String, List<int>> map;
}

/// Triggered by the OmemoSessionManager when our own device bundle was modified
/// and thus should be republished.
class DeviceModifiedEvent extends OmemoEvent {

  DeviceModifiedEvent(this.device);
  final Device device;
}
