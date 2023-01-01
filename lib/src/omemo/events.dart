import 'package:omemo_dart/src/double_ratchet/double_ratchet.dart';
import 'package:omemo_dart/src/omemo/device.dart';

abstract class OmemoEvent {}

/// Triggered when a ratchet has been modified
class RatchetModifiedEvent extends OmemoEvent {
  RatchetModifiedEvent(this.jid, this.deviceId, this.ratchet, this.added);
  final String jid;
  final int deviceId;
  final OmemoDoubleRatchet ratchet;

  /// Indicates whether the ratchet has just been created (true) or just modified (false).
  final bool added;
}

/// Triggered when a ratchet has been removed and should be removed from storage.
class RatchetRemovedEvent extends OmemoEvent {
  RatchetRemovedEvent(this.jid, this.deviceId);
  final String jid;
  final int deviceId;
}

/// Triggered when the device map has been modified
class DeviceListModifiedEvent extends OmemoEvent {
  DeviceListModifiedEvent(this.list);
  final Map<String, List<int>> list;
}

/// Triggered by the OmemoSessionManager when our own device bundle was modified
/// and thus should be republished.
class DeviceModifiedEvent extends OmemoEvent {
  DeviceModifiedEvent(this.device);
  final OmemoDevice device;
}
