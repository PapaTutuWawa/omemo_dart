import 'package:omemo_dart/omemo_dart.dart';

abstract class OmemoEvent {}

/// Triggered when (possibly multiple) ratchets have been created at sending time.
class RatchetsAddedEvent extends OmemoEvent {
  RatchetsAddedEvent(this.ratchets);

  /// The mapping of the newly created ratchets.
  final Map<RatchetMapKey, OmemoDoubleRatchet> ratchets;
}

/// Triggered when a ratchet has been modified
class RatchetModifiedEvent extends OmemoEvent {
  RatchetModifiedEvent(
    this.jid,
    this.deviceId,
    this.ratchet,
    this.added,
    this.replaced,
  );
  final String jid;
  final int deviceId;
  final OmemoDoubleRatchet ratchet;

  /// Indicates whether the ratchet has just been created (true) or just modified (false).
  final bool added;

  /// Indicates whether the ratchet has been replaced (true) or not.
  final bool replaced;
}

/// Triggered when a ratchet has been removed and should be removed from storage.
class RatchetRemovedEvent extends OmemoEvent {
  RatchetRemovedEvent(this.jid, this.deviceId);
  final String jid;
  final int deviceId;
}

/// Triggered when the device map has been modified
class DeviceListModifiedEvent extends OmemoEvent {
  DeviceListModifiedEvent(this.jid, this.devices);

  /// The JID of the user.
  final String jid;

  /// The list of devices for [jid].
  final List<int> devices;
}

/// Triggered by the OmemoSessionManager when our own device bundle was modified
/// and thus should be republished.
class DeviceModifiedEvent extends OmemoEvent {
  DeviceModifiedEvent(this.device);
  final OmemoDevice device;
}
