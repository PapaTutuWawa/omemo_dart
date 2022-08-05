import 'package:omemo_dart/src/omemo/device.dart';

abstract class OmemoEvent {}

/// Triggered by the OmemoSessionManager when our own device bundle was modified
/// and thus should be republished.
class DeviceBundleModifiedEvent extends OmemoEvent {

  DeviceBundleModifiedEvent(this.device);
  final Device device;
}
