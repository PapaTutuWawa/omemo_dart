import 'package:meta/meta.dart';
import 'package:omemo_dart/src/trust/base.dart';

/// Only use for testing!
/// An implementation of TrustManager that never trusts any device and thus
/// has no internal state.
@visibleForTesting
class NeverTrustingTrustManager extends TrustManager {
  @override
  Future<bool> isTrusted(String jid, int deviceId) async => false;

  @override
  Future<void> onNewSession(String jid, int deviceId) async {}
}
