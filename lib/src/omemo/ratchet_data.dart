import 'package:omemo_dart/src/double_ratchet/double_ratchet.dart';

class OmemoRatchetData {
  const OmemoRatchetData(
    this.jid,
    this.id,
    this.ratchet,
    this.added,
    this.replaced,
  );

  /// The JID we have the ratchet with.
  final String jid;

  /// The device id we have the ratchet with.
  final int id;

  /// The actual double ratchet to commit.
  final OmemoDoubleRatchet ratchet;

  /// Indicates whether the ratchet has just been created (true) or just modified (false).
  final bool added;

  /// Indicates whether the ratchet has been replaced (true) or not.
  final bool replaced;
}
