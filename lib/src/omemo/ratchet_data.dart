import 'package:omemo_dart/src/double_ratchet/double_ratchet.dart';

class OmemoRatchetData {
  const OmemoRatchetData(
    this.jid,
    this.id,
    this.ratchet,
  );

  /// The JID we have the ratchet with.
  final String jid;

  /// The device id we have the ratchet with.
  final int id;

  /// The actual double ratchet to commit.
  final OmemoDoubleRatchet ratchet;
}
