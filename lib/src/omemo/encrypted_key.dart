import 'package:meta/meta.dart';

/// EncryptedKey is the intermediary format of a <key /> element in the OMEMO message's
/// <keys /> header.
@immutable
class EncryptedKey {

  const EncryptedKey(this.jid, this.rid, this.value, this.kex);
  final String jid;
  final int rid;
  final String value;
  final bool kex;
}
