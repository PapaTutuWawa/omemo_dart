import 'package:omemo_dart/src/omemo/encrypted_key.dart';

/// Describes a stanza that was received by the underlying XMPP library.
class OmemoIncomingStanza {
  const OmemoIncomingStanza(
    this.bareSenderJid,
    this.senderDeviceId,
    this.timestamp,
    this.keys,
    this.payload,
  );

  /// The bare JID of the sender of the stanza.
  final String bareSenderJid;

  /// The device ID of the sender.
  final int senderDeviceId;

  /// The timestamp when the stanza was received.
  final int timestamp;

  /// The included encrypted keys
  final List<EncryptedKey> keys;

  /// The string payload included in the <encrypted /> element.
  final String? payload;
}

/// Describes a stanza that is to be sent out
class OmemoOutgoingStanza {
  const OmemoOutgoingStanza(
    this.recipientJids,
    this.payload,
  );

  /// The JIDs the stanza will be sent to.
  final List<String> recipientJids;

  /// The serialised XML data that should be encrypted.
  final String payload;
}
