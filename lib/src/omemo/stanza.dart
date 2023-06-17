import 'package:omemo_dart/src/omemo/encrypted_key.dart';

/// Describes a stanza that was received by the underlying XMPP library.
class OmemoIncomingStanza {
  const OmemoIncomingStanza(
    this.bareSenderJid,
    this.senderDeviceId,
    this.keys,
    this.payload,
    this.isCatchup,
  );

  /// The bare JID of the sender of the stanza.
  final String bareSenderJid;

  /// The device ID of the sender.
  final int senderDeviceId;

  /// The included encrypted keys for our own JID
  final List<EncryptedKey> keys;

  /// The string payload included in the <encrypted /> element.
  final String? payload;

  /// Flag indicating whether the message was received due to a catchup.
  final bool isCatchup;
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
  final String? payload;
}
