import 'package:omemo_dart/src/omemo/encrypted_key.dart';

class OmemoIncomingStanza {
  const OmemoIncomingStanza(
    this.bareSenderJid,
    this.senderDeviceId,
    this.timestamp,
    this.keys,
    this.payload,
  );
  final String bareSenderJid;
  final int senderDeviceId;
  final int timestamp;
  final List<EncryptedKey> keys;
  final String payload;
}

class OmemoOutgoingStanza {
  const OmemoOutgoingStanza(
    this.recipientJids,
    this.payload,
  );
  final List<String> recipientJids;
  final String payload;
}
