import 'package:omemo_dart/src/crypto.dart';
import 'package:omemo_dart/src/errors.dart';
import 'package:omemo_dart/src/helpers.dart';
import 'package:omemo_dart/src/protobuf/omemo_authenticated_message.dart';
import 'package:omemo_dart/src/protobuf/omemo_message.dart';

/// Info string for ENCRYPT
const encryptHkdfInfoString = 'OMEMO Message Key Material';

/// Signals ENCRYPT function as specified by OMEMO 0.8.3.
/// Encrypt [plaintext] using the message key [mk], given associated_data [associatedData]
/// and the AD output from the X3DH [sessionAd].
Future<List<int>> encrypt(
  List<int> mk,
  List<int> plaintext,
  List<int> associatedData,
  List<int> sessionAd,
) async {
  // Generate encryption, authentication key and IV
  final keys = await deriveEncryptionKeys(mk, encryptHkdfInfoString);
  final ciphertext =
      await aes256CbcEncrypt(plaintext, keys.encryptionKey, keys.iv);

  final header =
      OmemoMessage.fromBuffer(associatedData.sublist(sessionAd.length))
        ..ciphertext = ciphertext;
  final headerBytes = header.writeToBuffer();
  final hmacInput = concat([sessionAd, headerBytes]);
  final hmacResult = await truncatedHmac(hmacInput, keys.authenticationKey);
  final message = OmemoAuthenticatedMessage()
    ..mac = hmacResult
    ..message = headerBytes;
  return message.writeToBuffer();
}

/// Signals DECRYPT function as specified by OMEMO 0.8.3.
/// Decrypt [ciphertext] with the message key [mk], given the associated_data [associatedData]
/// and the AD output from the X3DH.
Future<List<int>> decrypt(
  List<int> mk,
  List<int> ciphertext,
  List<int> associatedData,
  List<int> sessionAd,
) async {
  // Generate encryption, authentication key and IV
  final keys = await deriveEncryptionKeys(mk, encryptHkdfInfoString);

  // Assumption ciphertext is a OMEMOAuthenticatedMessage
  final message = OmemoAuthenticatedMessage.fromBuffer(ciphertext);
  final header = OmemoMessage.fromBuffer(message.message!);

  final hmacInput = concat([sessionAd, header.writeToBuffer()]);
  final hmacResult = await truncatedHmac(hmacInput, keys.authenticationKey);

  if (!listsEqual(hmacResult, message.mac!)) {
    throw InvalidMessageHMACException();
  }

  return aes256CbcDecrypt(header.ciphertext!, keys.encryptionKey, keys.iv);
}
