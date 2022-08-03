import 'dart:convert';
import 'package:cryptography/cryptography.dart';
import 'package:omemo_dart/protobuf/schema.pb.dart';
import 'package:omemo_dart/src/errors.dart';
import 'package:omemo_dart/src/helpers.dart';

/// Info string for ENCRYPT
const encryptHkdfInfoString = 'OMEMO Message Key Material';

/// cryptography _really_ wants to check the MAC output from AES-256-CBC. Since
/// we don't have it, we need the MAC check to always "pass".
class NoMacSecretBox extends SecretBox {
  NoMacSecretBox(super.cipherText, { required super.nonce }) : super(mac: Mac.empty);

  @override
  Future<void> checkMac({
    required MacAlgorithm macAlgorithm,
    required SecretKey secretKey,
    required List<int> aad,
  }) async {}
}

/// Signals ENCRYPT function as specified by OMEMO 0.8.3.
/// Encrypt [plaintext] using the message key [mk], given associated_data [associatedData]
/// and the AD output from the X3DH [sessionAd].
Future<List<int>> encrypt(List<int> mk, List<int> plaintext, List<int> associatedData, List<int> sessionAd) async {
  final hkdf = Hkdf(
    hmac: Hmac(Sha256()),
    outputLength: 80,
  );
  final hkdfResult = await hkdf.deriveKey(
    secretKey: SecretKey(mk),
    nonce: List<int>.filled(32, 0x0),
    info: utf8.encode(encryptHkdfInfoString),
  );
  final hkdfBytes = await hkdfResult.extractBytes();

  // Split hkdfBytes into encryption, authentication key and IV
  final encryptionKey = hkdfBytes.sublist(0, 32);
  final authenticationKey = hkdfBytes.sublist(32, 64);
  final iv = hkdfBytes.sublist(64, 80);

  final aesResult = await AesCbc.with256bits(
    macAlgorithm: MacAlgorithm.empty,
  ).encrypt(
    plaintext,
    secretKey: SecretKey(encryptionKey),
    nonce: iv,
  );
  
  final header = OMEMOMessage.fromBuffer(associatedData.sublist(sessionAd.length))
    ..ciphertext = aesResult.cipherText;
  final headerBytes = header.writeToBuffer();
  final hmacInput = concat([sessionAd, headerBytes]);
  final hmacResult = (await Hmac.sha256().calculateMac(
    hmacInput,
    secretKey: SecretKey(authenticationKey),
  )).bytes.sublist(0, 16);
  
  final message = OMEMOAuthenticatedMessage()
    ..mac = hmacResult
    ..message = headerBytes;
  return message.writeToBuffer();
}

/// Signals DECRYPT function as specified by OMEMO 0.8.3.
/// Decrypt [ciphertext] with the message key [mk], given the associated_data [associatedData]
/// and the AD output from the X3DH.
Future<List<int>> decrypt(List<int> mk, List<int> ciphertext, List<int> associatedData, List<int> sessionAd) async {
  // Generate the keys and iv from mk
  final hkdf = Hkdf(
    hmac: Hmac(Sha256()),
    outputLength: 80,
  );
  final hkdfResult = await hkdf.deriveKey(
    secretKey: SecretKey(mk),
    nonce: List<int>.filled(32, 0x0),
    info: utf8.encode(encryptHkdfInfoString),
  );
  final hkdfBytes = await hkdfResult.extractBytes();

  // Split hkdfBytes into encryption, authentication key and IV
  final encryptionKey = hkdfBytes.sublist(0, 32);
  final authenticationKey = hkdfBytes.sublist(32, 64);
  final iv = hkdfBytes.sublist(64, 80);
  
  // Assumption ciphertext is a OMEMOAuthenticatedMessage
  final message = OMEMOAuthenticatedMessage.fromBuffer(ciphertext);
  final header = OMEMOMessage.fromBuffer(message.message);

  final hmacInput = concat([sessionAd, header.writeToBuffer()]);
  final hmacResult = (await Hmac.sha256().calculateMac(
    hmacInput,
    secretKey: SecretKey(authenticationKey),
  )).bytes.sublist(0, 16);

  if (!listsEqual(hmacResult, message.mac)) {
    throw InvalidMessageHMACException();
  }
  
  final plaintext = await AesCbc.with256bits(
    macAlgorithm: MacAlgorithm.empty,
  ).decrypt(
    NoMacSecretBox(
      header.ciphertext,
      nonce: iv,
    ),
    secretKey: SecretKey(encryptionKey),
  );

  return plaintext;
}
