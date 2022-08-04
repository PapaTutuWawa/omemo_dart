import 'package:omemo_dart/protobuf/schema.pb.dart';
import 'package:omemo_dart/src/protobuf/omemo_message.dart';
import 'package:omemo_dart/src/protobuf/protobuf.dart';
import 'package:test/test.dart';

void main() {
  group('Base 128 Varints', () {
    test('Test simple parsing of Varints', () {
      expect(
        decodeVarint(<int>[1], 0).n,
        1,
      );
      expect(
        decodeVarint(<int>[1], 0).length,
        1,
      );
      expect(
        decodeVarint(<int>[0x96, 0x01, 0x00], 0).n,
        150,
      );
      expect(
        decodeVarint(<int>[0x96, 0x01, 0x00], 0).length,
        2,
      );
      expect(
        decodeVarint(<int>[172, 2, 0x8], 0).n,
        300,
      );
      expect(
        decodeVarint(<int>[172, 2, 0x8], 0).length,
        2,
      );
    });

    test('Test encoding Varints', () {
      expect(
        encodeVarint(1),
        <int>[1],
      );
      expect(
        encodeVarint(150),
        <int>[0x96, 0x01],
      );
      expect(
        encodeVarint(300),
        <int>[172, 2],
      );
    });
  });

  group('OMEMOMessage', () {
    test('Decode a OMEMOMessage', () {
      final pbMessage = OMEMOMessage()
        ..n = 1
        ..pn = 5
        ..dhPub = <int>[1, 2, 3]
        ..ciphertext = <int>[4, 5, 6];
      final serial = pbMessage.writeToBuffer();
      final msg = OmemoMessage.fromBuffer(serial);

      expect(msg.n, 1);
      expect(msg.pn, 5);
      expect(msg.dhPub, <int>[1, 2, 3]);
      expect(msg.ciphertext, <int>[4, 5, 6]);
    });
    test('Decode a OMEMOMessage without ciphertext', () {
      final pbMessage = OMEMOMessage()
        ..n = 1
        ..pn = 5
        ..dhPub = <int>[1, 2, 3];
      final serial = pbMessage.writeToBuffer();
      final msg = OmemoMessage.fromBuffer(serial);
      
      expect(msg.n, 1);
      expect(msg.pn, 5);
      expect(msg.dhPub, <int>[1, 2, 3]);
      expect(msg.ciphertext, null);
    });
    test('Encode a OMEMOMessage', () {
      const m = OmemoMessage(
        1,
        5,
        <int>[1, 2, 3],
        <int>[4, 5, 6],
      );
      final serial = m.writeToBuffer();
      final msg = OMEMOMessage.fromBuffer(serial);
      
      expect(msg.n, 1);
      expect(msg.pn, 5);
      expect(msg.dhPub, <int>[1, 2, 3]);
      expect(msg.ciphertext, <int>[4, 5, 6]);
    });
    test('Encode a OMEMOMessage without ciphertext', () {
      const m = OmemoMessage(
        1,
        5,
        <int>[1, 2, 3],
        null,
      );
      final serial = m.writeToBuffer();
      final msg = OMEMOMessage.fromBuffer(serial);

      expect(msg.n, 1);
      expect(msg.pn, 5);
      expect(msg.dhPub, <int>[1, 2, 3]);
      expect(msg.ciphertext, <int>[]);
    });
  });
}
