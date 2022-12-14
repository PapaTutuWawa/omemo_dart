import 'package:omemo_dart/src/helpers.dart';
import 'package:omemo_dart/src/protobuf/protobuf.dart';

class OmemoMessage {

  OmemoMessage();

  factory OmemoMessage.fromBuffer(List<int> data) {
    var i = 0;
    
    // required uint32 n          = 1;
    if (data[0] != fieldId(1, fieldTypeUint32)) {
      throw Exception();
    }
    var decode = decodeVarint(data, 1);
    final n = decode.n;
    i += decode.length + 1;

    // required uint32 pn         = 2;
    if (data[i] != fieldId(2, fieldTypeUint32)) {
      throw Exception();
    }
    decode = decodeVarint(data, i + 1);
    final pn = decode.n;
    i += decode.length + 1;

    // required bytes  dh_pub     = 3;
    if (data[i] != fieldId(3, fieldTypeByteArray)) {
      throw Exception();
    }
    final dhPub = data.sublist(i + 2, i + 2 + data[i + 1]);
    i += 2 + data[i + 1];

    // optional bytes  ciphertext = 4;
    List<int>? ciphertext;
    if (i < data.length) {
      if (data[i] != fieldId(4, fieldTypeByteArray)) {
        throw Exception();
      }

      ciphertext = data.sublist(i + 2, i + 2 + data[i + 1]);
    }

    return OmemoMessage()
      ..n = n
      ..pn = pn
      ..dhPub = dhPub
      ..ciphertext = ciphertext;
  }

  int? n;
  int? pn;
  List<int>? dhPub;
  List<int>? ciphertext;

  List<int> writeToBuffer() {
    final data = concat([
      [fieldId(1, fieldTypeUint32)],
      encodeVarint(n!),
      [fieldId(2, fieldTypeUint32)],
      encodeVarint(pn!),
      [fieldId(3, fieldTypeByteArray), dhPub!.length],
      dhPub!,
    ]);

    if (ciphertext != null) {
      return concat([
        data,
        [fieldId(4, fieldTypeByteArray), ciphertext!.length],
        ciphertext!,
      ]);
    }

    return data;
  }
}
