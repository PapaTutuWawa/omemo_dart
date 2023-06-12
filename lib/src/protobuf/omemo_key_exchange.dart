import 'package:omemo_dart/src/helpers.dart';
import 'package:omemo_dart/src/protobuf/omemo_authenticated_message.dart';
import 'package:omemo_dart/src/protobuf/protobuf.dart';

class OmemoKeyExchange {
  OmemoKeyExchange();

  factory OmemoKeyExchange.fromBuffer(List<int> data) {
    var i = 0;

    if (data[i] != fieldId(1, fieldTypeUint32)) {
      throw Exception();
    }
    var decoded = decodeVarint(data, 1);
    final pkId = decoded.n;
    i += decoded.length + 1;

    if (data[i] != fieldId(2, fieldTypeUint32)) {
      throw Exception();
    }
    decoded = decodeVarint(data, i + 1);
    final spkId = decoded.n;
    i += decoded.length + 1;

    if (data[i] != fieldId(3, fieldTypeByteArray)) {
      throw Exception();
    }
    final ik = data.sublist(i + 2, i + 2 + data[i + 1]);
    i += 2 + data[i + 1];

    if (data[i] != fieldId(4, fieldTypeByteArray)) {
      throw Exception();
    }
    final ek = data.sublist(i + 2, i + 2 + data[i + 1]);
    i += 2 + data[i + 1];

    if (data[i] != fieldId(5, fieldTypeByteArray)) {
      throw Exception();
    }
    final message = OmemoAuthenticatedMessage.fromBuffer(data.sublist(i + 2));

    return OmemoKeyExchange()
      ..pkId = pkId
      ..spkId = spkId
      ..ik = ik
      ..ek = ek
      ..message = message;
  }

  int? pkId;
  int? spkId;
  List<int>? ik;
  List<int>? ek;
  OmemoAuthenticatedMessage? message;

  List<int> writeToBuffer() {
    final msg = message!.writeToBuffer();
    return concat([
      [fieldId(1, fieldTypeUint32)],
      encodeVarint(pkId!),
      [fieldId(2, fieldTypeUint32)],
      encodeVarint(spkId!),
      [fieldId(3, fieldTypeByteArray), ik!.length],
      ik!,
      [fieldId(4, fieldTypeByteArray), ek!.length],
      ek!,
      [fieldId(5, fieldTypeByteArray), msg.length],
      msg,
    ]);
  }
}
