import 'package:omemo_dart/src/helpers.dart';
import 'package:omemo_dart/src/protobuf/protobuf.dart';

class OmemoAuthenticatedMessage {

  const OmemoAuthenticatedMessage(this.mac, this.message);

  factory OmemoAuthenticatedMessage.fromBuffer(List<int> data) {
    var i = 0;
    
    // required bytes mac     = 1;
    if (data[0] != fieldId(1, fieldTypeByteArray)) {
      throw Exception();
    }
    final mac = data.sublist(2, i + 2 + data[1]);
    i += data[1] + 2;

    if (data[i] != fieldId(2, fieldTypeByteArray)) {
      throw Exception();
    }
    final message = data.sublist(i + 2, i + 2 + data[i + 1]);

    return OmemoAuthenticatedMessage(mac, message);
  }
  
  final List<int> mac;
  final List<int> message;

  List<int> writeToBuffer() {
    return concat([
      [fieldId(1, fieldTypeByteArray), mac.length],
      mac,
      [fieldId(2, fieldTypeByteArray), message.length],
      message,
    ]);
  }
}
