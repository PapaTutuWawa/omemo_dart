import 'package:omemo_dart/omemo_dart.dart';
import 'package:test/test.dart';

void main() {
  test('Test serialising and deserialising Device', () async {
    // Generate a random session
    final oldSession = await OmemoSessionManager.generateNewIdentity(opkAmount: 1);
    final oldDevice = await oldSession.getDevice();
    final serialised = await oldDevice.toJson();

    final newDevice = Device.fromJson(serialised);
    expect(oldDevice.id, newDevice.id);
    expect(await oldDevice.ik.equals(newDevice.ik), true);
    expect(await oldDevice.spk.equals(newDevice.spk), true);
    expect(listsEqual(oldDevice.spkSignature, newDevice.spkSignature), true);
    expect(oldDevice.spkId, newDevice.spkId);

    // Check the Ontime-Prekeys
    expect(oldDevice.opks.length, newDevice.opks.length);
    for (final entry in oldDevice.opks.entries) {
      expect(await newDevice.opks[entry.key]!.equals(entry.value), true);
    }
  });
}
