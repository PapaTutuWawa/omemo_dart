import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';
import 'package:omemo_dart/omemo_dart.dart';

void main() {
  test("X3DH", () async {
    // Generate keys
    final ikAlice = await OmemoKeyPair.generateNewPair(KeyPairType.ed25519);
    final ikBob = await OmemoKeyPair.generateNewPair(KeyPairType.ed25519);
    final spkBob = await OmemoKeyPair.generateNewPair(KeyPairType.x25519);
    final opkBob = await OmemoKeyPair.generateNewPair(KeyPairType.x25519);
    final bundleBob = OmemoBundle(
      '1',
      await spkBob.pk.asBase64(),
      '3',
      // TODO(PapaTutuWawa):
      'n/a',
      await ikBob.pk.asBase64(),
      {
        '2': await opkBob.pk.asBase64(),
      },
    );

    // Alice does X3DH
    final resultAlice = await x3dhFromBundle(bundleBob, ikAlice);

    // Alice sends the inital message to Bob
    // ...
    
    // Bob does X3DH
    final skBob = await x3dhFromInitialMessage(
      X3DHMessage(
        ikAlice.pk,
        resultAlice.ek.pk,
        '2',
      ),
      spkBob,
      opkBob,
      ikBob,
    );
    
    expect(resultAlice.sk, skBob);
  });
}
