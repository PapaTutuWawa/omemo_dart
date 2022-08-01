import 'package:cryptography/cryptography.dart';
import 'package:cryptography/dart.dart';
import 'package:test/test.dart';
import 'package:omemo_dart/src/x3dh/x3dh.dart';

Future<List<int>> publicKeyBytes(SimpleKeyPair kp) async {
  final pk = await kp.extractPublicKey();
  return pk.bytes;
}

Future<SimplePublicKey> publicKey(SimpleKeyPair kp) async {
  //return await DartEd25519.publicKeyToCurve25519(kp);
  return kp.extractPublicKey();
}

Future<SimpleKeyPair> toCurve(SimpleKeyPair kp) async {
  //final pk = await DartEd25519.publicKeyToCurve25519(kp);
  //final sk = await DartEd25519.privateKeyToCurve25519(kp);
  //return SimpleKeyPairData(sk, publicKey: pk, type: KeyPairType.x25519);
  return kp;
}

void main() {
  test("X3DH", () async {
    final ed = Ed25519();
    final x = Cryptography.instance.x25519();

    // Generate IKs for Alice and Bob
    final ikAlice = await x.newKeyPair();
    final ikBob = await x.newKeyPair();
    
    // Generate SPKs for Alice and Bob
    final spkAlice = await x.newKeyPair();
    final spkSigAlice = await sig(ikAlice, await publicKeyBytes(spkAlice));
    final spkBob = await x.newKeyPair();
    final spkSigBob = await sig(ikBob, await publicKeyBytes(spkBob));

    // Generate an OPK for Alice and Bob
    final opkAlice = await x.newKeyPair();
    final opkBob = await x.newKeyPair();

    
    // Perform X3DH
    final aliceMessage = await x3dhFromPrekeyBundle(
      await ikBob.extractPublicKey(),
      await spkBob.extractPublicKey(),
      await opkBob.extractPublicKey(),
      ikAlice,
    );

    final bobDh = await x3dhFromInitialMessage(
      await ikAlice.extractPublicKey(),
      await aliceMessage.epk.extractPublicKey(),
      opkBob,
      spkBob,
      ikBob,
    );

    expect(aliceMessage.sharedSecret, bobDh);
  });
}
