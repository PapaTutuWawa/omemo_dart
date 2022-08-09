import 'dart:convert';
import 'package:omemo_dart/omemo_dart.dart';

/// This example aims to demonstrate how omemo_dart is used. Since omemo_dart is not
/// dependent on any XMPP library, you need to convert stanzas to the appropriate
/// intermediary format and back.
void main() async {
  const aliceJid = 'alice@some.server';
  const bobJid = 'bob@other.serve';

  // You are Alice and want to begin using OMEMO, so you first create a SessionManager
  final aliceSession = await OmemoSessionManager.generateNewIdentity(
    // The bare Jid of Alice as a String
    aliceJid,
    // The trust manager we want to use. In this case, we use the provided one that
    // implements "Blind Trust Before Verification". To make things simpler, we keep
    // no persistent data and can thus use the MemoryBTBVTrustManager. If we wanted to keep
    // the state, we would have to override BlindTrustBeforeVerificationTrustManager.
    MemoryBTBVTrustManager(),
    // Here we specify how many Onetime Prekeys we want to have. XEP-0384 recommends around
    // 100 OPKs, so let's generate 100. The parameter defaults to 100.
    //opkAmount: 100,
  );

  // Alice now wants to chat with Bob at his bare Jid "bob@other.server". To make things
  // simple, we just generate the identity bundle ourselves. In the real world, we would
  // request it using PEP and then convert the device bundle into a OmemoBundle object.
  final bobSession = await OmemoSessionManager.generateNewIdentity(
    bobJid,
    MemoryBTBVTrustManager(),
    // Just for illustrative purposes
    opkAmount: 1,
  );

  // Alice prepares to send the message to Bob, so she builds the message stanza and
  // collects all the children of the stanza that should be encrypted into a string.
  const aliceMessageStanzaBody = '''
  <body>Hello Bob, it's me, Alice!</body>
  <super-secret-element xmlns='super-secret-element' />
  ''';

  // Since OMEMO 0.8.3 mandates usage of XEP-0420: Stanza Content Encryption, we have to
  // wrap our acual payload - aliceMessageStanzaBody - into an SCE envelope. Note that
  // the rpad element must contain a random string. See XEP-0420 for recommendations.
  // OMEMO makes the <time /> element optional, but let's use for this example.
  const envelope = '''
<envelope xmlns='urn:xmpp:sce:1'>
  <content>
    $aliceMessageStanzaBody
  </content>
  <rpad>s0m3-r4nd0m-b9t3s</rpad>
  <from jid='$aliceJid' />
  <time stamp='1969-07-20T21:56:15-05:00' />
</envelope>
''';
 
  // Since Alice has no open session with Bob, we need to tell the session manager to build
  // it when sending the message.
  final message = await aliceSession.encryptToJid(
    // The bare receiver Jid
    bobJid,
    // The envelope we want to encrypt
    envelope,
    // Since this is the first time Alice contacts Bob from this device, we need to create
    // a new session. Let's also assume that Bob only has one device. We may, however,
    // add more bundles to newSessions, if we know of more.
    newSessions: [
      await (await bobSession.getDevice()).toBundle(),
    ],
  );

  // Alice now builds the actual message stanza for Bob
  final payload = base64.encode(message.ciphertext!);
  final aliceDevice = await aliceSession.getDevice();
  // ignore: unused_local_variable
  final bobDevice = await bobSession.getDevice();
  // Since we know we have just one key for Bob, we take a shortcut. However, in the real
  // world, we have to serialise every EncryptedKey to a <key /> element and group them
  // per Jid.
  final key = message.encryptedKeys[0];

  // Note that the key's "kex" attribute refers to key.kex. It just means that the
  // encrypted key also contains the required data for Bob to build a session with Alice.
  // ignore: unused_local_variable
  final aliceStanza = '''
<message from='$aliceJid/device1' to='$bobJid/device2'>
  <encrypted xmlns='urn:xmpp:omemo:2'>
    <header sid='${aliceDevice.id}'>
      <keys jid='$bobJid'>
        <key rid='${key.rid} kex='true'>
          ${key.value}
        </key>
      </keys>
    </header>
    <payload>
      $payload
    </payload>
  </encrypted>
</message>
''';

  // Alice can now send this message to Bob using our preferred XMPP library.
  // ...

  // Bob now receives an OMEMO encrypted message from Alice and wants to decrypt it.
  // Since we have just one key, let's just deserialise the one key by hand.
  final keys = [
    EncryptedKey(bobJid, key.rid, key.value, true),
  ];

  // Bob extracts the payload and attempts to decrypt it.
  // ignore: unused_local_variable
  final bobMessage = await bobSession.decryptMessage(
    // base64 decode the payload
    base64.decode(payload),
    // Specify the Jid of the sender
    aliceJid,
    // Specify the device identifier of the sender (the "sid" attribute of <header />)
    aliceDevice.id,
    // The deserialised keys
    keys,
  );

  // All Bob has to do now is replace the OMEMO wrapper element 
  // <encrypted xmlns='urn:xmpp:omemo:2' />) with the content of the <content /> element
  // of the envelope we just decrypted.

  // Bob now has a session with Alice and can send encrypted message to her.
  // Since they both used the BlindTrustBeforeVerificationTrustManager, they currently
  // use blind trust, meaning that both Alice and Bob accept new devices without any
  // hesitation. If Alice, however, decides to verify one of Bob's devices and sets
  // it as verified using
  // ```
  // await aliceSession.trustManager.setDeviceTrust(bobJid, bobDevice.id, BTBVTrustState.verified)
  // ```
  // then Alice's OmemoSessionManager won't encrypt to new devices unless they are also
  // verified. To prevent user confusion, you should check if every device is trusted
  // before sending the message and ask the user for a trust decision.
  // If you want to make the BlindTrustBeforeVerificationTrustManager persistent, then
  // you need to subclass it and override the `Future<void> commitState()` and
  // `Future<void> loadState()` functions. commitState is called everytime the internal
  // state gets changed. loadState never gets automatically called but is more of a
  // function for the user to restore the trust manager. In those functions you have
  // access to `ratchetMap`, which maps a `RatchetMapKey` - essentially a tuple consisting
  // of a bare Jid and the device identifier - to the trust state, and `devices` which
  // maps a bare Jid to its device identifiers.
  // To make the entire OmemoSessionManager persistent, you have two options:
  // - use the provided `toJson()` and `fromJson()` functions. They, however, serialise
  //   and deserialise *ALL* known sessions, so it might be slow.
  // - subscribe to the session manager's `eventStream`. There, events get triggered
  //   everytime a ratchet changes, our own device changes or the internal ratchet map
  //   gets changed. This give finer control over the the serialisation. The session
  //   manager can then be restored using its constructor. For a list of events, see
  //   lib/src/omemo/events.dart.
}
