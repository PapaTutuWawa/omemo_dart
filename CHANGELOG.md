## 0.1.0

- Initial version
- Implement the Double Ratchet, X3DH and OMEMO specific bits
- Add a Blind-Trust-Before-Verification TrustManager
- Supported OMEMO version: 0.8.3

## 0.1.3

- Fix bug with the Double Ratchet causing only the initial message to be decryptable
- Expose `getDeviceMap` as a developer usable function
## 0.2.0

- Add convenience functions `getDeviceId` and `getDeviceBundle`
- Creating a new ratchet with an id for which we already have a ratchet will now overwrite the old ratchet
- Ratchet now carry an "acknowledged" attribute

## 0.2.1

- Add `isRatchetAcknowledged`
- Ratchets that are created due to accepting a kex are now unacknowledged

## 0.3.0

- Implement enabling and disabling ratchets via the TrustManager interface
- Fix deserialization of the various objects
- Remove the BTBV TrustManager's loadState method. Just use the constructor
- Allow removing all ratchets for a given Jid
- If an error occurs while decrypting the message, the ratchet will now be reset to its prior state
- Fix a bug within the Varint encoding function. This should fix some occasional UnknownSignedPrekeyExceptions
- Remove OmemoSessionManager's toJson and fromJson. Use toJsonWithoutSessions and fromJsonWithoutSessions. Restoring sessions is not out-of-scope for that function

## 0.3.1

- Fix a bug that caused the device's id to change when replacing a OPK
- Every decryption failure now causes the ratchet to be restored to a pre-decryption state
- Add method to get the device's fingerprint

## 0.4.0

- Deprecate `OmemoSessionManager`. Use `OmemoManager` instead.
- Implement queued access to the ratchets inside the `OmemoManager`.
- Implement heartbeat messages.
- [BREAKING] Rename `Device` to `OmemoDevice`.

## 0.4.1

- Fix fetching the current device and building a ratchet session with it when encrypting for our own JID

## 0.4.2

- Fix removeAllRatchets not removing, well, all ratchets. In fact, it did not remove any ratchet.

## 0.4.3

- Fix bug that causes ratchets to be unable to decrypt anything after receiving a heartbeat with a completely new session

## 0.5.0

This version is a complete rework of omemo_dart!

- Removed events from `OmemoManager`
- Removed `OmemoSessionManager`
- Removed serialization/deserialization code
- Replace exceptions with errors inside a result type
- Ratchets and trust data is now loaded and cached on demand
- Accessing the trust manager must happen via `withTrustManager`
- Overriding the base implementations is replaced by providing callback functions