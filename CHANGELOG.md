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
