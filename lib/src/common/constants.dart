/// The overarching assumption is that we use Ed25519 keys for the identity keys
const omemoX3DHInfoString = 'OMEMO X3DH';

/// The info used for when encrypting the AES key for the actual payload.
const omemoPayloadInfoString = 'OMEMO Payload';

/// Info string for ENCRYPT
const encryptHkdfInfoString = 'OMEMO Message Key Material';

/// Amount of messages we may skip per session
const maxSkip = 1000;
