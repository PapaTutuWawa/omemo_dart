# omemo_dart

`omemo_dart` is a Dart library to help developers of Dart/Flutter XMPP clients to implement
[OMEMO](https://xmpp.org/extensions/xep-0384.html) in its newest version - currently 0.8.3.

The library provides an implementation of the [X3DH](https://signal.org/docs/specifications/x3dh/)
key exchange, the [Double Ratchet](https://signal.org/docs/specifications/doubleratchet/) with
the OMEMO 0.8.3 specific `ENCRYPT`, `DECRYPT` and `KDF_*` functions and a very high-level
`OmemoSessionManager` that manages all Double Ratchet sessions and provides a clean and simple
interface for encrypting a message for all known Ratchet sessions we have with a user.

This library also has no dependency on any XMPP library. `omemo_dart` instead defines an
intermediary format for the required data, that you, the user, will need to transform between
the stanza format of your preferred XMPP library and `omemo_dart`'s intermediary format
yourself.

## Important Notes

- **Please note that this library has not been audited for its security! Use at your own risk!**
- This library is not tested with other implementations of OMEMO 0.8.3 as I do not know of any client implementing spec compliant OMEMO 0.8.3. It does, however, work with itself.

## Contributing

When submitting a PR, please run the linter using `dart analyze` and make sure that all
tests still pass using `dart test`.

## License

Licensed under the MIT license.

See `LICENSE`.
