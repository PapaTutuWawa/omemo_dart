# omemo_dart

`omemo_dart` is a Dart library to help developers of Dart/Flutter XMPP clients to implement
[OMEMO](https://xmpp.org/extensions/xep-0384.html) in its newest version - currently 0.8.3.

The library provides an implementation of the [X3DH](https://signal.org/docs/specifications/x3dh/)
key exchange, the [Double Ratchet](https://signal.org/docs/specifications/doubleratchet/) with
the OMEMO 0.8.3 specific `ENCRYPT`, `DECRYPT` and `KDF_*` functions and a very high-level
`OmemoSessionManager` that manages all Double Ratchet sessions and provides a clean and simple
interface for encrypting a message for all known Ratchet sessions we have with a user.

This library also has no dependency on any XMPP library. `omemo_dart` instead defines an
intermediary format for the required data that you, the user, will need to transform to and from
the stanza format of your preferred XMPP library yourself.

## Important Notes

- **Please note that this library has not been audited for its security! Use at your own risk!**
- This library is not tested with other implementations of OMEMO 0.8.3 as I do not know of any client implementing spec compliant OMEMO 0.8.3. It does, however, work with itself.

## Usage

Include `omemo_dart` in your `pubspec.yaml` like this:

```yaml
# [...]

dependencies:
  omemo_dart:
    hosted: https://git.polynom.me/api/packages/PapaTutuWawa/pub
    version: ^0.4.3
  # [...]

# [...]
```

## Contributing

Due to issues with `protobuf`, `omemo_dart` reimplements the Protobuf encoding for the required
OMEMO messages. As such, `protobuf` is only a dependency for testing that the serialisation and
deserialisation of the custom implementation. In order to run tests, you need the Protbuf
compiler. After that, making sure that
the [Dart Protobuf compiler addon](https://pub.dev/packages/protoc_plugin) and the
Protobuf compiler itself is in your PATH,
run `protoc -I=./protobuf/ --dart_out=lib/protobuf/ ./protobuf/schema.proto` in the
repository's root to generate the real Protobuf bindings.

When submitting a PR, please run the linter using `dart analyze` and make sure that all
tests still pass using `dart test`.

To ensure uniform commit message formatting, please also use `gitlint` to lint your commit
messages' formatting.

## License

Licensed under the MIT license.

See `LICENSE`.

## Support

If you like what I do and you want to support me, feel free to donate to me on Ko-Fi.

[<img src="https://codeberg.org/moxxy/moxxyv2/raw/branch/master/assets/repo/kofi.png" height="36" style="height: 36px; border: 0px;"></img>](https://ko-fi.com/papatutuwawa)
