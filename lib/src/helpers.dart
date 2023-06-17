import 'dart:convert';
import 'dart:math';
import 'package:cryptography/cryptography.dart';
import 'package:omemo_dart/src/keys.dart';

/// Flattens [inputs] and concatenates the elements.
List<int> concat(List<List<int>> inputs) {
  final tmp = List<int>.empty(growable: true);
  for (final input in inputs) {
    tmp.addAll(input);
  }

  return tmp;
}

/// Compares the two lists [a] and [b] and return true if [a] and [b] are index-by-index
/// equal. Returns false, if they are not "equal";
bool listsEqual<T>(List<T> a, List<T> b) {
  // TODO(Unknown): Do we need to use a constant time comparison?
  if (a.length != b.length) return false;

  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }

  return true;
}

/// Use Dart's cryptographically secure random number generator at Random.secure()
/// to generate [length] random numbers between 0 and 256 exclusive.
List<int> generateRandomBytes(int length) {
  final bytes = List<int>.empty(growable: true);
  final r = Random.secure();
  for (var i = 0; i < length; i++) {
    bytes.add(r.nextInt(256));
  }

  return bytes;
}

/// Generate a random number between 0 inclusive and 2**32 exclusive (2**32 - 1 inclusive).
int generateRandom32BitNumber() {
  return Random.secure().nextInt(4294967295 /*pow(2, 32) - 1*/);
}

OmemoPublicKey? decodeKeyIfNotNull(
  Map<String, dynamic> map,
  String key,
  KeyPairType type,
) {
  if (map[key] == null) return null;

  return OmemoPublicKey.fromBytes(
    base64.decode(map[key]! as String),
    type,
  );
}

int getTimestamp() {
  return DateTime.now().millisecondsSinceEpoch;
}

/// Describes the differences between two lists in terms of its items.
class ListDiff<T> {
  ListDiff(this.added, this.removed);

  /// The items that were added.
  final List<T> added;

  /// The items that were removed.
  final List<T> removed;
}

extension BeforeAfterListDiff<T> on List<T> {
  /// Compute the set-based changes between this list and [newList].
  ListDiff<T> diff(List<T> newList) {
    final oldSet = Set<T>.from(this);
    final newSet = Set<T>.from(newList);

    return ListDiff(
      newSet.difference(oldSet).toList(),
      oldSet.difference(newSet).toList(),
    );
  }
}

extension AppendToListOrCreateExtension<K, V> on Map<K, List<V>> {
  /// Create or append [value] to the list identified with key [key].
  void appendOrCreate(K key, V value, {bool checkExistence = false}) {
    if (containsKey(key)) {
      if (!checkExistence) {
        this[key]!.add(value);
      } if (!this[key]!.contains(value)) {
        this[key]!.add(value);
      }
    } else {
      this[key] = [value];
    }
  }
}

extension StringFromBase64Extension on String {
  /// Base64-decode this string. Useful for doing `someString?.fromBase64()` instead
  /// of `someString != null ? base64Decode(someString) : null`.
  List<int> fromBase64() => base64Decode(this);
}
