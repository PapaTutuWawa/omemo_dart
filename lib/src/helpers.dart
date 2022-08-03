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
bool listsEqual(List<int> a, List<int> b) {
  // TODO(Unknown): Do we need to use a constant time comparison?
  if (a.length != b.length) return false;

  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }

  return true;
}
