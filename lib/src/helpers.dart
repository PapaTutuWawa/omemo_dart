/// Flattens [inputs] and concatenates the elements.
List<int> concat(List<List<int>> inputs) {
  final tmp = List<int>.empty(growable: true);
  for (final input in inputs) {
    tmp.addAll(input);
  }

  return tmp;
}

List<int> pkcs7padding(List<int> input, int size) {
  final paddingLength = size - input.length % size;
  final padding = List<int>.filled(paddingLength, 0x0);
  return concat([input, padding]);
}
