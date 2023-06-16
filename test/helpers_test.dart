import 'package:omemo_dart/src/helpers.dart';
import 'package:omemo_dart/src/omemo/queue.dart';
import 'package:test/test.dart';

void main() {
  group('List diff', () {
    test('Empty list to full list', () {
      final result = <int>[].diff([1, 2, 3, 4]);
      expect(result.removed, isEmpty);
      expect(
        result.added.containsAll([1, 2, 3, 4]),
        isTrue,
      );
      expect(result.added.length, 4);
    });

    test('Full list to empty list', () {
      final result = [1, 2, 3, 4].diff([]);
      expect(result.added, isEmpty);
      expect(
        result.removed.containsAll([1, 2, 3, 4]),
        isTrue,
      );
      expect(result.removed.length, 4);
    });

    test('Full list to full list', () {
      final result = [1, 2, 3, 4].diff([1, 2, 4, 5]);
      expect(result.added, [5]);
      expect(result.removed, [3]);
    });
  });
}
