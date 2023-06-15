import 'dart:async';

import 'package:omemo_dart/src/omemo/queue.dart';
import 'package:test/test.dart';

Future<void> testMethod(RatchetAccessQueue queue, List<String> data, int duration) async {
  await queue.enterCriticalSection(data);

  await Future<void>.delayed(Duration(seconds: duration));

  await queue.leaveCriticalSection(data);
}

void main() {
  test('Test blocking due to conflicts', () async {
    final queue = RatchetAccessQueue();

    unawaited(testMethod(queue, ['a', 'b', 'c'], 5));
    unawaited(testMethod(queue, ['a'], 4));

    await Future<void>.delayed(const Duration(seconds: 1));
    expect(
      queue.runningOperations.containsAll(['a', 'b', 'c']),
      isTrue,
    );
    expect(queue.runningOperations.length, 3);

    await Future<void>.delayed(const Duration(seconds: 4));

    expect(
      queue.runningOperations.containsAll(['a']),
      isTrue,
    );
    expect(queue.runningOperations.length, 1);

    await Future<void>.delayed(const Duration(seconds: 4));
    expect(queue.runningOperations.length, 0);
  });

  test('Test not blocking due to no conflicts', () async {
    final queue = RatchetAccessQueue();

    unawaited(testMethod(queue, ['a', 'b'], 5));
    unawaited(testMethod(queue, ['c'], 5));
    unawaited(testMethod(queue, ['d'], 5));

    await Future<void>.delayed(const Duration(seconds: 1));
    expect(queue.runningOperations.length, 4);
    expect(
      queue.runningOperations.containsAll([
        'a', 'b', 'c', 'd',
      ]),
      isTrue,
    );
  });
}
