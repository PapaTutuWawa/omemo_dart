import 'dart:async';
import 'dart:collection';

import 'package:meta/meta.dart';
import 'package:synchronized/synchronized.dart';

extension UtilAllMethodsList<T> on List<T> {
  void removeAll(List<T> values) {
    for (final value in values) {
      remove(value);
    }
  }

  bool containsAll(List<T> values) {
    for (final value in values) {
      if (!contains(value)) {
        return false;
      }
    }

    return true;
  }
}

class _RatchetAccessQueueEntry {
  _RatchetAccessQueueEntry(
    this.jids,
    this.completer,
  );

  final List<String> jids;
  final Completer<void> completer;
}

class RatchetAccessQueue {
  final Queue<_RatchetAccessQueueEntry> _queue = Queue();

  @visibleForTesting
  final List<String> runningOperations = List<String>.empty(growable: true);

  final Lock lock = Lock();

  bool canBypass(List<String> jids) {
    for (final jid in jids) {
      if (runningOperations.contains(jid)) {
        return false;
      }
    }

    return true;
  }

  Future<void> enterCriticalSection(List<String> jids) async {
    final completer = await lock.synchronized<Completer<void>?>(() {
      if (canBypass(jids)) {
        runningOperations.addAll(jids);
        return null;
      }

      final completer = Completer<void>();
      _queue.add(
        _RatchetAccessQueueEntry(
          jids,
          completer,
        ),
      );

      return completer;
    });

    await completer?.future;
  }

  Future<void> leaveCriticalSection(List<String> jids) async {
    await lock.synchronized(() {
      runningOperations.removeAll(jids);

      while (_queue.isNotEmpty) {
        if (canBypass(_queue.first.jids)) {
          final head = _queue.removeFirst();
          runningOperations.addAll(head.jids);
          head.completer.complete();
        } else {
          break;
        }
      }
    });
  }

  Future<T> synchronized<T>(
    List<String> jids,
    Future<T> Function() function,
  ) async {
    await enterCriticalSection(jids);
    final result = await function();
    await leaveCriticalSection(jids);

    return result;
  }
}
