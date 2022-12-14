/// Masks the 7 LSB
const lsb7Mask = 0x7F;

/// Constant for setting the MSB
const msb = 1 << 7;

/// Field types
const fieldTypeUint32 = 0;
const fieldTypeByteArray = 2;

int fieldId(int number, int type) {
  return (number << 3) | type;
}

class VarintDecode {

  const VarintDecode(this.n, this.length);
  final int n;
  final int length;
}

/// Decode a Varint that begins at [input]'s index [offset].
VarintDecode decodeVarint(List<int> input, int offset) {
  // The return value
  var n = 0;
  // The byte offset counter
  var i = 0;

  // Iterate until the MSB of the byte is 0
  while (true) {
    // Mask only the 7 LSB and "move" them accordingly
    n += (input[offset + i] & lsb7Mask) << (7 * i);

    // Break if we reached the end
    if (input[offset + i] & 1 << 7 == 0) {
      break;
    }
    i++;
  }

  return VarintDecode(n, i + 1);
}

// Encodes the integer [i] into a Varint.
List<int> encodeVarint(int i) {
  assert(i >= 0, "Two's complement is not implemented");
  final ret = List<int>.empty(growable: true);

  // Thanks to https://github.com/hathibelagal-dev/LEB128 for the trick with toRadixString!
  final numSevenBlocks = (i.toRadixString(2).length / 7).ceil();
  for (var j = 0; j < numSevenBlocks; j++) {
    // The 7 LSB of the byte we're creating
    final x = (i & (lsb7Mask << j * 7)) >> j * 7;

    if (j == numSevenBlocks - 1) {
      // If we were to shift further, we only get zero, so we're at the end
      ret.add(x);
    } else {
      // We still have at least one bit more to go, so set the MSB to 1
      ret.add(x + msb);
    }
  }

  return ret;
}
