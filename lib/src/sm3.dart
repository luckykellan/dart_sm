import 'dart:typed_data';

import 'utils/utils.dart';

class SM3 {
  static List<int> hashBytesToBytes(List<int> array) {
    int inputLength = array.length * 8;
    int paddingLength = inputLength % 512;
    paddingLength = paddingLength >= 448 ? 512 - (paddingLength % 448) - 1 : 448 - paddingLength - 1;

    int size = (inputLength + paddingLength + 1 + 64) ~/ 8;
    Uint8List paddedData = Uint8List(size);
    paddedData.setAll(0, array);
    paddedData[array.length] = 0x80;

    // paddedData.buffer.asByteData().setUint64(size - 8, inputLength, Endian.big);
    final high = (inputLength >> 32) & 0xFFFFFFFF;
    final low = inputLength & 0xFFFFFFFF;
    paddedData.buffer.asByteData().setUint32(size - 8, high, Endian.big);
    paddedData.buffer.asByteData().setUint32(size - 4, low, Endian.big);

    int numberOfBlocks = paddedData.length ~/ 64;

    List<int> W = List<int>.filled(68, 0);
    List<int> M = List<int>.filled(64, 0);

    final V = Uint32List.fromList(_V);

    for (int i = 0; i < numberOfBlocks; i++) {
      W.fillRange(0, W.length, 0);
      M.fillRange(0, M.length, 0);

      int start = 16 * i;
      for (int j = 0; j < 16; j++) {
        W[j] = paddedData.buffer.asByteData().getUint32((start + j) * 4, Endian.big);
      }

      for (int j = 16; j < 68; j++) {
        W[j] = (_P1((W[j - 16] ^ W[j - 9]) ^ SMUtils.leftShift(W[j - 3], 15)) ^
        SMUtils.leftShift(W[j - 13], 7)) ^
        W[j - 6];
      }

      for (int j = 0; j < 64; j++) {
        M[j] = W[j] ^ W[j + 4];
      }

      int A = V[0];
      int B = V[1];
      int C = V[2];
      int D = V[3];
      int E = V[4];
      int F = V[5];
      int G = V[6];
      int H = V[7];

      int SS1, SS2, TT1, TT2, T;

      for (int j = 0; j < 64; j++) {
        T = j >= 0 && j <= 15 ? _T1 : _T2;
        SS1 = SMUtils.leftShift(SMUtils.leftShift(A, 12) + E + SMUtils.leftShift(T, j), 7);

        SS2 = SS1 ^ SMUtils.leftShift(A, 12);

        TT1 = (j >= 0 && j <= 15
            ? ((A ^ B) ^ C)
            : (((A & B) | (A & C)) | (B & C))) +
            D +
            SS2 +
            M[j];
        TT2 = (j >= 0 && j <= 15 ? ((E ^ F) ^ G) : ((E & F) | ((~E) & G))) +
            H +
            SS1 +
            W[j];

        D = C;
        C = SMUtils.leftShift(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = SMUtils.leftShift(F, 19);
        F = E;
        E = _P0(TT2);
      }

      V[0] ^= A;
      V[1] ^= B;
      V[2] ^= C;
      V[3] ^= D;
      V[4] ^= E;
      V[5] ^= F;
      V[6] ^= G;
      V[7] ^= H;
    }

    List<int> result = List<int>.filled(32, 0);
    for (int i = 0; i < 8; i++) {
      int word = V[i];
      result[i * 4] = (word >> 24) & 0xff;
      result[i * 4 + 1] = (word >> 16) & 0xff;
      result[i * 4 + 2] = (word >> 8) & 0xff;
      result[i * 4 + 3] = word & 0xff;
    }
    return result;
  }

  static String hash(String data, {String? key}) {
    if (key != null) {
      return _hmac(data, key);
    }
    return SMUtils.bytesToHexString(hashBytesToBytes(data.codeUnits));
  }

  static String hashBytes(List<int> data, {String? key}) {
    if (key != null) {
      return _hmac(data, key);
    }
    return SMUtils.bytesToHexString(hashBytesToBytes(data));
  }

  static String _hmac(dynamic input, String key) {
    final iPad = Uint8List(64)..fillRange(0, 64, 0x36);
    final oPad = Uint8List(64)..fillRange(0, 64, 0x5c);
    Uint8List keyBytes = Uint8List.fromList(SMUtils.hexStringToBytes(key));

    if (keyBytes.length > 64) {
      keyBytes = Uint8List.fromList(hashBytesToBytes(keyBytes));
    } else {
      final padding = 64 - keyBytes.length;
      keyBytes = Uint8List.fromList(keyBytes + List.filled(padding, 0));
    }

    final iPadKey = xor(keyBytes, iPad);
    final oPadKey = xor(keyBytes, oPad);
    Uint8List inputBytes;

    if (input is String) {
      inputBytes = Uint8List.fromList(input.codeUnits);
    } else if (input is List<int>) {
      inputBytes = Uint8List.fromList(input);
    } else {
      throw ArgumentError('Invalid input type');
    }
    return hashBytes(Uint8List.fromList(oPadKey + hashBytesToBytes(iPadKey + inputBytes)));
  }

  static int _P0(int X) => (X ^ SMUtils.leftShift(X, 9)) ^ SMUtils.leftShift(X, 17);

  static int _P1(int X) => (X ^ SMUtils.leftShift(X, 15)) ^ SMUtils.leftShift(X, 23);

  static const List<int> _V = [
    0x7380166f,
    0x4914b2b9,
    0x172442d7,
    0xda8a0600,
    0xa96f30bc,
    0x163138aa,
    0xe38dee4d,
    0xb0fb0e4e
  ];

  static const int _T1 = 0x79cc4519;
  static const int _T2 = 0x7a879d8a;

  static List<int> xor(List<int> x, List<int> y) {
    List<int> result = List<int>.filled(x.length, 0);
    for (int i = x.length - 1; i >= 0; i--) {
      result[i] = (x[i] ^ y[i]) & 0xff;
    }
    return result;
  }
}
