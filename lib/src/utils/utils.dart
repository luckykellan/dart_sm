
import 'dart:convert';

class SMUtils{
  static int leftShift(int x, int n){
    int s = n & 31;
    x = (x & 0xFFFFFFFF).toSigned(32);
    return (((x << s) | ((x & 0xFFFFFFFF) >> (32 - s))) & 0xFFFFFFFF).toSigned(32);
  }

  static int rightShift(int x, int n) {
    int s = n & 31;
    x = (x & 0xFFFFFFFF).toSigned(32);
    return ((x >> s) | ((x << (32 - s)) & 0xFFFFFFFF)).toSigned(32);
  }

  static String bytesToHexString(List<int> bytes) {
    final buffer = StringBuffer();
    for (final byte in bytes) {
      buffer.write(byte.toRadixString(16).padLeft(2, '0'));
    }
    return buffer.toString();
  }

  static List<int> hexStringToBytes(String hexString) {
    final length = hexString.length ~/ 2;
    final bytes = List<int>.filled(length, 0);
    for (int i = 0; i < length; i++) {
      final byteString = hexString.substring(i * 2, i * 2 + 2);
      bytes[i] = int.parse(byteString, radix: 16);
    }
    return bytes;
  }

  static String utf8ToHexString(String input) {
    List<int> utf8Encoded = utf8.encode(input);
    // 转换到16进制
    StringBuffer hexChars = StringBuffer();
    for (int i = 0; i < utf8Encoded.length; i++) {
      int bite = utf8Encoded[i];
      hexChars.write((bite >> 4).toRadixString(16));
      hexChars.write((bite & 0x0f).toRadixString(16));
    }
    return hexChars.toString();
  }
}
