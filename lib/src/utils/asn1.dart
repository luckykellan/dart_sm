

class _ASN1Object {
  String? tlv;
  String t = '00';
  String l = '00';
  String v = '';

  _ASN1Object() {
    tlv = null;
  }

  /// 获取 der 编码比特流16进制串
  String getEncodedHex() {
    if (tlv == null) {
      v = getValue();
      l = getLength();
      tlv = t + l + v;
    }
    return tlv!;
  }

  String getLength() {
    int n = v.length ~/ 2; // 字节数
    String nHex = n.toRadixString(16);
    if (nHex.length % 2 == 1) nHex = '0$nHex';

    if (n < 128) {
      return nHex;
    } else {
      int head = 128 + nHex.length ~/ 2;
      return head.toRadixString(16) + nHex;
    }
  }

  String getValue() {
    return '';
  }
}

class _DERInteger extends _ASN1Object {
  _DERInteger(BigInt? bigint) : super() {
    t = '02'; // 整型标签说明
    if (bigint != null) v = bigintToValue(bigint);
  }

  @override
  String getValue() {
    return v;
  }

  String bigintToValue(BigInt inputBigInt) {
    String hexString = inputBigInt.toRadixString(16);
    if (!hexString.startsWith('-')) {
      if (hexString.length % 2 == 1) {
        hexString = '0$hexString';
      } else if (!RegExp(r'^[0-7]').hasMatch(hexString)) {
        hexString = '00$hexString';
      }
    } else {
      // Negative number
      hexString = hexString.substring(1);

      int paddedLength = hexString.length;
      if (paddedLength % 2 == 1) {
        paddedLength += 1; // Pad to a whole byte
      } else if (!RegExp(r'^[0-7]').hasMatch(hexString)) {
        paddedLength += 2;
      }

      String bitmask = '';
      for (int i = 0; i < paddedLength; i++) {
        bitmask += 'f';
      }
      BigInt bitmaskBigInt = BigInt.parse(bitmask, radix: 16);

      BigInt twosComplementBigInt = bitmaskBigInt ^ inputBigInt;
      twosComplementBigInt = twosComplementBigInt + BigInt.one;
      hexString = twosComplementBigInt.toRadixString(16).replaceAll(RegExp(r'^-'), '');
    }
    return hexString;
  }

}

class _DERSequence extends _ASN1Object {
  List<_ASN1Object> asn1Array;

  _DERSequence(this.asn1Array) : super() {
    t = '30'; // 序列标签说明
  }

  @override
  String getValue() {
    v = asn1Array.map((asn1Object) => asn1Object.getEncodedHex()).join('');
    return v;
  }
}

int getLenOfL(String str, int start) {
  if (int.parse(str[start + 2]) < 8) return 1;
  return int.parse(str.substring(start + 2, start + 4)) & 0x7f + 1;
}

int getL(String str, int start) {
  // 获取 l
  int len = getLenOfL(str, start);
  String l = str.substring(start + 2, start + 2 + len * 2);

  if (l.isEmpty) return -1;
  BigInt bigint = int.parse(l[0]) < 8
      ? BigInt.parse(l, radix: 16)
      : BigInt.parse(l.substring(2), radix: 16);

  return bigint.toInt();
}

int getStartOfV(String str, int start) {
  int len = getLenOfL(str, start);
  return start + (len + 1) * 2;
}

class ASN1Utils {
  /// ASN.1 der 编码，针对 sm2 签名
  static String encodeDer(BigInt r, BigInt s) {
    final derR = _DERInteger(r);
    final derS = _DERInteger(s);
    final derSeq = _DERSequence([derR, derS]);
    return derSeq.getEncodedHex();
  }

  /// 解析 ASN.1 der，针对 sm2 验签
  static Map<String, BigInt> decodeDer(String input) {
    int start = getStartOfV(input, 0);

    int vIndexR = getStartOfV(input, start);
    int lR = getL(input, start);
    String vR = input.substring(vIndexR, vIndexR + lR * 2);

    int nextStart = vIndexR + vR.length;
    int vIndexS = getStartOfV(input, nextStart);
    int lS = getL(input, nextStart);
    String vS = input.substring(vIndexS, vIndexS + lS * 2);

    BigInt r = BigInt.parse(vR, radix: 16);
    BigInt s = BigInt.parse(vS, radix: 16);

    return {'r': r, 's': s};
  }
}