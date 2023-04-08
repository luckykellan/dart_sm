class ECFieldElementFp {
  final BigInt x;
  final BigInt q;

  ECFieldElementFp(this.q, this.x) {
    // TODO if (x.compareTo(q) >= 0) error
  }

  /// 判断相等
  bool equals(ECFieldElementFp other) {
    if (other == this) return true;
    return (q == other.q && x == other.x);
  }

  /// 返回具体数值
  BigInt toBigInteger() {
    return x;
  }

  /// 取反
  ECFieldElementFp negate() {
    return ECFieldElementFp(q, (-x) % q);
  }

  /// 相加
  ECFieldElementFp add(ECFieldElementFp b) {
    return ECFieldElementFp(q, (x + b.toBigInteger()) % q);
  }

  /// 相减
  ECFieldElementFp subtract(ECFieldElementFp b) {
    return ECFieldElementFp(q, (x - b.toBigInteger()) % q);
  }

  /// 相乘
  ECFieldElementFp multiply(ECFieldElementFp b) {
    return ECFieldElementFp(q, (x * b.toBigInteger()) % q);
  }

  /// 相除
  ECFieldElementFp divide(ECFieldElementFp b) {
    return ECFieldElementFp(q, (x * b.toBigInteger().modInverse(q)) % q);
  }

  /// 平方
  ECFieldElementFp square() {
    return ECFieldElementFp(q, (x * x) % q);
  }
}

class ECPointFp {
  final ECCurveFp curve;
  late final ECFieldElementFp? x;
  late final ECFieldElementFp? y;
  late final BigInt z;
  BigInt? zinv;

  ECPointFp(this.curve, this.x, this.y, [BigInt? z]) {
    this.z = z ?? BigInt.one;
    zinv = null;
  }

  ECFieldElementFp getX() {
    zinv ??= z.modInverse(curve.q);
    return curve.fromBigInteger(x!.toBigInteger() * zinv! % curve.q);
  }

  ECFieldElementFp getY() {
    zinv ??= z.modInverse(curve.q);
    return curve.fromBigInteger(y!.toBigInteger() * zinv! % curve.q);
  }

  bool equals(ECPointFp other) {
    if (other == this) return true;
    if (isInfinity()) return other.isInfinity();
    if (other.isInfinity()) return isInfinity();

    final u = (other.y!.toBigInteger() * z - y!.toBigInteger() * other.z) % curve.q;
    if (u != BigInt.zero) return false;

    final v = (other.x!.toBigInteger() * z - x!.toBigInteger() * other.z) % curve.q;
    return v == BigInt.zero;
  }

  bool isInfinity() {
    if (x == null && y == null) return true;
    return z == BigInt.zero && y!.toBigInteger() != BigInt.zero;
  }

  ECPointFp negate() {
    return ECPointFp(curve, x, y!.negate(), z);
  }

  ECPointFp add(ECPointFp b) {
    if (isInfinity()) return b;
    if (b.isInfinity()) return this;
    final x1 = x!.toBigInteger();
    final y1 = y!.toBigInteger();
    final z1 = z;
    final x2 = b.x!.toBigInteger();
    final y2 = b.y!.toBigInteger();
    final z2 = b.z;
    final q = curve.q;
    final w1 = (x1 * z2) % q;
    final w2 = (x2 * z1) % q;
    final w3 = (w1 - w2) % q;
    final w4 = (y1 * z2) % q;
    final w5 = (y2 * z1) % q;
    final w6 = (w4 - w5) % q;

    if (w3 == BigInt.zero) {
      if (w6 == BigInt.zero) {
        return twice();
      }
      return curve.infinity;
    }

    final w7 = (w1 + w2) % q;
    final w8 = (z1 * z2) % q;
    final w9 = (w3 * w3) % q;
    final w10 = (w3 * w9) % q;
    final w11 = (w8 * (w6 * w6) % q - w7 * w9) % q;

    final x3 = (w3 * w11) % q;
    final y3 = (w6 * (w9 * w1 % q - w11) - w4 * w10) % q;
    final z3 = (w10 * w8) % q;

    return ECPointFp(curve, curve.fromBigInteger(x3), curve.fromBigInteger(y3), z3);
  }

  ECPointFp twice() {
    if (isInfinity()) return this;
    if (y!.toBigInteger().sign == 0) return curve.infinity;

    final x1 = x!.toBigInteger();
    final y1 = y!.toBigInteger();
    final z1 = z;
    final q = curve.q;
    final a = curve.a.toBigInteger();

    final w1 = (x1 * x1 * BigInt.from(3) + a * (z1 * z1)) % q;
    final w2 = (y1 * BigInt.from(2) * z1) % q;
    final w3 = (y1 * y1) % q;
    final w4 = (w3 * x1 * z1) % q;
    final w5 = (w2 * w2) % q;
    final w6 = (w1 * w1 - w4 * BigInt.from(8)) % q;

    final x3 = (w2 * w6) % q;
    final y3 = (w1 * (w4 * BigInt.from(4) - w6) - w5 * BigInt.from(2) * w3) % q;
    final z3 = (w2 * w5) % q;

    return ECPointFp(curve, curve.fromBigInteger(x3), curve.fromBigInteger(y3), z3);
  }

  ECPointFp multiply(BigInt k) {
    if (isInfinity()) return this;
    if (k.sign == 0) return curve.infinity;

    final k3 = k * BigInt.from(3);
    final neg = negate();
    ECPointFp Q = this;

    for (int i = k3.bitLength - 2; i > 0; i--) {
      Q = Q.twice();

      /*final k3Bit = (k3 >> i) & BigInt.one == BigInt.one;
      final kBit = (k >> i) & BigInt.one == BigInt.zero;*/

      final k3Bit = (k3 >> i).isOdd;
      ;
      final kBit = (k >> i).isOdd;

      if (k3Bit != kBit) {
        Q = Q.add(k3Bit ? this : neg);
      }
    }

    return Q;
  }
}

class ECCurveFp {
  ECCurveFp(this.q, BigInt a, BigInt b) {
    this.a = fromBigInteger(a);
    this.b = fromBigInteger(b);
    infinity = ECPointFp(this, null, null); // 无穷远点
  }

  final BigInt q;
  late ECFieldElementFp a;
  late ECFieldElementFp b;
  late ECPointFp infinity;

  bool equals(Object? other) {
    if (identical(this, other)) return true;
    if (other is! ECCurveFp) return false;
    return q == other.q && a == other.a && b == other.b;
  }

  ECFieldElementFp fromBigInteger(BigInt x) {
    return ECFieldElementFp(q, x);
  }

  ECPointFp? decodePointHex(String s) {
    switch (int.parse(s.substring(0, 2), radix: 16)) {
      case 0:
        return infinity;
      case 2:
      case 3:
        final x = fromBigInteger(BigInt.parse(s.substring(2), radix: 16));
        var y = fromBigInteger(x
            .multiply(x.square())
            .add(x.multiply(a))
            .add(b)
            .toBigInteger()
            .modPow(q ~/ BigInt.from(4) + BigInt.one, q));

        /* var y = x
            .multiply(x.square())
            .add(x.multiply(a.add(b)))
            .toBigInteger()
            .modPow(q ~/ BigInt.from(4) + BigInt.one, q);*/
        if (y.toBigInteger() % BigInt.two !=
            BigInt.parse(s.substring(0, 2), radix: 16) - BigInt.two) {
          y = y.negate();
        }
        return ECPointFp(this, x, y);
      case 4:
      case 6:
      case 7:
        final len = (s.length - 2) ~/ 2;
        final xHex = s.substring(2, 2 + len);
        final yHex = s.substring(2 + len, 2 + 2 * len);
        /*print("xHex: ${BigInt.parse(xHex, radix: 16).toRadixString(16)}");
        print("yHex: ${BigInt.parse(yHex, radix: 16).toRadixString(16)}");*/
        return ECPointFp(this, fromBigInteger(BigInt.parse(xHex, radix: 16)),
            fromBigInteger(BigInt.parse(yHex, radix: 16)));
      default:
        return null;
    }
  }
}

String leftPad(String input, int num) {
  if (input.length >= num) return input;
  return List.filled(num - input.length, '0').join() + input;
}

