import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'sm3.dart';
import 'utils/asn1.dart';
import 'utils/ec.dart';
import 'utils/utils.dart';

const C1C2C3 = 0;
const C1C3C2 = 1;

class SM2 {
  static final _EcParam _ecParam = _generateEcParam();
  static final Random _rng = Random.secure();

  static _EcParam _generateEcParam() {
    final p = BigInt.parse(
        'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF',
        radix: 16);
    final a = BigInt.parse(
        'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC',
        radix: 16);
    final b = BigInt.parse(
        '28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93',
        radix: 16);
    final curve = ECCurveFp(p, a, b);

    const gxHex =
        '32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7';
    const gyHex =
        'BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0';
    final G = curve.decodePointHex('04$gxHex$gyHex');

    final n = BigInt.parse(
        'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123',
        radix: 16);

    return _EcParam(curve: curve, G: G, n: n);
  }

  static String compressPublicKey(String s) {
    if (s.length != 130) throw ArgumentError('Invalid public key to compress');

    final len = (s.length - 2) ~/ 2;
    final xHex = s.substring(2, len + 2);
    final y = BigInt.parse(s.substring(len + 2, len * 2 + 2), radix: 16);

    String prefix = '03';
    if (y % BigInt.two == BigInt.zero) prefix = '02';

    return prefix + xHex;
  }

  static bool comparePublicKey(String publicKey1, String publicKey2) {
    final point1 = _ecParam.curve.decodePointHex(publicKey1);
    if (point1 == null) return false;

    final point2 = _ecParam.curve.decodePointHex(publicKey2);
    if (point2 == null) return false;

    return point1.equals(point2);
  }

  static bool verifyPublicKey(String publicKey) {
    final point = _ecParam.curve.decodePointHex(publicKey);
    if (point == null) return false;

    final x = point.getX();
    final y = point.getY();

    return y.square().equals(x
        .multiply(x.square())
        .add(x.multiply(_ecParam.curve.a))
        .add(_ecParam.curve.b));
  }

  static KeyPair generateKeyPair() {
    final int bitLength = _ecParam.n.bitLength;
    BigInt random = BigInt.parse('0');
    for (var i = 0; i < bitLength; i++) {
      final bit = _rng.nextBool() ? BigInt.one : BigInt.zero;
      random |= bit << i;
    }
    final d = random % (_ecParam.n - BigInt.one) + BigInt.one;
    final String privateKey = leftPad(d.toRadixString(16), 64);

    final ECPointFp P = _ecParam.G!.multiply(d);
    final String Px = leftPad(P.getX().toBigInteger().toRadixString(16), 64);
    final String Py = leftPad(P.getY().toBigInteger().toRadixString(16), 64);
    final String publicKey = '04$Px$Py';

    return KeyPair(privateKey: privateKey, publicKey: publicKey);
  }

  static String encrypt(String msg, String publicKey,
      {int cipherMode = C1C3C2}) {
    //List<int> msgBytes = SMUtils.hexStringToBytes(SMUtils.utf8ToHexString(msg));
    List<int> msgBytes = utf8.encode(msg);
    ECPointFp publicKeyPoint = _ecParam.curve.decodePointHex(publicKey)!;

    final keypair = generateKeyPair();
    BigInt k = BigInt.parse(keypair.privateKey, radix: 16);

    String c1 = keypair.publicKey;
    if (c1.length > 128) c1 = c1.substring(c1.length - 128);

    final p = publicKeyPoint.multiply(k);
    final x2 = SMUtils.hexStringToBytes(
        leftPad(p.getX().toBigInteger().toRadixString(16), 64));
    final y2 = SMUtils.hexStringToBytes(
        leftPad(p.getY().toBigInteger().toRadixString(16), 64));

    final c3 = SM3.hashBytes([...x2, ...msgBytes, ...y2]);

    int ct = 1;
    int offset = 0;
    List<int> t = [];
    List<int> z = [...x2, ...y2];
    int zLength = z.length;

    void nextT() {
      z.addAll([
        ct >> 24 & 0x00ff,
        ct >> 16 & 0x00ff,
        ct >> 8 & 0x00ff,
        ct & 0x00ff
      ]);
      t = SMUtils.hexStringToBytes(SM3.hashBytes(z));
      ct++;
      offset = 0;
      z.removeRange(zLength, z.length);
    }

    nextT();

    for (int i = 0, len = msgBytes.length; i < len; i++) {
      if (offset == t.length) nextT();
      msgBytes[i] ^= t[offset++] & 0xff;
    }

    final c2 = SMUtils.bytesToHexString(msgBytes);

    return cipherMode == C1C2C3 ? c1 + c2 + c3 : c1 + c3 + c2;
  }

  static String decrypt(String encryptData, String privateKey,
      {int cipherMode = C1C3C2}) {
    BigInt privateKeyBigInt = BigInt.parse(privateKey, radix: 16);

    String c3 = encryptData.substring(128, 128 + 64);
    String c2 = encryptData.substring(128 + 64);

    if (cipherMode == C1C2C3) {
      c3 = encryptData.substring(encryptData.length - 64);
      c2 = encryptData.substring(128, encryptData.length - 64);
    }

    Uint8List msg = Uint8List.fromList(SMUtils.hexStringToBytes(c2));

    ECPointFp c1 =
        _ecParam.curve.decodePointHex('04${encryptData.substring(0, 128)}')!;

    ECPointFp p = c1.multiply(privateKeyBigInt);
    List<int> x2 = SMUtils.hexStringToBytes(
        leftPad(p.getX().toBigInteger().toRadixString(16), 64));
    List<int> y2 = SMUtils.hexStringToBytes(
        leftPad(p.getY().toBigInteger().toRadixString(16), 64));
    int ct = 1;
    int offset = 0;
    List<int> t = [];
    List<int> z = [...x2, ...y2];

    void nextT() {
      t = SM3.hashBytesToBytes([
        ...z,
        ct >> 24 & 0x00ff,
        ct >> 16 & 0x00ff,
        ct >> 8 & 0x00ff,
        ct & 0x00ff
      ]);
      ct++;
      offset = 0;
    }

    nextT();

    for (int i = 0, len = msg.length; i < len; i++) {
      if (offset == t.length) nextT();
      msg[i] ^= t[offset++] & 0xff;
    }

    String checkC3 = SM3.hashBytes([...x2, ...msg, ...y2]);

    if (checkC3.toLowerCase() == c3.toLowerCase()) {
      return utf8.decode(msg);
    } else {
      return '';
    }
  }

  static String signature(dynamic msg, String privateKey,
      {bool der = false,
      bool hash = false,
      String? publicKey,
      String userId = '1234567812345678'}) {
    String hashHex = msg is String
        ? SMUtils.utf8ToHexString(msg)
        : SMUtils.bytesToHexString(msg);
    if (hash) {
      // sm3杂凑
      publicKey = publicKey ?? _getPublicKeyFromPrivateKey(privateKey);
      hashHex = _getHash(hashHex, publicKey, userId);
    }

    final BigInt dA = BigInt.parse(privateKey, radix: 16);
    final BigInt e = BigInt.parse(hashHex, radix: 16);
    BigInt dAInverse = (BigInt.one + dA).modInverse(_ecParam.n);
    BigInt k, r, s;

    do {
      do {
        Map<String, BigInt> point;
        point = getPoint();
        k = point['k']!;
        r = (e + point['x1']!) % _ecParam.n;
      } while (r == BigInt.zero || r + k == _ecParam.n);

      s = (dAInverse * (k - (r * dA))) % _ecParam.n;
    } while (s == BigInt.zero);

    if (der) return ASN1Utils.encodeDer(r, s); // asn.1 der 编码
    return leftPad(r.toRadixString(16), 64) + leftPad(s.toRadixString(16), 64);
  }

  static bool verifySignature(String msg, String signHex, String publicKey,
      {bool der = false,
      bool hash = false,
      String userId = '1234567812345678'}) {

    String hashHex = SMUtils.utf8ToHexString(msg);
    if (hash) {
      hashHex = _getHash(hashHex, publicKey, userId);
    }

    BigInt r;
    BigInt s;
    if (der) {
      final Map<String, BigInt> decodeDerObj = ASN1Utils.decodeDer(signHex);
      r = decodeDerObj['r']!;
      s = decodeDerObj['s']!;
    } else {
      r = BigInt.parse(signHex.substring(0, 64), radix: 16);
      s = BigInt.parse(signHex.substring(64), radix: 16);
    }

    final ECPointFp PA = _ecParam.curve.decodePointHex(publicKey)!;
    final BigInt e = BigInt.parse(hashHex, radix: 16);

    final BigInt t = (r + s) % _ecParam.n;
    if (t == BigInt.zero) return false;
    final ECPointFp x1y1 = _ecParam.G!.multiply(s).add(PA.multiply(t));
    final BigInt R = (e + x1y1.getX().toBigInteger()) % _ecParam.n;
    return r == R;
  }

  static Map<String, BigInt> getPoint() {
    final keyPair = generateKeyPair();
    final ECPointFp PA = _ecParam.curve.decodePointHex(keyPair.publicKey)!;
    return {
      "k": BigInt.parse(keyPair.privateKey, radix: 16),
      "x1": PA.getX().toBigInteger()
    };
  }

  static String _getHash(String hashHex, String publicKey, String userId) {
    userId = SMUtils.utf8ToHexString(userId);
    final String a =
        leftPad(_ecParam.G!.curve.a.toBigInteger().toRadixString(16), 64);
    final String b =
        leftPad(_ecParam.G!.curve.b.toBigInteger().toRadixString(16), 64);
    final String gx =
        leftPad(_ecParam.G!.getX().toBigInteger().toRadixString(16), 64);
    final String gy =
        leftPad(_ecParam.G!.getY().toBigInteger().toRadixString(16), 64);
    late String px;
    late String py;

    if (publicKey.length == 128) {
      px = publicKey.substring(0, 64);
      py = publicKey.substring(64, 128);
    } else {
      final ECPointFp point = _ecParam.G!.curve.decodePointHex(publicKey)!;
      px = leftPad(point.getX().toBigInteger().toRadixString(16), 64);
      py = leftPad(point.getY().toBigInteger().toRadixString(16), 64);
    }
    List<int> data = List.from(SMUtils.hexStringToBytes(userId + a + b + gx + gy + px + py));

    final int entl = userId.length * 4;
    data.insert(0, entl & 0x00ff);
    data.insert(0, (entl >> 8) & 0x00ff);

    List<int> z = SMUtils.hexStringToBytes(
        SM3.hashBytes(data));

    return SM3.hashBytes(z + SMUtils.hexStringToBytes(hashHex));
  }

  static String _getPublicKeyFromPrivateKey(String privateKey) {
    final BigInt privateKeyBigInt = BigInt.parse(privateKey, radix: 16);
    final ECPointFp PA = _ecParam.G!.multiply(privateKeyBigInt);
    final String x = leftPad(PA.getX().toBigInteger().toRadixString(16), 64);
    final String y = leftPad(PA.getY().toBigInteger().toRadixString(16), 64);
    return '04$x$y';
  }
}

class KeyPair {
  final String privateKey;
  final String publicKey;
  BigInt? k;
  BigInt? x1;

  KeyPair({required this.privateKey, required this.publicKey, this.k, this.x1});
}

class _EcParam {
  final ECCurveFp curve;
  final ECPointFp? G;
  final BigInt n;

  _EcParam({required this.curve, required this.G, required this.n});
}
