# dart_sm
基于Dart语言实现的国密SM2、SM3、SM4算法。

# 实现内容
* SM2
  - [x] 非对称加密解密，支持C1C3C2和C1C2C3格式
  - [x] 公钥压缩
  - [x] 签名验签，包括纯签名、sm3杂凑（userId）、der编码
  - [ ] 密钥交换算法
* SM3
  - [x] 消息杂凑
  - [x] hmac模式
* SM4
  - [x] ECB模式
  - [x] CBC模式
  - [ ] CTR模式
  - [ ] GCM模式

# 安装
```yaml
dependencies:
  dart_sm: ^0.1.4 
```

# 使用方法
## SM2
### 生成密钥对
```dart
KeyPair keypair = SM2.generateKeyPair();
String privateKey = keypair.privateKey; // 私钥
String publicKey = keypair.publicKey; // 公钥
```
### 公钥压缩（可选）
```dart
// 66位压缩公钥
String compressedPublicKey = SM2.compressPublicKey(publicKey);
bool isEqual = SM2.comparePublicKey(compressedPublicKey, publicKey);// 判断公钥是否相等
bool isValid = SM2.verifyPublicKey(compressedPublicKey); // 验证公钥
```
### 加密解密
```dart
// 默认C1C3C2格式
String cipherText = SM2.encrypt(data, publicKey);
String plainText = SM2.decrypt(cipherText, privateKey);
// C1C2C3格式
String cipherText = SM2.encrypt(data, publicKey, cipherMode: C1C2C3);
String plainText = SM2.decrypt(cipherText, privateKey, cipherMode: C1C2C3);
```
### 签名验签
```Dart
// 纯签名
String sigValue = SM2.signature(data, privateKey);
bool verifyValue = SM2.verifySignature(data, sigValue, publicKey);
// 纯签名，不做公钥推导
String sigValue = SM2.signature(data, privateKey, publicKey: publicKey);
bool verifyValue = SM2.verifySignature(data, sigValue, publicKey);
// sm3杂凑
String sigValue = SM2.signature(data, privateKey, publicKey: publicKey, hash: true, userId: 'userId');
bool verifyValue = SM2.verifySignature(data, sigValue, publicKey, hash: true, userId: 'userId');
// der编码
String sigValue = SM2.signature(data, privateKey, publicKey: publicKey, der: true);
bool verifyValue = SM2.verifySignature(data, sigValue, publicKey, der: true);
```
## SM3
```dart
// 参数为字符串
String hashValue = SM3.hash(data);
// 参数为字节数组
String hashValue = SM3.hashBytes(data);

//hmac，key要求为16进制字符串
String hashValue = SM3.hash(data, key:'95cb90ad5ba0c7c0e2a556f0072626b3');
String hashValue = SM3.hashBytes(data, key:'95cb90ad5ba0c7c0e2a556f0072626b3'); 
```
## SM4
### 设置全局密钥，效率比每次加解密时设置密钥高
```dart
SM4.setKey('0123456789abcdeffedcba9876543210');
```
### 加密解密
```dart
// 默认ECB模式
String cipherText = SM4.encrypt(data);
String plainText = SM4.encrypt(cipherText);
// CBC模式
String cipherText = SM4.encrypt(data,mode: SM4CryptoMode.CBC,iv: 'fedcba98765432100123456789abcdef');
String plainText = SM4.decrypt(encryptData, mode: SM4CryptoMode.CBC,iv: 'fedcba98765432100123456789abcdef');
//单独指定密钥
String cipherText = SM4.encrypt(data, key: '0123456789abcdeffedcba9876543210');
String plainText = SM4.encrypt(cipherText, key: '0123456789abcdeffedcba9876543210');
```

# 致谢
* [js版本的国密实现：sm-crypto](https://github.com/JuneAndGreen/sm-crypto)

# 协议
```
Copyright [luckykellan]

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

