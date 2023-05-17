import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:http/http.dart' as http;

import 'package:pointycastle/block/aes_fast.dart';
import 'package:pointycastle/block/modes/cbc.dart';
import 'package:pointycastle/digests/md5.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/digests/sha512.dart';
import 'package:pointycastle/ecc/curves/secp256r1.dart';
import 'package:pointycastle/export.dart';
import 'package:pointycastle/key_generators/ec_key_generator.dart';
import 'package:pointycastle/pointycastle.dart';
import 'package:pointycastle/random/fortuna_random.dart';
import 'package:pointycastle/signers/ecdsa_signer.dart';

/**
 * dependencies:
 *   pointycastle: ^3.7.3
 *   http: ^0.13.4
 */
Future<void> main() async {
  // ECC测试
  // String messag = "我是中国人梵蒂冈啊!!!ABC@#";
  // String publicKeyTo =
  //     "BIWUWAiOuCM8kXAjzrDUDcQsYONjaspiIPMqvqR/u4kBLJR4MeGbLDOHqsrBnH7FLaNQQHif0756ThysXLHNS1g=";
  // Uint8List text =
  //     await eccEncrypt(publicKeyTo, stringToUint8List(messag));
  // print("ECC公钥加密结果: ${base64.encode(text)}");

  // EcKeyPair keyPair = await generateEcKeyPair();
  // Uint8List r = sign(keyPair.privateKey, stringToUint8List(messag));
  // print("ECC签名: ${uint8ListToHex(r)}");
  // ECPublicKey publicKey = loadECPublicKey(
  //     "04859458088eb8233c917023ceb0d40dc42c60e3636aca6220f32abea47fbb89012c947831e19b2c3387aacac19c7ec52da35040789fd3be7a4e1cac5cb1cd4b58");
  // String s =
  //     "abfa10165e740c7ba2ae00b8c162ea8e88dc49a7fcace0b62a1e6847be60ce905e1316440185edf77477d5cf8661d09a90d3fcbb33eea5ad4c75dba171c0c664";
  // bool valid = verify(keyPair.publicKey, stringToUint8List(messag), r);
  // print("ECC验签: $valid");
  // http请求接口格式实现
  https: //crmadm.lbdev.fun/adm/PublicKey
  for (var i = 0; i < 10000; i++) {
    String domain = "https://crmapi.lbdev.fun";
    String publicKey = await getPublicKey("$domain/api/public_key");
    print("服务端公钥: $publicKey");
    // https://crmapi.lbdev.fun/api/reg?mobile=13823912345&password=123456&email=123456@qq.com
    await postByECC(
        domain, "/api/login", publicKey, {
      'mobile': "13823912345",
      'email': "123456@qq.com",
      'code': '123',
      'username': "123",
      'password': "123456"
    });
    print("----------------------------------------------");
    await postData(domain, "/adm/getUser", {}, true);
  }
}

Future<Uint8List> eccEncrypt(String publicKeyTo, Uint8List message) async {
  ECPublicKey publicKey = loadECPublicKey(publicKeyTo);
  final keyPairA = await generateEcKeyPair();
  Uint8List? ephemPublicKey = await getECPublicKeyBytes(keyPairA.publicKey);
  print("临时公钥: ${uint8ListToHex(ephemPublicKey!)}");
  String shared = await deriveSharedSecret(keyPairA.privateKey, publicKey);
  print("共享密钥: $shared");
  Uint8List sharedHash = hash512(Uint8List.fromList(utf8.encode(shared)));
  print("密钥哈希: ${uint8ListToHex(sharedHash)}");
  Uint8List macKey = sharedHash.sublist(32);
  Uint8List encryptionKey = sharedHash.sublist(0, 32);
  Uint8List iv = randomBytes(16);
  print("macKey: ${uint8ListToHex(macKey)}");
  print("encryptionKey: ${uint8ListToHex(encryptionKey)}");
  print("iv: ${uint8ListToHex(iv)}");
  Uint8List ciphertext = aesCbcEncrypt(iv, encryptionKey, message);
  print("aes encrypt: ${uint8ListToHex(ciphertext)}");
  Uint8List pre = concatPre(iv, ephemPublicKey, ciphertext);
  Uint8List realMac = hmac256(macKey, pre);
  return concatKDF(ephemPublicKey, iv, realMac, ciphertext);
}

Uint8List sign(ECPrivateKey privateKey, Uint8List message) {
  // final domain = ECCurve_secp256r1();
  // final privKey = ECPrivateKey(BigInt.parse(privateKey.toString()), domain);
  Uint8List hash = hash256(message);
  final signer = ECDSASigner(SHA256Digest(), HMac(SHA256Digest(), 64))
    ..init(true, PrivateKeyParameter(privateKey));
  ECSignature sig = signer.generateSignature(hash) as ECSignature;
  Uint8List r = bigIntToUint8List(sig.r);
  Uint8List s = bigIntToUint8List(sig.s);
  final result = Uint8List(r.length + s.length);
  result.setRange(0, r.length, r);
  result.setRange(r.length, result.length, s);
  return result;
}

bool verify(ECPublicKey publicKey, Uint8List message, Uint8List signature) {
  // final domain = ECCurve_secp256r1();
  // final Q = domain.curve.decodePoint(publicKey);
  Uint8List hash = hash256(message);
  final verifier = ECDSASigner(SHA256Digest(), HMac(SHA256Digest(), 64));
  verifier.init(false, PublicKeyParameter(publicKey));
  final sig = ECSignature(
      BigInt.parse(
          uint8ListToBigInt(signature.sublist(0, signature.length ~/ 2))
              .toString()),
      BigInt.parse(uint8ListToBigInt(signature.sublist(signature.length ~/ 2))
          .toString()));
  return verifier.verifySignature(hash, sig);
}

Uint8List bigIntToUint8List(BigInt value) {
  final byteCount = (value.bitLength + 7) >> 3; // bitLength除以8并向上取整
  final result = Uint8List(byteCount);
  for (var i = 0; i < byteCount; i++) {
    result[i] = value.toUnsigned(8).toInt(); // toUnsigned返回一个无符号整数，toInt将其转换为字节
    value = value >> 8;
  }
  return result;
}

BigInt uint8ListToBigInt(Uint8List value) {
  BigInt result = BigInt.zero;
  for (var i = value.length - 1; i >= 0; i--) {
    result = (result << 8) + BigInt.from(value[i]);
  }
  return result;
}

Uint8List concatPre(Uint8List a, Uint8List b, Uint8List c) {
  final result = Uint8List(a.length + b.length + c.length);
  var offset = 0;
  offset += a.length;
  result.setRange(0, offset, a);
  offset += b.length;
  result.setRange(a.length, offset, b);
  result.setRange(a.length + b.length, result.length, c);
  return result;
}

Uint8List concatKDF(Uint8List a, Uint8List b, Uint8List c, Uint8List d) {
  final result = Uint8List(a.length + b.length + c.length + d.length);
  var offset = 0;
  offset += a.length;
  result.setRange(0, offset, a);
  offset += b.length;
  result.setRange(a.length, offset, b);
  offset += c.length;
  result.setRange(a.length + b.length, offset, c);
  result.setRange(a.length + b.length + c.length, result.length, d);
  return result;
}

String base64ToHex(String b64) {
  return uint8ListToHex(Uint8List.fromList(base64.decode(b64)));
}

Uint8List aesCbcEncrypt(Uint8List iv, Uint8List key, Uint8List plaintext) {
  final blockCipher = CBCBlockCipher(AESFastEngine())
    ..init(true, ParametersWithIV(KeyParameter(key), iv));
  final paddedPlaintext = pkcs7Padding(plaintext, blockCipher.blockSize);
  final cipherText = Uint8List(paddedPlaintext.length);
  var offset = 0;
  while (offset < paddedPlaintext.length) {
    offset +=
        blockCipher.processBlock(paddedPlaintext, offset, cipherText, offset);
  }
  return cipherText;
}

Uint8List aesCbcDecrypt(Uint8List iv, Uint8List key, Uint8List ciphertext) {
  final blockCipher = CBCBlockCipher(AESFastEngine())
    ..init(false, ParametersWithIV(KeyParameter(key), iv));
  final plaintext = Uint8List(ciphertext.length);
  var offset = 0;
  while (offset < ciphertext.length) {
    offset += blockCipher.processBlock(ciphertext, offset, plaintext, offset);
  }
  return pkcs7UnPadding(plaintext);
}

Uint8List pkcs7Padding(Uint8List ciphertext, int blockSize) {
  int padding = blockSize - ciphertext.length % blockSize;
  List<int> padtext = List.filled(padding, padding);
  return Uint8List.fromList([...ciphertext, ...padtext]);
}

Uint8List pkcs7UnPadding(Uint8List plaintext) {
  int length = plaintext.length;
  int unpadding = plaintext[length - 1];
  return plaintext.sublist(0, length - unpadding);
}

Uint8List hmac256(Uint8List key, Uint8List message) {
  final blocksize = 64;
  if (key.length > blocksize) {
    key = hash256(key);
  }
  key = Uint8List.fromList(
      [...key, ...List.filled(blocksize - key.length, 0).cast<int>()]);
  final innerKey = key.map((b) => b ^ 0x36).toList();
  final outerKey = key.map((b) => b ^ 0x5c).toList();
  final innerData = Uint8List.fromList([...innerKey, ...message]);
  final outerData = Uint8List.fromList([...outerKey, ...hash256(innerData)]);
  return hash256(outerData);
}

Uint8List hash256(Uint8List data) {
  return SHA256Digest().process(data);
}

Uint8List hash512(Uint8List msg) {
  return SHA512Digest().process(msg);
}

Uint8List hashMD5(Uint8List data) {
  return MD5Digest().process(data);
}

Future<Uint8List?> getECPublicKeyBytes(ECPublicKey publicKey) async {
  return publicKey.Q?.getEncoded(false);
}

ECPublicKey loadECPublicKey(String publicKeyBase64) {
  final domainParams = ECCurve_secp256r1();
  final q = domainParams.curve.decodePoint(base64.decode(publicKeyBase64));
  return ECPublicKey(q, domainParams);
}

Uint8List randomBytes(int length) {
  final rand = Random.secure();
  final bytes = Uint8List(length);
  for (int i = 0; i < length; i++) {
    bytes[i] = rand.nextInt(256);
  }
  return bytes;
}

Uint8List stringToUint8List(String s) {
  return Uint8List.fromList(utf8.encode(s));
}

String uint8ListToHex(Uint8List bytes) {
  return bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join('');
}

Uint8List hexToUint8List(String hexString) {
  final len = hexString.length;
  final uint8List = Uint8List(len ~/ 2);
  for (var i = 0; i < len; i += 2) {
    final hex = hexString.substring(i, i + 2);
    final byte = int.parse(hex, radix: 16);
    uint8List[i ~/ 2] = byte;
  }
  return uint8List;
}

String randomStr(int length) {
  if (length > 32) {
    length = 32;
  }
  return uint8ListToHex(hash256(randomBytes(16))).substring(0, length);
}

Future<String> deriveSharedSecret(ECPrivateKey privateKey,
    ECPublicKey publicKey) async {
  final agreement = ECDHBasicAgreement();
  agreement.init(privateKey);
  final sharedSecret = agreement.calculateAgreement(publicKey);
  String secretHex = sharedSecret.toRadixString(16);
  if (secretHex.length < 64) {
    StringBuffer sb = StringBuffer();
    for (var i = 0; i < 64 - secretHex.length; i++) {
      sb.write("0");
    }
    sb.write(secretHex);
    secretHex = sb.toString();
  }
  return secretHex;
}

Future<EcKeyPair> generateEcKeyPair() async {
  final secureRandom = FortunaRandom();
  final seedSource = Random.secure();
  final seeds = <int>[];
  for (var i = 0; i < 32; i++) {
    seeds.add(seedSource.nextInt(256));
  }
  secureRandom.seed(KeyParameter(Uint8List.fromList(seeds)));

  final domainParams = ECCurve_secp256r1();
  final keyGenParams = ECKeyGeneratorParameters(domainParams);
  final keyGenerator = ECKeyGenerator();
  keyGenerator.init(ParametersWithRandom(keyGenParams, secureRandom));
  final keyPair = keyGenerator.generateKeyPair();

  return EcKeyPair(
      keyPair.privateKey as ECPrivateKey, keyPair.publicKey as ECPublicKey);
}

class EcKeyPair {
  final ECPrivateKey privateKey;
  final ECPublicKey publicKey;

  EcKeyPair(this.privateKey, this.publicKey);
}

class TokenInfo {
  final String secret;
  final String token;

  TokenInfo(this.secret, this.token);
}

Future<String> aesEncrypt(String data, String secret, String secret1) async {
  String key = uint8ListToHex(hashMD5(stringToUint8List(secret)));
  String iv =
  uint8ListToHex(hashMD5(stringToUint8List(secret1))).substring(0, 16);
  Uint8List r = aesCbcEncrypt(
      stringToUint8List(iv), stringToUint8List(key), stringToUint8List(data));
  return base64Encode(r);
}

Future<String> aesDecrypt(String data, String secret) async {
  Uint8List b = base64Decode(data);
  String key = uint8ListToHex(hashMD5(stringToUint8List(secret)));
  String iv = key.substring(0, 16);
  Uint8List r = aesCbcDecrypt(stringToUint8List(iv), stringToUint8List(key), b);
  return utf8.decode(r);
}

Future<String> getPublicKey(String url) async {
  final response = await http.get(Uri.parse(url));
  if (response.statusCode == 200) {
    return response.body;
  }
  throw Exception('Request failed with status: ${response.statusCode}.');
}

/// domain 请求域名
/// path 请求方法
/// publicKey 服务器公钥
/// param 请求参数JSON对象
Future<TokenInfo> postByECC(String domain, String path, String publicKey,
    Object param) async {
  String randomCode = randomStr(24);
  Uint8List code =
  await eccEncrypt(publicKey, stringToUint8List(randomCode));
  print("随机数: ${base64Encode(code)}");
  String jsonData = jsonEncode(param);
  String data = await aesEncrypt(jsonData, randomCode, randomCode);
  String nonce = randomStr(8);
  int time = DateTime
      .now()
      .millisecondsSinceEpoch ~/ 1000;
  int plan = 2;
  String sigStr = "$path$data$nonce$time$plan";
  print("random code: $randomCode");
  print("nonce: $nonce");
  print("time:  $time");
  print("签名字符串: $sigStr");
  String sign = base64Encode(
      hmac256(stringToUint8List(publicKey), stringToUint8List(sigStr)));
  print("sign: $sign");
  Map postBody = {'d': data, 't': time, 'n': nonce, 'p': plan, 's': sign};
  final response = await http.post(
    Uri.parse("$domain$path"),
    body: jsonEncode(postBody),
    headers: {'RandomCode': base64Encode(code)},
  );
  if (response.statusCode != 200) {
    throw Exception("网络请求失败");
  }
  Map map = jsonDecode(response.body);
  print(map);
  if (map['c'] == 200) {
    String d = map['d'];
    String n = map['n'];
    int t = map['t'];
    int p = map['p'];
    String s = map['s'];
    String sigStr = "$path$d$n$t$p";
    String checkSign = base64Encode(
        hmac256(stringToUint8List(randomCode), stringToUint8List(sigStr)));
    if (checkSign != s) {
      throw Exception("响应数据验签失败");
    }
    String res = await aesDecrypt(d, randomCode);
    map = jsonDecode(res);
    TokenInfo tokenInfo = TokenInfo(map['secret'], map['token']);
    print("密钥: ${tokenInfo.secret}");
    print("令牌: ${tokenInfo.token}");
    return tokenInfo;
  }
  throw Exception("请求失败: " + map['m']);
}

/// domain 请求域名
/// path 请求方法
/// param 请求参数JSON对象
/// useAes false明文, true密文
Future<Map> postData(String domain, String path, Object param,
    bool useAes) async {
  String secret =
      "Tu0M3g9NJu+LeYIHy*kT^j#lKG2maQEPI9+lZAta#lK!ZC@diQPuWcW6rux4MZU=";
  String token =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxNjQ5NjQyMjg5NDQzNjM1MjAxIiwiYXVkIjoiIiwiaXNzIjoiIiwiaWF0IjowLCJleHAiOjE2ODMzNDk5NDUsImRldiI6IkFQUCIsImp0aSI6IkU2SjlzS3NISXN2eWtXZWNjVGozeHc9PSIsImV4dCI6IiJ9.S00KxO/XGJ75QT3EYIM6xc0p8whFRxN8C6+WZxI9eJg=";
  String jsonData = jsonEncode(param);
  String nonce = randomStr(8);
  int time = DateTime
      .now()
      .millisecondsSinceEpoch ~/ 1000;
  String data = "";
  int plan = 0;
  if (useAes) {
    data = await aesEncrypt(jsonData, secret, "$nonce$time");
    plan = 1;
  } else {
    data = base64Encode(stringToUint8List(jsonData));
    plan = 0;
  }
  String sign = base64Encode(hmac256(stringToUint8List(secret),
      stringToUint8List("$path$data$nonce$time$plan")));
  print("nonce: $nonce");
  print("time:  $time");
  print("sign: $sign");
  Map postBody = {'d': data, 't': time, 'n': nonce, 'p': plan, 's': sign};
  print("请求方法: $path 参数: $postBody");
  final response = await http.post(
    Uri.parse("$domain$path"),
    body: jsonEncode(postBody),
    headers: {'Authorization': token},
  );
  Map map = jsonDecode(response.body);
  int c = map['c'];
  if (c != 200) {
    if (c >= 400 && c < 500) {
      throw Exception("令牌校验失败或已过期");
    }
    throw Exception(map['m']);
  }
  String d = map['d'];
  String n = map['n'];
  int t = map['t'];
  int p = map['p'];
  String s = map['s'];
  String checkSign = base64Encode(
      hmac256(stringToUint8List(secret), stringToUint8List("$path$d$n$t$p")));
  if (checkSign != s) {
    throw Exception("响应数据验签失败");
  }
  if (p == 0) {
    map = jsonDecode(utf8.decode(base64Decode(d)));
  } else if (p == 1) {
    map = jsonDecode(await aesDecrypt(d, secret));
  } else {
    throw Exception("无效的加密计划");
  }
  print("响应结果: $map");
  return map;
}
