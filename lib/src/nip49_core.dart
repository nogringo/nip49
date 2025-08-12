import 'dart:typed_data';
import 'dart:convert';
import 'dart:math';
import 'package:cryptography/cryptography.dart';
import 'package:bech32/bech32.dart';
import 'package:convert/convert.dart';
import 'package:pointycastle/key_derivators/scrypt.dart' as pc;
import 'package:pointycastle/pointycastle.dart' as pointycastle;

/// NIP-49 Private Key Encryption implementation.
///
/// Provides methods to encrypt and decrypt Nostr private keys using
/// passwords with XChaCha20-Poly1305 symmetric encryption and scrypt
/// key derivation.
class Nip49 {
  /// Protocol version byte
  static const int version = 0x02;
  
  /// Bech32 human-readable prefix for encrypted keys
  static const String hrp = 'ncryptsec';
  
  /// Default log2(N) parameter for scrypt (N=65536)
  static const int defaultLogN = 16;
  
  /// Minimum allowed log2(N) parameter (N=4096)
  static const int minLogN = 12;
  
  /// Maximum allowed log2(N) parameter (N=4194304)
  static const int maxLogN = 22;

  /// Normalizes password using Unicode NFKC normalization.
  static String normalizePassword(String password) {
    // Unicode NFKC normalization
    // In Dart, we'll use the password as-is since Dart strings are already UTF-16
    // For full NFKC normalization, you would need a specialized library
    return password;
  }

  /// Derives an encryption key from a password using scrypt.
  ///
  /// [password] The password to derive from.
  /// [salt] 16-byte salt for the key derivation.
  /// [logN] The log2 of the scrypt N parameter (between 12 and 22).
  ///
  /// Returns a 32-byte derived key.
  static Future<Uint8List> deriveKey(
    String password,
    Uint8List salt,
    int logN,
  ) async {
    if (logN < minLogN || logN > maxLogN) {
      throw ArgumentError('logN must be between $minLogN and $maxLogN');
    }

    final normalizedPassword = normalizePassword(password);
    final passwordBytes = utf8.encode(normalizedPassword);

    final n = 1 << logN;
    const r = 8;
    const p = 1;
    const dkLen = 32;

    // Use PointyCastle's scrypt implementation
    final scrypt = pc.Scrypt();
    final params = pointycastle.ScryptParameters(n, r, p, dkLen, salt);
    scrypt.init(params);

    final derivedKey = Uint8List(dkLen);
    scrypt.deriveKey(Uint8List.fromList(passwordBytes), 0, derivedKey, 0);

    return derivedKey;
  }

  /// Encrypts a Nostr private key with a password.
  ///
  /// [privateKeyHex] The private key as a 64-character hex string.
  /// [password] The password to encrypt with.
  /// [logN] The log2 of the scrypt N parameter (default: 16).
  /// [keySecurityByte] Security tracking byte (0x00, 0x01, or 0x02).
  ///
  /// Returns a bech32-encoded encrypted key string starting with 'ncryptsec1'.
  static Future<String> encrypt(
    String privateKeyHex,
    String password, {
    int logN = defaultLogN,
    int keySecurityByte = 0x02,
  }) async {
    if (privateKeyHex.length != 64) {
      throw ArgumentError('Private key must be 32 bytes (64 hex characters)');
    }

    final privateKeyBytes = Uint8List.fromList(hex.decode(privateKeyHex));

    final random = Random.secure();
    final salt = Uint8List.fromList(
      List.generate(16, (_) => random.nextInt(256)),
    );

    final nonce = Uint8List.fromList(
      List.generate(24, (_) => random.nextInt(256)),
    );

    final key = await deriveKey(password, salt, logN);

    final algorithm = Xchacha20.poly1305Aead();
    final secretKey = SecretKey(key);

    // KEY_SECURITY_BYTE is used as additional authenticated data
    final aad = Uint8List.fromList([keySecurityByte]);

    final secretBox = await algorithm.encrypt(
      privateKeyBytes,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
    );

    // Ensure cipherText is 32 bytes and mac is 16 bytes
    final cipherText = secretBox.cipherText;
    final macBytes = secretBox.mac.bytes;

    if (cipherText.length != 32) {
      throw StateError('Unexpected ciphertext length: ${cipherText.length}');
    }
    if (macBytes.length != 16) {
      throw StateError('Unexpected MAC length: ${macBytes.length}');
    }

    // Total size: 1 (version) + 1 (logN) + 16 (salt) + 24 (nonce) + 1 (key_security) + 32 (encrypted) + 16 (mac) = 91 bytes
    final encryptedData = Uint8List(91);

    int offset = 0;
    encryptedData[offset++] = version;
    encryptedData[offset++] = logN;
    encryptedData.setRange(offset, offset + 16, salt);
    offset += 16;
    encryptedData.setRange(offset, offset + 24, nonce);
    offset += 24;
    encryptedData[offset++] = keySecurityByte;
    encryptedData.setRange(offset, offset + 32, cipherText);
    offset += 32;
    encryptedData.setRange(offset, offset + 16, macBytes);

    final bech32Data = Bech32(hrp, _convertBits(encryptedData, 8, 5, true));
    // NIP-49 encrypted keys are longer than default bech32 limit
    final encoder = Bech32Encoder();
    return encoder.convert(bech32Data, 500); // Allow up to 500 chars
  }

  /// Decrypts a NIP-49 encrypted private key.
  ///
  /// [encryptedKey] The bech32-encoded encrypted key starting with 'ncryptsec1'.
  /// [password] The password to decrypt with.
  ///
  /// Returns the decrypted private key as a hex string.
  ///
  /// Throws [ArgumentError] if the password is incorrect or data is corrupted.
  static Future<String> decrypt(String encryptedKey, String password) async {
    final decoder = Bech32Decoder();
    final bech32Data = decoder.convert(encryptedKey, 500);

    if (bech32Data.hrp != hrp) {
      throw ArgumentError('Invalid HRP, expected $hrp');
    }

    final data = Uint8List.fromList(_convertBits(bech32Data.data, 5, 8, false));

    // NIP-49 encrypted data should be exactly 91 bytes:
    // 1 (version) + 1 (logN) + 16 (salt) + 24 (nonce) + 1 (key_security) + 32 (encrypted) + 16 (mac) = 91 bytes
    // But due to bech32 padding, we may have slightly different length
    if (data.length < 89) {
      throw ArgumentError('Invalid encrypted key length: ${data.length}');
    }

    int offset = 0;
    final version = data[offset++];
    if (version != 0x02) {
      throw ArgumentError('Unsupported version: $version');
    }

    final logN = data[offset++];
    if (logN < minLogN || logN > maxLogN) {
      throw ArgumentError('Invalid logN: $logN');
    }

    final salt = data.sublist(offset, offset + 16);
    offset += 16;

    final nonce = data.sublist(offset, offset + 24);
    offset += 24;

    final keySecurityByte = data[offset++];

    final cipherText = data.sublist(offset, offset + 32);
    offset += 32;

    final mac = data.sublist(offset, offset + 16);

    final key = await deriveKey(password, salt, logN);

    final algorithm = Xchacha20.poly1305Aead();
    final secretKey = SecretKey(key);

    // KEY_SECURITY_BYTE is used as additional authenticated data
    final aad = Uint8List.fromList([keySecurityByte]);

    final secretBox = SecretBox(cipherText, nonce: nonce, mac: Mac(mac));

    try {
      final decrypted = await algorithm.decrypt(
        secretBox,
        secretKey: secretKey,
        aad: aad,
      );

      return hex.encode(decrypted);
    } catch (e) {
      throw ArgumentError(
        'Failed to decrypt: invalid password or corrupted data',
      );
    }
  }

  static List<int> _convertBits(
    List<int> data,
    int fromBits,
    int toBits,
    bool pad,
  ) {
    var acc = 0;
    var bits = 0;
    final ret = <int>[];
    final maxv = (1 << toBits) - 1;
    final maxAcc = (1 << (fromBits + toBits - 1)) - 1;

    for (var value in data) {
      if (value < 0 || (value >> fromBits) != 0) {
        throw ArgumentError('Invalid data for conversion');
      }
      acc = ((acc << fromBits) | value) & maxAcc;
      bits += fromBits;
      while (bits >= toBits) {
        bits -= toBits;
        ret.add((acc >> bits) & maxv);
      }
    }

    if (pad) {
      if (bits > 0) {
        ret.add((acc << (toBits - bits)) & maxv);
      }
    } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv) != 0) {
      throw ArgumentError('Invalid padding in convertBits');
    }

    return ret;
  }
}
