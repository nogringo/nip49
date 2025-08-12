import 'package:nip49/nip49.dart';
import 'package:test/test.dart';

void main() {
  group('NIP-49 Encryption/Decryption', () {
    test('Decrypt NIP-49 specification test vector', () async {
      // Test vector from NIP-49 specification
      final encryptedKey =
          'ncryptsec1qgg9947rlpvqu76pj5ecreduf9jxhselq2nae2kghhvd5g7dgjtcxfqtd67p9m0w57lspw8gsq6yphnm8623nsl8xn9j4jdzz84zm3frztj3z7s35vpzmqf6ksu8r89qk5z2zxfmu5gv8th8wclt0h4p';
      final password = 'nostr';
      final expectedPrivateKey =
          '3501454135014541350145413501453fefb02227e449e57cf4d3a3ce05378683';

      final decrypted = await Nip49.decrypt(encryptedKey, password);
      expect(decrypted, equals(expectedPrivateKey));
    });

    test('Encrypt and decrypt NIP-49 test vector private key', () async {
      // Use the same private key and password from the test vector
      final privateKey =
          '3501454135014541350145413501453fefb02227e449e57cf4d3a3ce05378683';
      final password = 'nostr';

      // Encrypt with same parameters as test vector
      final encrypted = await Nip49.encrypt(privateKey, password, logN: 16);

      expect(encrypted, startsWith('ncryptsec1'));
      expect(encrypted.length, equals(162));

      // Verify we can decrypt our own encryption
      final decrypted = await Nip49.decrypt(encrypted, password);
      expect(decrypted, equals(privateKey));
    });
  });
}
