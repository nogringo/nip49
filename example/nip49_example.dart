import 'package:nip49/nip49.dart';

void main() async {
  final privateKey =
      '7f3b34c7a7a42f3d7b8b5e1a2c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d';
  final password = 'mysecurepassword';

  print('NIP-49 Private Key Encryption Example');
  print('=====================================\n');

  print('Original private key:');
  print(privateKey);
  print('');

  print('Encrypting with password: "$password"');
  final encrypted = await Nip49.encrypt(privateKey, password);
  print('Encrypted key:');
  print(encrypted);
  print('');

  print('Decrypting...');
  final decrypted = await Nip49.decrypt(encrypted, password);
  print('Decrypted private key:');
  print(decrypted);
  print('');

  print('Verification: ${decrypted == privateKey ? "✓ Success" : "✗ Failed"}');
  print('');

  print(
    'Encrypting with custom parameters (logN=14 for faster computation)...',
  );
  final encryptedFast = await Nip49.encrypt(privateKey, password, logN: 14);
  print('Encrypted key (fast):');
  print(encryptedFast);
  print('');

  print(
    'Note: Each encryption produces a different result due to random nonce.',
  );
  final encrypted2 = await Nip49.encrypt(privateKey, password);
  print('Second encryption of same key:');
  print(encrypted2);
  print('Different: ${encrypted != encrypted2}');

  print('\nTrying with wrong password...');
  try {
    await Nip49.decrypt(encrypted, 'wrongpassword');
    print('Should not reach here!');
  } catch (e) {
    print(
      '✓ Correctly failed with wrong password: ${e.toString().split(':')[0]}',
    );
  }
}
