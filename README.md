NIP-49 Private Key Encryption for Nostr protocol - encrypt/decrypt private keys with passwords.

## Examples

### Encrypt

```dart
import 'package:nip49/nip49.dart';

final privateKey = '7f3b34c7a7a42f3d7b8b5e1a2c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d';
final password = 'mysecurepassword';

final encrypted = await Nip49.encrypt(privateKey, password);
print(encrypted);
// ncryptsec1qgg...
```

### Decrypt

```dart
import 'package:nip49/nip49.dart';

final encryptedKey = 'ncryptsec1qgg9947rlpvqu76pj5ecreduf9jxhselq2nae2kghhvd5g7dgjtcxfqtd67p9m0w57lspw8gsq6yphnm8623nsl8xn9j4jdzz84zm3frztj3z7s35vpzmqf6ksu8r89qk5z2zxfmu5gv8th8wclt0h4p';
final password = 'nostr';

final privateKey = await Nip49.decrypt(encryptedKey, password);
print(privateKey);
// 3501454135014541350145413501453fefb02227e449e57cf4d3a3ce05378683
```

## My Nostr for contact and donation

https://njump.me/npub1kg4sdvz3l4fr99n2jdz2vdxe2mpacva87hkdetv76ywacsfq5leqquw5te
