# ivmia/totp

Time-based one-time passwords (RFC 6238) for PHP 8.1+, in one file, with no dependencies.

Works with Google Authenticator, Microsoft Authenticator, Authy, 1Password and any other app that reads an `otpauth://` URI. Written for the admin panel of our own sites; published because every small PHP project seems to need the same 150 lines.

## Install

```
composer require ivmia/totp
```

Or copy `src/Totp.php` into your project and `require` it. There is nothing else.

## Enrol a user

```php
use Ivmia\Totp\Totp;

$secret = Totp::secret();                                  // store this with the user, encrypted at rest if you can
$uri    = Totp::uri($secret, 'alice@example.com', 'My App'); // render as a QR code, or show Totp::pretty($secret)

// ask the user to type the first code before you switch 2FA on
if (Totp::verify($secret, $_POST['code']) === null) {
    // wrong code, do not enable
}
```

## Check a code at login

```php
$counter = Totp::verify($secret, $_POST['code'], $user->totp_last_counter);

if ($counter === null) {
    // reject
} else {
    $user->totp_last_counter = $counter;   // persist it: the same code will not pass again
}
```

`verify()` accepts one 30-second step of clock drift in each direction (`$window = 1`). Pass the counter it returned back in as `$lastUsed` on the next attempt and codes at or below it are refused, which closes the replay window.

## Recovery codes

```php
$codes  = Totp::recoveryCodes();                                        // 8 codes like 7KQ4M-2XWRT, show once
$hashes = array_map(fn ($c) => Totp::recoveryHash($c, APP_PEPPER), $codes); // store only these

// later
$given = Totp::recoveryHash($_POST['recovery'], APP_PEPPER);
foreach ($hashes as $i => $h) {
    if (hash_equals($h, $given)) {
        unset($hashes[$i]);   // single use
        // accept
    }
}
```

`APP_PEPPER` is any constant string private to your application. It stops a leaked hash list from being matched against another application's codes.

## API

| Method | Purpose |
| --- | --- |
| `secret()` | New base32 secret, 20 random bytes |
| `code($secret, $time = null)` | Current code (or the code for a given Unix time) |
| `verify($secret, $code, $lastUsed = 0, $window = 1)` | Matching counter or `null` |
| `uri($secret, $account, $issuer)` | `otpauth://totp/...` for authenticator apps |
| `pretty($secret)` | Secret grouped in fours for manual entry |
| `recoveryCodes($count = 8)` | Single-use backup codes |
| `recoveryHash($code, $pepper)` | SHA-256 of a normalised code, for storage |
| `base32Encode()` / `base32Decode()` | RFC 4648 base32 without padding |

Fixed parameters: HMAC-SHA1, 6 digits, 30-second step. These are what authenticator apps assume; the class does not try to be configurable.

## Tests

```
php tests/run.php
```

Checks the RFC 6238 appendix B vectors, drift and replay handling, base32 round trips and recovery code shape. No test framework needed.

## License

MIT, see `LICENSE`.
