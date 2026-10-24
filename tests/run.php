<?php

declare(strict_types=1);

// Plain test runner, no framework needed: php tests/run.php

require __DIR__ . '/../src/Totp.php';

use Ivmia\Totp\Totp;

$failures = 0;
$check = static function (string $name, bool $ok) use (&$failures): void {
    echo ($ok ? 'ok   ' : 'FAIL ') . $name . PHP_EOL;
    if (!$ok) {
        $failures++;
    }
};

// RFC 6238 appendix B vectors (SHA1, secret "12345678901234567890"); the RFC
// lists 8 digits, we compare the trailing 6.
$secret = Totp::base32Encode('12345678901234567890');
$vectors = [
    59          => '287082',
    1111111109  => '081804',
    1111111111  => '050471',
    1234567890  => '005924',
    2000000000  => '279037',
    20000000000 => '353130',
];
foreach ($vectors as $time => $expected) {
    $check("rfc6238 vector t=$time", Totp::code($secret, $time) === $expected);
}

// base32 round trip
$bytes = random_bytes(20);
$check('base32 round trip', Totp::base32Decode(Totp::base32Encode($bytes)) === $bytes);
$check('base32 ignores spaces and case', Totp::base32Decode(strtolower(Totp::pretty(Totp::base32Encode($bytes)))) === $bytes);

// secret shape
$s = Totp::secret();
$check('secret is 32 base32 chars', (bool) preg_match('/^[A-Z2-7]{32}$/', $s));
$check('secret decodes to 20 bytes', strlen(Totp::base32Decode($s)) === 20);

// verify: current code passes, counter comes back
$now = time();
$counter = Totp::verify($s, Totp::code($s, $now), 0, 1, $now);
$check('verify accepts current code', $counter === intdiv($now, Totp::STEP));

// verify: drift of one step each way passes, two steps fails
$check('verify accepts previous step', Totp::verify($s, Totp::code($s, $now - 30), 0, 1, $now) !== null);
$check('verify accepts next step', Totp::verify($s, Totp::code($s, $now + 30), 0, 1, $now) !== null);
$check('verify rejects two steps back', Totp::verify($s, Totp::code($s, $now - 60), 0, 1, $now) === null);

// verify: replay refused once the counter is stored
$check('verify refuses replayed code', Totp::verify($s, Totp::code($s, $now), (int) $counter, 1, $now) === null);

// verify: formatting and garbage
$check('verify tolerates "123 456" formatting', Totp::verify($s, substr_replace(Totp::code($s, $now), ' ', 3, 0), 0, 1, $now) !== null);
$check('verify rejects wrong length', Totp::verify($s, '12345', 0, 1, $now) === null);
$check('verify rejects wrong code', Totp::verify($s, '000000', 0, 1, $now) === null || Totp::code($s, $now) === '000000');

// uri
$uri = Totp::uri($s, 'alice@example.com', 'Example Corp');
$check('uri has issuer and secret', str_starts_with($uri, 'otpauth://totp/Example%20Corp%3Aalice%40example.com?secret=' . $s . '&issuer=Example%20Corp'));

// recovery codes
$codes = Totp::recoveryCodes();
$check('8 recovery codes', count($codes) === 8);
$check('recovery code shape', count(array_filter($codes, static fn ($c) => preg_match('/^[A-HJ-NP-Z2-9]{5}-[A-HJ-NP-Z2-9]{5}$/', $c) === 1)) === 8);
$check('recovery codes unique', count(array_unique($codes)) === 8);
$check('recovery hash ignores dash and case', Totp::recoveryHash(strtolower($codes[0]), 'p') === Totp::recoveryHash(str_replace('-', '', $codes[0]), 'p'));
$check('recovery hash depends on pepper', Totp::recoveryHash($codes[0], 'a') !== Totp::recoveryHash($codes[0], 'b'));

echo PHP_EOL . ($failures === 0 ? 'All tests passed.' : "$failures test(s) failed.") . PHP_EOL;
exit($failures === 0 ? 0 : 1);
