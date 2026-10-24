<?php

declare(strict_types=1);

namespace Ivmia\Totp;

/**
 * Time-based one-time passwords (RFC 6238) with no dependencies.
 *
 * Defaults match what authenticator apps expect: base32 secret, HMAC-SHA1,
 * 6 digits, 30-second step. Verification accepts one step of drift in each
 * direction and returns the matching counter so the caller can store it and
 * refuse the same code twice.
 */
final class Totp
{
    private const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    public const STEP = 30;
    public const DIGITS = 6;

    /** A fresh secret: 20 random bytes, base32 encoded (32 characters). */
    public static function secret(): string
    {
        return self::base32Encode(random_bytes(20));
    }

    /** The code for the given moment (defaults to now). */
    public static function code(string $secret, ?int $time = null): string
    {
        return self::at($secret, intdiv($time ?? time(), self::STEP));
    }

    /**
     * Verify a code typed by the user.
     *
     * Returns the counter that matched, or null if nothing matched. Store the
     * returned counter and pass it back as $lastUsed next time: counters at or
     * below it are skipped, so a captured code cannot be replayed.
     *
     * @param int $lastUsed  counter accepted on the previous successful login
     * @param int $window    steps of clock drift tolerated on each side
     */
    public static function verify(string $secret, string $code, int $lastUsed = 0, int $window = 1, ?int $time = null): ?int
    {
        $code = preg_replace('/\D+/', '', $code) ?? '';
        if (strlen($code) !== self::DIGITS) {
            return null;
        }
        $now = intdiv($time ?? time(), self::STEP);
        for ($d = -$window; $d <= $window; $d++) {
            $counter = $now + $d;
            if ($counter <= $lastUsed) {
                continue;
            }
            if (hash_equals(self::at($secret, $counter), $code)) {
                return $counter;
            }
        }
        return null;
    }

    /** otpauth:// URI for the authenticator app (render it as a QR code or show it as text). */
    public static function uri(string $secret, string $account, string $issuer): string
    {
        return 'otpauth://totp/' . rawurlencode($issuer . ':' . $account)
             . '?secret=' . $secret
             . '&issuer=' . rawurlencode($issuer)
             . '&algorithm=SHA1&digits=' . self::DIGITS . '&period=' . self::STEP;
    }

    /** The secret in groups of four, easier to type by hand. */
    public static function pretty(string $secret): string
    {
        return trim(chunk_split($secret, 4, ' '));
    }

    /**
     * Single-use recovery codes, formatted XXXXX-XXXXX. The alphabet leaves out
     * 0/O and 1/I so a printed code is not misread.
     *
     * @return string[]
     */
    public static function recoveryCodes(int $count = 8): array
    {
        $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
        $out = [];
        for ($i = 0; $i < $count; $i++) {
            $raw = '';
            for ($j = 0; $j < 10; $j++) {
                $raw .= $alphabet[random_int(0, strlen($alphabet) - 1)];
            }
            $out[] = substr($raw, 0, 5) . '-' . substr($raw, 5);
        }
        return $out;
    }

    /**
     * Hash of a recovery code for storage. Only hashes are kept; compare with
     * hash_equals(). $pepper is an application-wide constant that keeps a
     * leaked hash list from being matched against another application's.
     */
    public static function recoveryHash(string $code, string $pepper = ''): string
    {
        $code = strtoupper(preg_replace('/[^A-Za-z0-9]/', '', $code) ?? '');
        return hash('sha256', $pepper . '|' . $code);
    }

    private static function at(string $secret, int $counter): string
    {
        $key  = self::base32Decode($secret);
        $msg  = pack('N*', 0) . pack('N*', $counter);
        $hash = hash_hmac('sha1', $msg, $key, true);
        $off  = ord($hash[19]) & 0x0F;
        $bin  = ((ord($hash[$off]) & 0x7F) << 24)
              | ((ord($hash[$off + 1]) & 0xFF) << 16)
              | ((ord($hash[$off + 2]) & 0xFF) << 8)
              | (ord($hash[$off + 3]) & 0xFF);
        return str_pad((string) ($bin % (10 ** self::DIGITS)), self::DIGITS, '0', STR_PAD_LEFT);
    }

    public static function base32Encode(string $bytes): string
    {
        $bits = '';
        foreach (str_split($bytes) as $char) {
            $bits .= str_pad(decbin(ord($char)), 8, '0', STR_PAD_LEFT);
        }
        $out = '';
        foreach (str_split($bits, 5) as $chunk) {
            $out .= self::ALPHABET[bindec(str_pad($chunk, 5, '0', STR_PAD_RIGHT))];
        }
        return $out;
    }

    public static function base32Decode(string $encoded): string
    {
        $encoded = strtoupper(preg_replace('/[^A-Za-z2-7]/', '', $encoded) ?? '');
        $bits = '';
        foreach (str_split($encoded) as $char) {
            $index = strpos(self::ALPHABET, $char);
            if ($index === false) {
                continue;
            }
            $bits .= str_pad(decbin($index), 5, '0', STR_PAD_LEFT);
        }
        $out = '';
        foreach (str_split($bits, 8) as $chunk) {
            if (strlen($chunk) === 8) {
                $out .= chr(bindec($chunk));
            }
        }
        return $out;
    }
}
