<?php

declare(strict_types=1);

// Dependency-free test runner: php tests/run.php  (set VPQC_LIBRARY to libvpqc_ffi.so)
spl_autoload_register(function (string $class): void {
    $prefix = 'Vecter\\Vpqc\\';
    if (str_starts_with($class, $prefix)) {
        require __DIR__ . '/../src/' . substr($class, strlen($prefix)) . '.php';
    }
});

use Vecter\Vpqc\DecryptionException;
use Vecter\Vpqc\InvalidInputException;
use Vecter\Vpqc\Profile;
use Vecter\Vpqc\PublicKey;
use Vecter\Vpqc\SecretKey;
use Vecter\Vpqc\VerificationException;
use Vecter\Vpqc\Vpqc;
use Vecter\Vpqc\VpqcException;

$failures = 0;
$count = 0;

function check(bool $cond, string $what): void
{
    global $failures, $count;
    $count++;
    if (!$cond) {
        $failures++;
        fwrite(STDERR, "FAIL: $what\n");
    }
}

function throws(string $class, callable $fn, string $what): void
{
    try {
        $fn();
        check(false, "$what (no exception)");
    } catch (Throwable $e) {
        check($e instanceof $class, "$what (got " . get_class($e) . ': ' . $e->getMessage() . ')');
    }
}

check(Vpqc::abiVersion() >> 16 === 1, 'abi version');

foreach (Profile::cases() as $p) {
    $k = Vpqc::generateEncryptionKeypair($p);
    $sealed = Vpqc::seal($k->public, 'secret', 'ctx');
    check(Vpqc::open($k->secret, $sealed, 'ctx') === 'secret', "encrypt round trip {$p->name}");

    $s = Vpqc::generateSigningKeypair($p);
    $sig = Vpqc::sign($s->secret, 'msg', 'app/v1');
    Vpqc::verify($s->public, 'msg', 'app/v1', $sig);
    throws(VerificationException::class, fn () => Vpqc::verify($s->public, 'msg', 'app/v2', $sig), "wrong context {$p->name}");
    throws(VerificationException::class, fn () => Vpqc::verify($s->public, 'other', 'app/v1', $sig), "wrong message {$p->name}");
}

$a = Vpqc::generateEncryptionKeypair();
$b = Vpqc::generateEncryptionKeypair();
$sealed = Vpqc::seal($a->public, 'secret', 'one');
throws(DecryptionException::class, fn () => Vpqc::open($a->secret, $sealed, 'two'), 'wrong aad');
throws(DecryptionException::class, fn () => Vpqc::open($b->secret, $sealed, 'one'), 'wrong key');
foreach ([0, 6, 12, 500, strlen($sealed) - 1] as $i) {
    $bad = $sealed;
    $bad[$i] = chr(ord($bad[$i]) ^ 1);
    throws(VpqcException::class, fn () => Vpqc::open($a->secret, $bad, 'one'), "tamper at $i");
}

$empty = Vpqc::seal($a->public, '', '');
check(Vpqc::open($a->secret, $empty, '') === '', 'empty plaintext');

$sig = Vpqc::generateSigningKeypair();
throws(InvalidInputException::class, fn () => Vpqc::seal($sig->public, 'x'), 'signing key cannot encrypt');
throws(InvalidInputException::class, fn () => Vpqc::sign($sig->secret, 'm', str_repeat('x', 256)), 'long context');
throws(InvalidInputException::class, fn () => Vpqc::seal(PublicKey::fromBytes("\x01\x02\x03"), 'x'), 'garbage key');

$text = $a->public->toText();
check(str_starts_with($text, '-----BEGIN VPQC PUBLIC KEY-----'), 'armored public key');
check(PublicKey::fromText($text)->toBytes() === $a->public->toBytes(), 'public text round trip');
$sk = SecretKey::fromText($a->secret->toText());
check(Vpqc::open($sk, Vpqc::seal($a->public, 'x'), '') === 'x', 'secret text round trip');
throws(VpqcException::class, fn () => PublicKey::fromText($a->secret->toText()), 'secret text is not a public key');

check((string) $a->secret === 'SecretKey(<redacted>)', 'secret key __toString redacted');
ob_start();
var_dump($a->secret);
check(!str_contains(ob_get_clean(), 'bytes'), 'var_dump does not leak the key');
$a->secret->destroy();
throws(LogicException::class, fn () => Vpqc::open($a->secret, $sealed, 'one'), 'destroyed key unusable');

$big = random_bytes(1 << 20);
$k = Vpqc::generateEncryptionKeypair();
check(Vpqc::open($k->secret, Vpqc::seal($k->public, $big)) === $big, 'large message');

echo "php: $count checks, $failures failures\n";
exit($failures === 0 ? 0 : 1);
