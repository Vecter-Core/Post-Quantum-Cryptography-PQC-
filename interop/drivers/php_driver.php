<?php

declare(strict_types=1);

// PHP driver for the interoperability suite. See interop/run.sh.
spl_autoload_register(function (string $class): void {
    $prefix = 'Vecter\\Vpqc\\';
    if (str_starts_with($class, $prefix)) {
        require __DIR__ . '/../../bindings/php/src/' . substr($class, strlen($prefix)) . '.php';
    }
});

use Vecter\Vpqc\Profile;
use Vecter\Vpqc\PublicKey;
use Vecter\Vpqc\SecretKey;
use Vecter\Vpqc\Vpqc;
use Vecter\Vpqc\VpqcException;

$a = array_slice($argv, 1);
$cmd = array_shift($a);
try {
    switch ($cmd) {
        case 'keygen': // keygen encrypt|sign PROFILE_NAME OUT_PREFIX
            $p = match ($a[1]) {
                'standard' => Profile::Standard,
                'fast-auth' => Profile::FastAuth,
                'cnsa2' => Profile::Cnsa2,
                'high' => Profile::High,
            };
            $kp = $a[0] === 'encrypt' ? Vpqc::generateEncryptionKeypair($p) : Vpqc::generateSigningKeypair($p);
            file_put_contents($a[2] . '.pub', $kp->public->toText());
            file_put_contents($a[2] . '.sec', $kp->secret->toText());
            break;
        case 'seal': // seal PUBFILE AAD IN OUT
            file_put_contents($a[3], Vpqc::seal(PublicKey::fromText(file_get_contents($a[0])), file_get_contents($a[2]), $a[1]));
            break;
        case 'open': // open SECFILE AAD IN OUT
            file_put_contents($a[3], Vpqc::open(SecretKey::fromText(file_get_contents($a[0])), file_get_contents($a[2]), $a[1]));
            break;
        case 'sign': // sign SECFILE CTX IN OUT
            file_put_contents($a[3], Vpqc::sign(SecretKey::fromText(file_get_contents($a[0])), file_get_contents($a[2]), $a[1]));
            break;
        case 'verify': // verify PUBFILE CTX SIG IN
            Vpqc::verify(PublicKey::fromText(file_get_contents($a[0])), file_get_contents($a[3]), $a[1], file_get_contents($a[2]));
            break;
        case 'encrypt-file': // encrypt-file PUBFILE AAD IN OUT
            Vpqc::encryptFile(PublicKey::fromText(file_get_contents($a[0])), $a[2], $a[3], $a[1]);
            break;
        case 'decrypt-file': // decrypt-file SECFILE AAD IN OUT
            Vpqc::decryptFile(SecretKey::fromText(file_get_contents($a[0])), $a[2], $a[3], $a[1]);
            break;
        default:
            throw new InvalidArgumentException("unknown command $cmd");
    }
} catch (VpqcException | InvalidArgumentException $e) {
    fwrite(STDERR, 'php-driver: ' . $e->getMessage() . "\n");
    exit(1);
}
