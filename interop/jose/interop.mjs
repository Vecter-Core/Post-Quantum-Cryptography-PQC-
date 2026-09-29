// vpqc CLI <-> panva/jose (Node.js >= 24.7 WebCrypto ML-DSA, backed by OpenSSL), both directions:
// keys (JWK derivation from the seed, thumbprints), JWS and JWT. Usage: node interop.mjs <vpqc>
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as jose from 'jose';

const VPQC = process.argv[2];
const ROUNDS = Number(process.env.ROUNDS ?? 5);
const dir = mkdtempSync(join(tmpdir(), 'vpqc-jose-'));
const enc = new TextEncoder();
let checks = 0, failures = 0;

const raw = (args, input) => execFileSync(VPQC, args, { input, stdio: ['pipe', 'pipe', 'pipe'] }).toString();
const vpqc = (args, input) => raw(args, input).trim();
const vpqcFails = (args, input) => { try { vpqc(args, input); return false; } catch { return true; } };
function check(ok, what) { checks++; if (!ok) { failures++; console.error('FAIL', what); } }
const file = (name, text) => { const p = join(dir, name); writeFileSync(p, text); return p; };

try {
  for (const alg of ['ML-DSA-65', 'ML-DSA-87']) {
    for (let r = 0; r < ROUNDS; r++) {
      // jose key -> vpqc: same public key derived from the seed, same thumbprint.
      const { publicKey, privateKey } = await jose.generateKeyPair(alg, { extractable: true });
      const jPriv = await jose.exportJWK(privateKey);
      const jPub = await jose.exportJWK(publicKey);
      const privPath = file('j-priv.jwk', JSON.stringify(jPriv));
      const pubPath = file('j-pub.jwk', JSON.stringify(jPub));
      const derived = JSON.parse(vpqc(['jwk', 'public', privPath]));
      check(derived.pub === jPub.pub && derived.alg === alg && derived.kty === 'AKP', `${alg} seed -> public key`);
      const tp = await jose.calculateJwkThumbprint(jPub);
      check(vpqc(['jwk', 'thumbprint', pubPath]) === tp, `${alg} thumbprint`);

      // jose JWS -> vpqc verify.
      const payload = `payload ${r} ${'x'.repeat(r * 37)}`;
      const jws = await new jose.CompactSign(enc.encode(payload)).setProtectedHeader({ alg, kid: tp }).sign(privateKey);
      check(raw(['jws', 'verify', '--key', pubPath], jws) === payload, `${alg} jose JWS -> vpqc`);
      const tampered = jws.slice(0, -8) + (jws.at(-8) === 'A' ? 'B' : 'A') + jws.slice(-7);
      check(vpqcFails(['jws', 'verify', '--key', pubPath], tampered), `${alg} vpqc rejects tampered jose JWS`);

      // jose JWT -> vpqc verify (issuer, audience, typ).
      const jwt = await new jose.SignJWT({ sub: 'alice', scope: 'read' })
        .setProtectedHeader({ alg, typ: 'JWT' }).setIssuer('https://idp.example')
        .setAudience('api').setIssuedAt().setExpirationTime('5m').sign(privateKey);
      const claims = JSON.parse(vpqc(['jwt', 'verify', '--key', pubPath, '--iss', 'https://idp.example', '--aud', 'api'], jwt));
      check(claims.sub === 'alice' && claims.scope === 'read', `${alg} jose JWT -> vpqc`);
      check(vpqcFails(['jwt', 'verify', '--key', pubPath, '--aud', 'other'], jwt), `${alg} vpqc rejects wrong audience`);
      const expired = await new jose.SignJWT({}).setProtectedHeader({ alg }).setExpirationTime(Math.floor(Date.now() / 1000) - 3600).sign(privateKey);
      check(vpqcFails(['jwt', 'verify', '--key', pubPath], expired), `${alg} vpqc rejects expired jose JWT`);

      // vpqc key -> jose: import both JWKs, same thumbprint.
      const vPrivPath = join(dir, `v-priv-${alg}-${r}.jwk`);
      const vPub = JSON.parse(vpqc(['jwk', 'generate', '--alg', alg, '--out', vPrivPath]));
      const vPriv = JSON.parse(readFileSync(vPrivPath, 'utf8'));
      const vPubPath = file('v-pub.jwk', JSON.stringify(vPub));
      const jImportedPub = await jose.importJWK(vPub, alg);
      const jImportedPriv = await jose.importJWK(vPriv, alg);
      check(vPriv.pub === vPub.pub, `${alg} vpqc private JWK carries pub`);
      check(await jose.calculateJwkThumbprint(vPub) === vpqc(['jwk', 'thumbprint', vPubPath]), `${alg} vpqc thumbprint`);

      // vpqc JWS -> jose verify.
      const vJws = vpqc(['jws', 'sign', '--key', vPrivPath], payload);
      const { payload: got, protectedHeader } = await jose.compactVerify(vJws, jImportedPub);
      check(new TextDecoder().decode(got) === payload && protectedHeader.alg === alg, `${alg} vpqc JWS -> jose`);

      // vpqc JWT -> jose jwtVerify.
      const vJwt = vpqc(['jwt', 'sign', '--key', vPrivPath, '--ttl', '120'], JSON.stringify({ sub: 'bob', aud: 'api', iss: 'vpqc' }));
      const { payload: c, protectedHeader: h } = await jose.jwtVerify(vJwt, jImportedPub, { issuer: 'vpqc', audience: 'api', typ: 'JWT' });
      check(c.sub === 'bob' && c.exp - c.iat === 120 && h.kid === vpqc(['jwk', 'thumbprint', vPubPath]), `${alg} vpqc JWT -> jose`);

      // A token signed by jose with the vpqc-generated private key verifies in vpqc (key import).
      const cross = await new jose.CompactSign(enc.encode('cross')).setProtectedHeader({ alg }).sign(jImportedPriv);
      check(raw(['jws', 'verify', '--key', vPubPath], cross) === 'cross', `${alg} jose signs with vpqc key`);
    }
  }
} finally {
  rmSync(dir, { recursive: true, force: true });
}
console.log(`jose interop: ${checks} checks, ${failures} failures`);
process.exit(failures ? 1 : 0);
