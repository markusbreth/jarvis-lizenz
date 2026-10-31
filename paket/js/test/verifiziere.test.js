// Eingespeiste Prüfung (seit 0.2.1) — JS-Einheitsfälle.
//
// Nicht im gemeinsamen Prüfstand: die Option gibt es nur in JS, denn nur dort
// kann ein vorgeladenes Paket node:crypto umbiegen, bevor der Kern lädt. Der
// Prüfstand (faelle/*.json) bleibt unverändert und belegt „ohne Option wie 0.2.0".
//
// Der Kern unter Prüfung ist `../src/index.js`, oder `JARVIS_LIZENZ_KERN`
// (absoluter Pfad) — das ist die Naht für Gegenprobe und Mutationen.
//
// Als echte Prüfung dient eine reine Ed25519-Referenz nach RFC 8032 §5.1.7
// (BigInt, cofaktorlos), damit weder der Kern noch die Tests eine Abhängigkeit
// brauchen. Sie wird unten gegen die RFC-Vektoren und gegen node:crypto gehalten
// — ohne diese Kontrolle bewiese ein grüner Fall nur, dass zwei Dinge desselben
// Autors zueinander passen.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const crypto = require('node:crypto');

const KERN = process.env.JARVIS_LIZENZ_KERN || path.join(__dirname, '..', 'src', 'index.js');

// ── Reine Ed25519-Prüfung (nur für die Tests) ──────────────────────────────
// SHA-512 aus node:crypto ist hier erlaubt: gezählt und gebogen werden nur
// `verify` und `createPublicKey`, die Wege, über die der Kern prüft.
const sha512 = crypto.createHash.bind(null, 'sha512');
const P = 2n ** 255n - 19n;
const L = 2n ** 252n + 27742317777372353535851937790883648493n;
const mod = (a, m = P) => ((a % m) + m) % m;
function pot(b, e, m = P) {
  let r = 1n; b = mod(b, m);
  for (; e > 0n; e >>= 1n, b = (b * b) % m) if (e & 1n) r = (r * b) % m;
  return r;
}
const inv = (a) => pot(a, P - 2n);
const D = mod(-121665n * inv(121666n));
const I = pot(2n, (P - 1n) / 4n);
const leZahl = (bytes) => {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]);
  return n;
};
function addiere([X1, Y1, Z1, T1], [X2, Y2, Z2, T2]) {
  const A = mod((Y1 - X1) * (Y2 - X2)), B = mod((Y1 + X1) * (Y2 + X2));
  const C = mod(T1 * 2n * D * T2), Dd = mod(Z1 * 2n * Z2);
  const E = B - A, F = Dd - C, G = Dd + C, H = B + A;
  return [mod(E * F), mod(G * H), mod(F * G), mod(E * H)];
}
function mal(s, Q) {
  let R = [0n, 1n, 1n, 0n];
  for (; s > 0n; s >>= 1n, Q = addiere(Q, Q)) if (s & 1n) R = addiere(R, Q);
  return R;
}
function punkt(bytes) {
  if (bytes.length !== 32) return null;
  const b = Uint8Array.from(bytes); const vz = b[31] >> 7; b[31] &= 0x7f;
  const y = leZahl(b);
  if (y >= P) return null;
  const u = mod(y * y - 1n), w = mod(D * y * y + 1n);
  let x = pot(mod(u * inv(w)), (P + 3n) / 8n);
  if (mod(w * x * x) !== u) {
    if (mod(w * x * x) !== mod(-u)) return null;
    x = mod(x * I);
  }
  if (x === 0n && vz === 1) return null;
  if (Number(x & 1n) !== vz) x = P - x;
  return [x, y, 1n, mod(x * y)];
}
const BY = mod(4n * inv(5n));
const BASIS = punkt(Uint8Array.from({ length: 32 }, (_, i) => Number((BY >> BigInt(8 * i)) & 0xffn)));
const gleich = ([X1, Y1, Z1], [X2, Y2, Z2]) => mod(X1 * Z2) === mod(X2 * Z1) && mod(Y1 * Z2) === mod(Y2 * Z1);

function referenz(roh, sig, schluessel) {
  if (sig.length !== 64) return false;
  const A = punkt(schluessel), R = punkt(sig.subarray(0, 32));
  if (!A || !R) return false;
  const S = leZahl(sig.subarray(32));
  if (S >= L) return false;
  const k = mod(leZahl(sha512().update(sig.subarray(0, 32)).update(schluessel).update(roh).digest()), L);
  return gleich(mal(S, BASIS), addiere(R, mal(k, A)));
}

// ── Werkstoff: Schlüssel und signierte Drähte ──────────────────────────────
const hex = (h) => Buffer.from(h, 'hex');
const b64u = (b) => Buffer.from(b).toString('base64url');
const neuerSchluessel = () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    privat: privateKey,
    pem: publicKey.export({ type: 'spki', format: 'pem' }),
    roh: new Uint8Array(publicKey.export({ type: 'spki', format: 'der' }).subarray(12)),
  };
};
const draht = (nutzlast, k) => {
  const roh = Buffer.from(JSON.stringify(nutzlast));
  return `${b64u(roh)}.${b64u(crypto.sign(null, roh, k.privat))}`;
};
const pemAus = (der) => `-----BEGIN PUBLIC KEY-----\n${Buffer.from(der).toString('base64')}\n-----END PUBLIC KEY-----\n`;

const HAUPT = neuerSchluessel();
const NAECHSTER = neuerSchluessel();
const FREMD = neuerSchluessel();
const ERNEUERUNG = neuerSchluessel();
const JETZT = new Date('2026-10-31T12:00:00Z');
const PRODUKT = 'produkt-a';
const NUTZLAST = {
  license_id: 'lic-1', product: PRODUKT,
  issued_at: '2026-10-01T00:00:00Z', expires_at: '2027-10-01T00:00:00Z',
};
const TOKEN = draht(NUTZLAST, HAUPT);
const TOKEN_FREMD = draht(NUTZLAST, FREMD);
const BERECHTIGUNG = draht({
  type: 'erneuerungs-berechtigung', pubkey: ERNEUERUNG.pem, product: PRODUKT,
  issued_at: '2026-10-01T00:00:00Z', expires_at: '2027-09-30T00:00:00Z', max_token_tage: 31,
}, HAUPT);
const TOKEN_KETTE = draht({
  license_id: 'lic-1', product: PRODUKT, berechtigung: BERECHTIGUNG,
  issued_at: '2026-10-20T00:00:00Z', expires_at: '2026-11-15T00:00:00Z',
}, ERNEUERUNG);
const MANIFEST = draht({
  type: 'license-manifest', seq: 3, valid_until: '2026-11-30T00:00:00Z',
  licenses: { 'lic-1': {} }, revoked: [],
}, HAUPT);

// ── Der Kern, geladen NACHDEM node:crypto umgebogen wurde ──────────────────
// So wie es ein vorgeladenes Paket im Kunden-Image täte: der Kern holt sich
// `verify`/`createPublicKey` beim Laden, also wird VORHER gebogen.
function gebogenerKern() {
  const echt = { verify: crypto.verify, createPublicKey: crypto.createPublicKey };
  const beruehrt = { verify: 0, createPublicKey: 0 };
  crypto.verify = () => { beruehrt.verify++; throw new Error('gebogen'); };
  crypto.createPublicKey = () => { beruehrt.createPublicKey++; throw new Error('gebogen'); };
  delete require.cache[require.resolve(KERN)];
  try {
    return { kern: require(KERN), beruehrt };
  } finally {
    Object.assign(crypto, echt);
    delete require.cache[require.resolve(KERN)];
  }
}

// Attrappe über die Referenz: zählt Aufrufe und hält fest, welcher Schlüssel kam.
function zaehlend(urteil = referenz) {
  const f = (roh, sig, schluessel) => {
    f.aufrufe.push(Buffer.from(schluessel).toString('hex'));
    return urteil(roh, sig, schluessel);
  };
  f.aufrufe = [];
  return f;
}
const hexVon = (k) => Buffer.from(k.roh).toString('hex');

// ── Die Referenz selbst — erst wenn sie stimmt, sagen die Fälle unten etwas ─

test('Referenz: RFC 8032 §7.1 TEST 1 und TEST 2, und verfälscht falsch', () => {
  const t1 = ['d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', '',
    'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'];
  const t2 = ['3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c', '72',
    '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00'];
  for (const [k, m, s] of [t1, t2]) {
    assert.equal(referenz(hex(m), hex(s), hex(k)), true);
    const kaputt = hex(s); kaputt[5] ^= 1;
    assert.equal(referenz(hex(m), kaputt, hex(k)), false);
  }
  assert.equal(referenz(hex('72'), hex(t2[2]), hex(t1[0])), false, 'fremder Schlüssel');
});

test('Referenz: einig mit node:crypto über frisch signierte Drähte', () => {
  for (const d of [TOKEN, MANIFEST, BERECHTIGUNG]) {
    const [n, s] = d.split('.').map((t) => Buffer.from(t, 'base64url'));
    assert.equal(referenz(n, s, HAUPT.roh), true);
    assert.equal(referenz(n, s, FREMD.roh), false);
  }
});

// ── Die eingespeiste Prüfung entscheidet — und nur sie ─────────────────────

test('eingespeiste Prüfung wird benutzt, node:crypto 0-mal berührt', () => {
  const { kern, beruehrt } = gebogenerKern();
  const v = zaehlend();
  const u = kern.pruefeToken(TOKEN, HAUPT.pem, PRODUKT, JETZT, { verifiziere: v });
  assert.equal(u.grund, 'ok');
  assert.equal(u.gueltig, true);
  assert.deepEqual(v.aufrufe, [hexVon(HAUPT)]);
  assert.deepEqual(beruehrt, { verify: 0, createPublicKey: 0 });
});

test('ohne Option prüft der Kern weiter über node:crypto (gebogen ⇒ ungueltig)', () => {
  const { kern, beruehrt } = gebogenerKern();
  assert.equal(kern.pruefeToken(TOKEN, HAUPT.pem, PRODUKT, JETZT).grund, 'ungueltig');
  assert.ok(beruehrt.createPublicKey + beruehrt.verify > 0, 'node:crypto wurde nicht gefragt');
  assert.equal(require(KERN).pruefeToken(TOKEN, HAUPT.pem, PRODUKT, JETZT).grund, 'ok');
});

test('KONTROLLFALL: Attrappe sagt immer false ⇒ ungueltig trotz echter Signatur', () => {
  const { kern } = gebogenerKern();
  const v = zaehlend(() => false);
  assert.equal(kern.pruefeToken(TOKEN, HAUPT.pem, PRODUKT, JETZT, { verifiziere: v }).grund, 'ungueltig');
  assert.equal(v.aufrufe.length, 1);
});

test('KONTROLLFALL: Attrappe sagt immer true ⇒ das fremde Token gilt', () => {
  const { kern } = gebogenerKern();
  const v = zaehlend(() => true);
  const u = kern.pruefeToken(TOKEN_FREMD, HAUPT.pem, PRODUKT, JETZT, { verifiziere: v });
  assert.equal(u.grund, 'ok');
  assert.equal(v.aufrufe.length, 1);
  // Gegenstück: dasselbe fremde Token mit der echten Prüfung ist ungueltig.
  assert.equal(kern.pruefeToken(TOKEN_FREMD, HAUPT.pem, PRODUKT, JETZT, { verifiziere: referenz }).grund, 'ungueltig');
});

// Diese drei zählen die Aufrufe mit: `ungueltig` allein sähe genauso aus, wenn
// die Option gar nicht gefragt und der gebogene node:crypto gescheitert wäre.
test('Rückgabe 1 zählt nicht als wahr', () => {
  const { kern } = gebogenerKern();
  const v = zaehlend(() => 1);
  assert.equal(kern.pruefeToken(TOKEN_FREMD, HAUPT.pem, PRODUKT, JETZT, { verifiziere: v }).grund, 'ungueltig');
  assert.equal(v.aufrufe.length, 1);
});

test("Rückgabe 'true' zählt nicht als wahr", () => {
  const { kern } = gebogenerKern();
  const v = zaehlend(() => 'true');
  assert.equal(kern.pruefeToken(TOKEN_FREMD, HAUPT.pem, PRODUKT, JETZT, { verifiziere: v }).grund, 'ungueltig');
  assert.equal(v.aufrufe.length, 1);
});

test('eine werfende Option ist eine falsche Signatur, kein Absturz', () => {
  const { kern, beruehrt } = gebogenerKern();
  const v = zaehlend(() => { throw new Error('x'); });
  assert.equal(kern.pruefeToken(TOKEN, HAUPT.pem, PRODUKT, JETZT, { verifiziere: v }).grund, 'ungueltig');
  const m = kern.bewerteManifest(MANIFEST, HAUPT.pem, 'lic-1', JETZT, null, { verifiziere: v });
  assert.equal(m.detail, 'signatur_falsch');
  assert.equal(v.aufrufe.length, 2);
  assert.deepEqual(beruehrt, { verify: 0, createPublicKey: 0 });
});

// ── Alle Wege: Ring mit/ohne kid, Kette, Manifest ──────────────────────────

test('Ring mit kid: genau der Schlüssel des kid wird gefragt', () => {
  const { kern, beruehrt } = gebogenerKern();
  const v = zaehlend();
  const t = draht({ ...NUTZLAST, kid: 'k2' }, NAECHSTER);
  const u = kern.pruefeToken(t, { k1: HAUPT.pem, k2: NAECHSTER.pem }, PRODUKT, JETZT, { verifiziere: v });
  assert.equal(u.grund, 'ok');
  assert.deepEqual(v.aufrufe, [hexVon(NAECHSTER)]);
  assert.deepEqual(beruehrt, { verify: 0, createPublicKey: 0 });
});

test('Ring ohne kid: der Reihe nach, bis einer passt', () => {
  const { kern, beruehrt } = gebogenerKern();
  const v = zaehlend();
  const t = draht(NUTZLAST, NAECHSTER);
  const u = kern.pruefeToken(t, { k1: HAUPT.pem, k2: NAECHSTER.pem }, PRODUKT, JETZT, { verifiziere: v });
  assert.equal(u.grund, 'ok');
  assert.deepEqual(v.aufrufe, [hexVon(HAUPT), hexVon(NAECHSTER)]);
  assert.deepEqual(beruehrt, { verify: 0, createPublicKey: 0 });
});

test('Kette: Berechtigung mit dem Hauptschlüssel, Token mit dem Erneuerungsschlüssel', () => {
  const { kern, beruehrt } = gebogenerKern();
  const v = zaehlend();
  const u = kern.pruefeToken(TOKEN_KETTE, { k1: HAUPT.pem }, PRODUKT, JETZT, { verifiziere: v });
  assert.equal(u.grund, 'ok');
  assert.deepEqual(v.aufrufe, [hexVon(HAUPT), hexVon(ERNEUERUNG)]);
  assert.deepEqual(beruehrt, { verify: 0, createPublicKey: 0 });
  // Gegenstück: sagt die Option beim Erneuerungsschlüssel nein, fällt die Kette.
  const nein = zaehlend((r, s, k) => Buffer.from(k).toString('hex') !== hexVon(ERNEUERUNG) && referenz(r, s, k));
  assert.equal(kern.pruefeToken(TOKEN_KETTE, { k1: HAUPT.pem }, PRODUKT, JETZT, { verifiziere: nein }).grund, 'ungueltig');
  assert.equal(nein.aufrufe.length, 2);
});

test('Manifest: über die Option, node:crypto 0-mal berührt', () => {
  const { kern, beruehrt } = gebogenerKern();
  const v = zaehlend();
  const m = kern.bewerteManifest(MANIFEST, HAUPT.pem, 'lic-1', JETZT, null, { verifiziere: v });
  assert.deepEqual([m.status, m.detail, m.seq], ['aktiv', 'ok', 3]);
  assert.deepEqual(v.aufrufe, [hexVon(HAUPT)]);
  assert.deepEqual(beruehrt, { verify: 0, createPublicKey: 0 });
  const f = kern.bewerteManifest(MANIFEST, HAUPT.pem, 'lic-1', JETZT, null, { verifiziere: () => false });
  assert.equal(f.detail, 'signatur_falsch');
});

// ── PEM-Zerlegung ohne createPublicKey ─────────────────────────────────────

const TEST1 = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';

test('PEM-Zerlegung: RFC-8032-TEST-1 als SPKI-PEM ⇒ genau diese 32 Bytes', () => {
  const { kern, beruehrt } = gebogenerKern();
  const pem = pemAus(hex('302a300506032b6570032100' + TEST1));
  const r = kern.rohSchluessel(pem);
  assert.ok(r instanceof Uint8Array);
  assert.equal(Buffer.from(r).toString('hex'), TEST1);
  // Derselbe Schlüssel kommt so auch bei der Option an.
  const v = zaehlend(() => false);
  kern.pruefeToken(TOKEN, pem, PRODUKT, JETZT, { verifiziere: v });
  assert.deepEqual(v.aufrufe, [TEST1]);
  assert.deepEqual(beruehrt, { verify: 0, createPublicKey: 0 });
});

test('PEM-Zerlegung: falsches Präfix ⇒ LizenzFehler, Option nie gefragt', () => {
  const { kern } = gebogenerKern();
  const pem = pemAus(hex('302a300506032b6571032100' + TEST1));
  assert.throws(() => kern.rohSchluessel(pem), kern.LizenzFehler);
  const v = zaehlend(() => true);
  assert.equal(kern.pruefeToken(TOKEN, pem, PRODUKT, JETZT, { verifiziere: v }).grund, 'ungueltig');
  assert.equal(v.aufrufe.length, 0);
});

test('PEM-Zerlegung: X25519-PEM ⇒ LizenzFehler', () => {
  const { kern } = gebogenerKern();
  const x = crypto.generateKeyPairSync('x25519').publicKey.export({ type: 'spki', format: 'pem' });
  assert.throws(() => kern.rohSchluessel(x), kern.LizenzFehler);
  assert.equal(kern.pruefeToken(TOKEN, x, PRODUKT, JETZT, { verifiziere: () => true }).grund, 'ungueltig');
});

test('PEM-Zerlegung: falsche Länge, kein base64, kein PEM ⇒ LizenzFehler', () => {
  const { kern } = gebogenerKern();
  for (const pem of [
    pemAus(hex('302a300506032b6570032100' + TEST1 + '00')),
    pemAus(hex('302a300506032b6570032100' + TEST1.slice(2))),
    '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA1121!\n-----END PUBLIC KEY-----',
    TEST1, '', null,
  ]) {
    assert.throws(() => kern.rohSchluessel(pem), kern.LizenzFehler, String(pem));
  }
  assert.equal(Buffer.from(kern.rohSchluessel(HAUPT.pem)).toString('hex'), hexVon(HAUPT));
});
