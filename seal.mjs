// Seals a small JSON data file so only the unlocked page can read it.
// Usage: node seal.mjs <plain.json> [out=w.json]
// Needs no secret: it uses the public key below. The matching private key
// lives only inside the password-encrypted page.
import fs from 'node:fs';
import crypto from 'node:crypto';

const PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAstHXBVtQQGPwduHugAuQ
boKFO1xHXMSuHcDmRGdoPWa8j/T1389hX5F2qxxv0Xco7+E+WIYbZIs+nZrEmMIV
jG41C1sjrFN+sK+ZhOUCVD3t3DoRAI/S1nNx9x+HgjC30yl3kxnTu4JeD+P1HWv3
Tje5K3ZRRPIf42/FVou2Wbxb0Df7n2ZI8vIyfWGF5wybUO1URiV3PhUyqvyC6pzn
jiLOVsf6c/UFDAHpxwayUjcFxvEiVeN8ztVl2YPoBZhkN/yBTWX0OL+y7d4d/UiE
4QikeIkdM5so9E1TbCJ2T1B585vegSRll5Q0Cry7nDUSGCBq3ZQkXEWYSTqjlp3y
UiTaYQhT6s2CB74+KIH4tfbnsJRWnDv8LSrNxz9QZNpsuU8mqbA13NR5JVpYS8/X
TFAluKkD3+uKkZV25kqBblc7U/6gISB+j5LYHoKbMSUc+1cG3/7+3ve7Q5kZjnWQ
VoHle459N1LA9a2qA+HFZ59GYJ6QxqNCyhZ9TaSgSwA5AgMBAAE=
-----END PUBLIC KEY-----`;

const [,, inPath, outPath = 'w.json'] = process.argv;
if (!inPath) { console.error('usage: node seal.mjs <plain.json> [out.json]'); process.exit(2); }
const data = JSON.parse(fs.readFileSync(inPath, 'utf8'));

// ---- validate (refuse anything the page would not show) ----
const fail = m => { console.error('INVALID: ' + m); process.exit(1); };
const str = (v, max, name) => { if (typeof v !== 'string' || !v.trim() || v.length > max) fail(name + ' must be a non-empty string up to ' + max + ' chars'); };
const SKY = ['sun', 'partly', 'cloud', 'showers', 'rain', 'storm', 'snow', 'fog'];
if (!/^\d{4}-\d{2}-\d{2}$/.test(data.asof || '')) fail('asof must be YYYY-MM-DD');
str(data.asofText, 20, 'asofText');
if (!data.days || typeof data.days !== 'object') fail('days missing');
const keys = Object.keys(data.days);
if (!keys.length) fail('days is empty');
for (const k of keys) {
  if (!/^(1[3-9]|2[0-2])$/.test(k)) fail('day key ' + k + ' must be 13 to 22');
  const d = data.days[k];
  if (!SKY.includes(d.sky)) fail('day ' + k + ' sky must be one of ' + SKY.join(', '));
  str(d.line, 48, 'day ' + k + ' line');
  str(d.temp, 24, 'day ' + k + ' temp');
  str(d.tempF, 28, 'day ' + k + ' tempF');
  str(d.rain, 16, 'day ' + k + ' rain');
  str(d.detail, 420, 'day ' + k + ' detail');
  for (const f of Object.keys(d)) if (!['sky', 'line', 'temp', 'tempF', 'rain', 'detail'].includes(f)) fail('day ' + k + ' has unknown field ' + f);
}
for (const f of Object.keys(data)) if (!['asof', 'asofText', 'days'].includes(f)) fail('unknown top-level field ' + f);

// ---- seal: AES-256-GCM for the data, RSA-OAEP-SHA256 for the AES key ----
const plain = Buffer.from(JSON.stringify(data), 'utf8');
const aes = crypto.randomBytes(32), iv = crypto.randomBytes(12);
const c = crypto.createCipheriv('aes-256-gcm', aes, iv);
const ct = Buffer.concat([c.update(plain), c.final(), c.getAuthTag()]);
const k = crypto.publicEncrypt({ key: PUBLIC_KEY, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, aes);
fs.writeFileSync(outPath, JSON.stringify({ v: 1, k: k.toString('base64'), iv: iv.toString('base64'), ct: ct.toString('base64') }) + '\n');
console.log('sealed ' + keys.length + ' day(s), as of ' + data.asof + ' -> ' + outPath);
