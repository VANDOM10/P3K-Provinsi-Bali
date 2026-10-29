"use strict";
const crypto = require("crypto");
const { promisify } = require("util");
const scrypt = promisify(crypto.scrypt);

const PROV = "Provinsi Bali";
// Hash SHA-256 password lama (hanya dipakai server, hanya jika INIT_PASSWORD tidak diisi)
const LEGACY = {
  "Provinsi Bali": "caafb8c200210ebfff71b0019004fdb01826fdd7c04b04a1fd4464c4a3868e02",
  Badung: "fcccb0ef9637721c6ef266ea00456128fb17d1af1e106ce24f680f40f2674dd3",
  Bangli: "65f8387518eeeb1bf57ecec06185725e1abb01c2d6550f312cfe65673315d08c",
  Buleleng: "ac4b34fc9fa5ad79e35f955412cafe1081f8ebaf6072ea5218c45cc9ff7b797b",
  Gianyar: "19cb72e21cb84cf82d23725bdea9e91b85217ced4390250311de83d570183205",
  Jembrana: "9b8c7dd0f5f2bfee4cdbb920564a2a37c084ebcb3194c63eebde224c0f04f8b4",
  Karangasem: "dc8866d4c4a983c5c96f8ba9a915d26760a2326e51c4de18c93944f87c683a3f",
  Klungkung: "411d46c085fe00f123fdf1a2ddd609053f4760ae120db758ba61eb6c8de6b8ea",
  Tabanan: "b60202e2b223c6a16ddae46c0bccf3f718c3a2b83e50496074408b23899dc9cf",
  Denpasar: "091935e99f46eb54e2435ae5c3d4f523377d7513aba0f5916c4726d547bca108",
};
const LEGACY_RECOVERY = "014fe7e052bc3781627292ce1aba1a3b533d0ce0174e5c1710451804dad042c1";
const WIL = Object.keys(LEGACY);
const KAB = WIL.filter((k) => k !== PROV);
const TENAGA = ["Dokter", "Perawat", "Bidan", "Paramedis/EMT", "Relawan Terlatih"];
const STATUS = ["Menunggu", "Terverifikasi", "Perlu Revisi"];
const SESSION_SEC = 15 * 60;
const SESSION_MAX_SEC = 12 * 3600;

class HttpError extends Error {
  constructor(code, msg, extra) { super(msg); this.code = code; this.extra = extra; }
}

/* ---------- Redis (Upstash REST) ---------- */
async function redis(cmds) {
  const url = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) throw new HttpError(500, "Database belum tersambung (KV_REST_API_URL / KV_REST_API_TOKEN kosong).");
  const r = await fetch(url.replace(/\/$/, "") + "/pipeline", {
    method: "POST",
    headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" },
    body: JSON.stringify(cmds),
  });
  if (!r.ok) throw new HttpError(502, "Database error " + r.status);
  const j = await r.json();
  return j.map((x) => { if (x.error) throw new HttpError(502, "Database: " + x.error); return x.result; });
}
const cmd = async (...a) => (await redis([a]))[0];
function pairs(flat) {
  if (!flat) return {};
  if (!Array.isArray(flat)) return flat;
  const o = {};
  for (let i = 0; i < flat.length; i += 2) o[flat[i]] = flat[i + 1];
  return o;
}
const bump = () => cmd("INCR", "p3k:ver");

/* ---------- util ---------- */
const sha256 = (s) => crypto.createHash("sha256").update(String(s)).digest("hex");
function safeEq(a, b) {
  return crypto.timingSafeEqual(crypto.createHash("sha256").update(String(a)).digest(), crypto.createHash("sha256").update(String(b)).digest());
}
const kuat = (n) => typeof n === "string" && /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*\W).{8,128}$/.test(n);
async function hashPw(p) {
  const salt = crypto.randomBytes(16);
  const h = await scrypt(p, salt, 32, { N: 16384, r: 8, p: 1 });
  return "s1:" + salt.toString("hex") + ":" + h.toString("hex");
}
async function verifyPw(p, stored) {
  const [v, s, h] = String(stored).split(":");
  if (v !== "s1") return false;
  const x = await scrypt(p, Buffer.from(s, "hex"), 32, { N: 16384, r: 8, p: 1 });
  const y = Buffer.from(h, "hex");
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
function genPw() {
  const A = "ABCDEFGHJKLMNPQRSTUVWXYZ", B = "abcdefghijkmnpqrstuvwxyz", C = "23456789", S = "#@!%";
  const r = (x) => x[crypto.randomInt(x.length)];
  const a = [A, A, B, B, B, B, C, C, S].map(r);
  for (let i = a.length - 1; i > 0; i--) { const j = crypto.randomInt(i + 1); [a[i], a[j]] = [a[j], a[i]]; }
  return a.join("");
}
const ipOf = (req) => String(req.headers["x-real-ip"] || (req.headers["x-forwarded-for"] || "").split(",")[0] || "0").trim();

/* ---------- rate limit ---------- */
async function lockLeft(key) {
  const t = await cmd("TTL", key + ":lock");
  return t > 0 ? t : 0;
}
async function addFail(key, max, lockSec, winSec) {
  const n = await cmd("INCR", key + ":n");
  if (n === 1) await cmd("EXPIRE", key + ":n", winSec);
  if (n >= max) { await redis([["SET", key + ":lock", "1", "EX", String(lockSec)], ["DEL", key + ":n"]]); return true; }
  return false;
}
async function hit(key, max, winSec) {
  const n = await cmd("INCR", key);
  if (n === 1) await cmd("EXPIRE", key, winSec);
  if (n > max) throw new HttpError(429, "Terlalu banyak permintaan. Coba lagi nanti.");
}

/* ---------- sesi (cookie HttpOnly, ditandatangani HMAC) ---------- */
function secret() {
  const s = process.env.SESSION_SECRET;
  if (!s || s.length < 32) throw new HttpError(500, "SESSION_SECRET belum diatur (min. 32 karakter).");
  return s;
}
const b64u = (b) => Buffer.from(b).toString("base64url");
function sign(p) {
  const body = b64u(JSON.stringify(p));
  return body + "." + crypto.createHmac("sha256", secret()).update(body).digest("base64url");
}
function readSession(req) {
  const m = /(?:^|;\s*)p3k_s=([^;]+)/.exec(req.headers.cookie || "");
  if (!m) return null;
  const [body, mac] = m[1].split(".");
  if (!body || !mac) return null;
  const exp = crypto.createHmac("sha256", secret()).update(body).digest("base64url");
  const a = Buffer.from(mac), b = Buffer.from(exp);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  let p;
  try { p = JSON.parse(Buffer.from(body, "base64url").toString()); } catch { return null; }
  const now = Math.floor(Date.now() / 1000);
  if (!p || !WIL.includes(p.u) || p.exp < now || now - p.iat > SESSION_MAX_SEC) return null;
  return p;
}
function setSession(res, u, tmp, iat) {
  const now = Math.floor(Date.now() / 1000);
  const tok = sign({ u, t: tmp ? 1 : 0, iat: iat || now, exp: now + SESSION_SEC });
  res.setHeader("Set-Cookie", `p3k_s=${tok}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_SEC}`);
}
function clearSession(res) {
  res.setHeader("Set-Cookie", "p3k_s=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0");
}

/* ---------- log ---------- */
const lg = (wil, aksi) =>
  redis([["LPUSH", "p3k:log", JSON.stringify({ ts: Date.now(), wil, aksi })], ["LTRIM", "p3k:log", "0", "999"]]);

module.exports = {
  PROV, WIL, KAB, TENAGA, STATUS, LEGACY, LEGACY_RECOVERY, SESSION_SEC,
  HttpError, redis, cmd, pairs, bump, sha256, safeEq, kuat, hashPw, verifyPw, genPw, ipOf,
  lockLeft, addFail, hit, readSession, setSession, clearSession, lg,
};
