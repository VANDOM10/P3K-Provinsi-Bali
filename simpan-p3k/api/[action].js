"use strict";
const P = require("../lib/p3k");
const { HttpError, PROV, WIL, KAB, TENAGA, STATUS, cmd, redis, pairs, bump, lg } = P;

const str = (v, max) => String(v == null ? "" : v).trim().slice(0, max);
const num = (v) => { const n = Math.floor(Number(v)); return Number.isFinite(n) && n >= 0 && n <= 100000 ? n : NaN; };
const lapKey = (k) => "p3k:lap:" + k;

function need(req, res) {
  const s = P.readSession(req);
  if (!s) throw new HttpError(401, "Sesi berakhir. Silakan login lagi.");
  return s;
}
const bg = (req) => req.headers["x-p3k-bg"] === "1";

async function checkPassword(w, p) {
  const raw = await cmd("HGET", "p3k:akun", w);
  if (raw) {
    const a = JSON.parse(raw);
    return { ok: await P.verifyPw(p, a.h), tmp: !!a.tmp };
  }
  const init = process.env.INIT_PASSWORD;
  if (init) return { ok: P.safeEq(p, init), tmp: true };
  return { ok: P.safeEq(P.sha256(p), P.LEGACY[w]), tmp: true };
}
const savePw = (w, pw, tmp) => cmd("HSET", "p3k:akun", w, JSON.stringify({ h: pw, tmp: !!tmp }));

const H = {
  async login(req, res, b) {
    const w = str(b.w, 40), p = String(b.p == null ? "" : b.p).slice(0, 200);
    if (!WIL.includes(w) || !p) throw new HttpError(400, "Wilayah/password tidak valid.");
    const ip = P.ipOf(req), k1 = `p3k:rl:${ip}:${w}`, k2 = `p3k:rl:w:${w}`;
    const left = Math.max(await P.lockLeft(k1), await P.lockLeft(k2));
    if (left) throw new HttpError(429, `Terkunci sementara. Coba lagi ${left} detik lagi.`, { lock: left });
    const r = await checkPassword(w, p);
    if (!r.ok) {
      await lg(w, "Login gagal");
      const l = await P.addFail(k1, 5, 30, 900);
      await P.addFail(k2, 30, 300, 900);
      throw new HttpError(401, l ? "5x salah. Terkunci 30 detik." : "Password salah.", l ? { lock: 30 } : undefined);
    }
    await redis([["DEL", k1 + ":n"], ["DEL", k2 + ":n"]]);
    P.setSession(res, w, r.tmp);
    await lg(w, "Login");
    return { user: w, tmp: r.tmp };
  },

  async logout(req, res) {
    const s = P.readSession(req);
    if (s) await lg(s.u, "Logout");
    P.clearSession(res);
    return { ok: 1 };
  },

  async ping(req, res) {
    const s = need(req, res);
    P.setSession(res, s.u, s.t, s.iat);
    return { ok: 1 };
  },

  async state(req, res) {
    const s = need(req, res);
    if (!bg(req)) P.setSession(res, s.u, s.t, s.iat);
    const ver = String((await cmd("GET", "p3k:ver")) || "0");
    if (req.query && String(req.query.v) === ver) return { same: 1, user: s.u, tmp: !!s.t };
    const isP = s.u === PROV;
    const q = (isP ? KAB : [s.u]).map((k) => ["HGETALL", lapKey(k)]);
    if (isP) { q.push(["HGETALL", "p3k:reset"]); q.push(["LRANGE", "p3k:log", "0", "299"]); }
    const out = await redis(q);
    const laporan = [];
    const n = isP ? KAB.length : 1;
    for (let i = 0; i < n; i++) for (const v of Object.values(pairs(out[i]))) { try { laporan.push(JSON.parse(v)); } catch {} }
    const r = { ver, user: s.u, tmp: !!s.t, laporan };
    if (isP) {
      r.reset = Object.entries(pairs(out[n])).map(([k, v]) => ({ id: k, ts: +v }));
      r.log = (out[n + 1] || []).map((x) => { try { return JSON.parse(x); } catch { return null; } }).filter(Boolean);
    }
    return r;
  },

  async laporan(req, res, b) {
    const s = need(req, res);
    if (s.u === PROV) throw new HttpError(403, "Provinsi hanya memantau.");
    if (s.t) throw new HttpError(403, "Ganti password sementara dulu.");
    const tgl = str(b.tgl, 10), t = Date.parse(tgl + "T00:00:00Z");
    if (!/^\d{4}-\d{2}-\d{2}$/.test(tgl) || !Number.isFinite(t) || t > Date.now() + 2 * 864e5) throw new HttpError(400, "Tanggal tidak valid.");
    const r = {
      kab: s.u, tgl, lokasi: str(b.lokasi, 120), kegiatan: str(b.kegiatan, 120), petugas: str(b.petugas, 100),
      tenaga: str(b.tenaga, 30), jmlPetugas: num(b.jmlPetugas), pasien: num(b.pasien), ringan: num(b.ringan),
      sedang: num(b.sedang), berat: num(b.berat), rujukan: num(b.rujukan), catatan: str(b.catatan, 1000),
      status: "Menunggu", ts: Date.now(),
    };
    if (!r.lokasi || !r.petugas) throw new HttpError(400, "Isi tanggal, lokasi, dan nama petugas.");
    if (!TENAGA.includes(r.tenaga)) throw new HttpError(400, "Jenis tenaga tidak valid.");
    for (const k of ["jmlPetugas", "pasien", "ringan", "sedang", "berat", "rujukan"]) if (Number.isNaN(r[k])) throw new HttpError(400, "Angka tidak valid.");
    if (r.ringan + r.sedang + r.berat > r.pasien) throw new HttpError(400, "Jumlah kasus melebihi jumlah pasien.");
    r.id = "r" + r.ts + Math.random().toString(36).slice(2, 6);
    await cmd("HSET", lapKey(s.u), r.id, JSON.stringify(r));
    await bump();
    await lg(s.u, "Kirim laporan");
    return { ok: 1, id: r.id };
  },

  async hapus(req, res, b) {
    const s = need(req, res);
    if (s.t) throw new HttpError(403, "Ganti password sementara dulu.");
    const k = str(b.k, 40), id = str(b.id, 60);
    if (!KAB.includes(k) || (s.u !== PROV && s.u !== k)) throw new HttpError(403, "Tidak diizinkan.");
    const n = await cmd("HDEL", lapKey(k), id);
    if (n) { await bump(); await lg(s.u, "Hapus laporan"); }
    return { ok: 1 };
  },

  async status(req, res, b) {
    const s = need(req, res);
    if (s.u !== PROV) throw new HttpError(403, "Hanya Provinsi yang boleh verifikasi.");
    if (s.t) throw new HttpError(403, "Ganti password sementara dulu.");
    const k = str(b.k, 40), id = str(b.id, 60), v = str(b.v, 20);
    if (!KAB.includes(k) || !STATUS.includes(v)) throw new HttpError(400, "Data tidak valid.");
    const raw = await cmd("HGET", lapKey(k), id);
    if (!raw) throw new HttpError(404, "Laporan tidak ditemukan.");
    const r = JSON.parse(raw); r.status = v; r.diverifikasi = Date.now();
    await cmd("HSET", lapKey(k), id, JSON.stringify(r));
    await bump();
    await lg(s.u, "Verifikasi: " + v);
    return { ok: 1 };
  },

  async pw(req, res, b) {
    const s = need(req, res);
    const o = String(b.o || ""), n = String(b.n || "");
    const k = `p3k:rl:pw:${s.u}`;
    if (await P.lockLeft(k)) throw new HttpError(429, "Terkunci sementara. Coba lagi nanti.");
    const c = await checkPassword(s.u, o);
    if (!c.ok) { await P.addFail(k, 5, 60, 900); throw new HttpError(400, "Password lama salah."); }
    if (!P.kuat(n)) throw new HttpError(400, "Password kurang kuat (min. 8, besar, kecil, angka, simbol).");
    if (P.safeEq(o, n)) throw new HttpError(400, "Password baru harus berbeda.");
    await savePw(s.u, await P.hashPw(n), false);
    P.setSession(res, s.u, false, s.iat);
    await bump();
    await lg(s.u, "Ganti password");
    return { ok: 1 };
  },

  async minta(req, res, b) {
    const w = str(b.w, 40);
    if (!KAB.includes(w)) throw new HttpError(400, "Wilayah tidak valid.");
    await P.hit(`p3k:rl:minta:${P.ipOf(req)}`, 5, 3600);
    await cmd("HSET", "p3k:reset", w, String(Date.now()));
    await bump();
    await lg(w, "Minta reset password");
    return { ok: 1 };
  },

  async pulih(req, res, b) {
    const kode = String(b.k || "").slice(0, 200), n = String(b.n || "");
    const key = `p3k:rl:pulih:${P.ipOf(req)}`;
    const left = await P.lockLeft(key);
    if (left) throw new HttpError(429, `Terkunci sementara. Coba lagi ${left} detik lagi.`);
    const rc = process.env.RECOVERY_CODE;
    const ok = rc ? P.safeEq(kode, rc) : P.safeEq(P.sha256(kode), P.LEGACY_RECOVERY);
    if (!ok) { await P.addFail(key, 5, 60, 900); throw new HttpError(401, "Kode pemulihan salah."); }
    if (!P.kuat(n)) throw new HttpError(400, "Password kurang kuat (min. 8, besar, kecil, angka, simbol).");
    await savePw(PROV, await P.hashPw(n), false);
    await bump();
    await lg(PROV, "Pemulihan akun Provinsi");
    return { ok: 1 };
  },

  async setpw(req, res, b) {
    const s = need(req, res);
    if (s.u !== PROV) throw new HttpError(403, "Hanya Provinsi.");
    if (s.t) throw new HttpError(403, "Ganti password sementara dulu.");
    const k = str(b.k, 40);
    if (!KAB.includes(k)) throw new HttpError(400, "Wilayah tidak valid.");
    let n = String(b.n || "");
    if (!n) n = P.genPw();
    if (!P.kuat(n)) throw new HttpError(400, "Password kurang kuat (min. 8, besar, kecil, angka, simbol).");
    await savePw(k, await P.hashPw(n), true);
    await cmd("HDEL", "p3k:reset", k);
    await bump();
    await lg(s.u, "Reset password " + k);
    return { ok: 1, pw: n };
  },
};
const GET_OK = new Set(["state"]);

module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  try {
    const a = String((req.query && req.query.action) || "");
    const fn = Object.prototype.hasOwnProperty.call(H, a) ? H[a] : null;
    if (!fn) throw new HttpError(404, "Tidak ditemukan.");
    const want = GET_OK.has(a) ? "GET" : "POST";
    if (req.method !== want) { res.setHeader("Allow", want); throw new HttpError(405, "Metode tidak diizinkan."); }
    if (req.headers["x-p3k"] !== "1") throw new HttpError(400, "Permintaan tidak valid.");
    let b = req.body;
    if (typeof b === "string") { try { b = JSON.parse(b); } catch { b = {}; } }
    const out = await fn(req, res, b && typeof b === "object" ? b : {});
    res.status(200).json(out);
  } catch (e) {
    if (e instanceof HttpError) return res.status(e.code).json({ error: e.message, ...(e.extra || {}) });
    console.error(e);
    res.status(500).json({ error: "Kesalahan server." });
  }
};
