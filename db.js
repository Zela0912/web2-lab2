import pg from "pg";
import crypto from "node:crypto";

const { Pool } = pg;

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
});

export function hashPassword(lozinka) {
    const salt = crypto.randomBytes(16).toString("hex");
    const hash = crypto.scryptSync(lozinka, salt, 64).toString("hex");
    return salt + ":" + hash;
}

export function verifyPassword(lozinka, spremljeno) {
    if (!spremljeno) return false;
    const [salt, hash] = spremljeno.split(":");
    const novi = crypto.scryptSync(lozinka, salt, 64);
    return crypto.timingSafeEqual(novi, Buffer.from(hash, "hex"));
}

export async function initDb() {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL,
            password_plain TEXT,
            password_hash TEXT,
            failed_attempts INT NOT NULL DEFAULT 0,
            locked_until TIMESTAMPTZ
        )
    `);

    const korisnici = [
        { username: "admin", email: "admin@fer.hr", lozinka: "admin123" },
        { username: "ana", email: "ana@fer.hr", lozinka: "lozinka" },
        { username: "marko", email: "marko@fer.hr", lozinka: "Marko#2026!" },
    ];

    for (const k of korisnici) {
        await pool.query(
            "INSERT INTO users (username, email, password_plain, password_hash) VALUES ($1, $2, $3, $4) ON CONFLICT (username) DO NOTHING",
            [k.username, k.email, k.lozinka, hashPassword(k.lozinka)]
        );
    }

    console.log("Baza je spremna");
}
export async function resetDb() {
    await pool.query("DROP TABLE IF EXISTS users");
    await initDb();
}

export default pool;
