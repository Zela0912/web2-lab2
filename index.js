import express from "express";
import session from "express-session";
import pool, { initDb, resetDb, hashPassword, verifyPassword } from "./db.js";

const app = express();
const PORT = process.env.PORT || 3000;

app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));

app.use(
    session({
        secret: process.env.SESSION_SECRET || "neka-tajna-za-labos",
        resave: false,
        saveUninitialized: true,
    })
);

app.use((req, res, next) => {
    if (req.session.sqliRanjivo === undefined) req.session.sqliRanjivo = true;
    if (req.session.authRanjivo === undefined) req.session.authRanjivo = true;
    next();
});

async function prikaziStranicu(req, res, podaci = {}) {
    const korisnici = await pool.query("SELECT * FROM users ORDER BY id");

    res.render("index", {
        sqliRanjivo: req.session.sqliRanjivo,
        authRanjivo: req.session.authRanjivo,
        prijavljen: req.session.user,
        sessionId: req.sessionID,
        korisnici: korisnici.rows,
        sqlUpit: null,
        sqlRezultat: null,
        sqlGreska: null,
        authPoruka: null,
        authLog: null,
        ...podaci,
    });
}

app.get("/", async (req, res) => {
    await prikaziStranicu(req, res);
});

app.post("/toggle/:koja", (req, res) => {
    const ukljuceno = req.body.ukljuceno === "on";
    if (req.params.koja === "sqli") req.session.sqliRanjivo = ukljuceno;
    if (req.params.koja === "auth") req.session.authRanjivo = ukljuceno;
    res.redirect("/");
});

app.post("/sqli", async (req, res) => {
    const username = req.body.username || "";
    let upit;
    let rezultat;

    try {
        if (req.session.sqliRanjivo) {
            upit = "SELECT id, username, email FROM users WHERE username = '" + username + "'";
            rezultat = await pool.query({ text: upit, queryMode: "extended" });
        } else {
            upit = "SELECT id, username, email FROM users WHERE username = $1";
            rezultat = await pool.query(upit, [username]);
            upit = upit + "   [ $1 = '" + username + "' ]";
        }

        await prikaziStranicu(req, res, { sqlUpit: upit, sqlRezultat: rezultat.rows });
    } catch (err) {
        await prikaziStranicu(req, res, { sqlUpit: upit, sqlGreska: err.message });
    }
});



async function provjeriPrijavu(username, lozinka, ranjivo) {
    const r = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
    const korisnik = r.rows[0];

    if (ranjivo) {
        if (!korisnik) {
            return { uspjeh: false, poruka: "Korisnik '" + username + "' ne postoji!" };
        }
        if (korisnik.password_plain !== lozinka) {
            return { uspjeh: false, poruka: "Kriva lozinka za korisnika '" + username + "'." };
        }
        return { uspjeh: true, poruka: "Uspjesna prijava!" };
    }

    if (!korisnik) {
        return { uspjeh: false, poruka: "Pogresno korisnicko ime ili lozinka." };
    }

    if (korisnik.locked_until && new Date(korisnik.locked_until) > new Date()) {
        const sekunde = Math.ceil((new Date(korisnik.locked_until) - new Date()) / 1000);
        return { uspjeh: false, zakljucan: true, poruka: "Previse neuspjelih pokusaja. Racun je zakljucan jos " + sekunde + " s." };
    }

    if (!verifyPassword(lozinka, korisnik.password_hash)) {
        const pokusaji = korisnik.failed_attempts + 1;
        if (pokusaji >= 3) {
            await pool.query(
                "UPDATE users SET failed_attempts = 0, locked_until = NOW() + INTERVAL '1 minute' WHERE id = $1",
                [korisnik.id]
            );
            return { uspjeh: false, zakljucan: true, poruka: "Pogresno korisnicko ime ili lozinka. Racun je zakljucan na 1 minutu." };
        }
        await pool.query("UPDATE users SET failed_attempts = $1 WHERE id = $2", [pokusaji, korisnik.id]);
        return { uspjeh: false, poruka: "Pogresno korisnicko ime ili lozinka." };
    }




    await pool.query("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = $1", [korisnik.id]);
    return { uspjeh: true, poruka: "Uspjesna prijava!" };


}

app.post("/login", async (req, res) => {
    const { username, lozinka } = req.body;

    const ranjivo = req.session.authRanjivo;

    const stariSessionId = req.sessionID;

    const rez = await provjeriPrijavu(username, lozinka, ranjivo);

    if (!rez.uspjeh) {


        return prikaziStranicu(req, res, { authPoruka: rez.poruka });
    }

    if (ranjivo) {
        req.session.user = username;
        return prikaziStranicu(req, res, {
            authPoruka: rez.poruka + " Session ID prije: " + stariSessionId + " / poslije: " + req.sessionID + " (ISTI!)",
       
         });
    }

    const sqliRanjivo = req.session.sqliRanjivo;
    req.session.regenerate(async () => {
        req.session.user = username;
        req.session.authRanjivo = false;

         req.session.sqliRanjivo = sqliRanjivo;
        await prikaziStranicu(req, res, {
            authPoruka: rez.poruka + " Session ID prije: " + stariSessionId + " / poslije: " + req.sessionID + " (novi)",
        });
    });
});

app.post("/logout", (req, res) => {
    req.session.user = null;
    res.redirect("/");
});



app.post("/register", async (req, res) => {
    const { username, email, lozinka } = req.body;



    if (!username || !email || !lozinka) {

        return prikaziStranicu(req, res, { authPoruka: "Sva polja su obavezna." });
    }

    try {   
        if  (req.session.authRanjivo) {
            await pool.query(
                "INSERT INTO users (username, email, password_plain) VALUES ($1, $2, $3)",
                [username, email, lozinka]
            );
        } else {
            if (    
                lozinka.length < 8 ||
                !/[A-Z]/.test(lozinka) ||
                !/[a-z]/.test(lozinka) ||
                !/[0-9]/.test(lozinka) ||
                !/[^A-Za-z0-9]/.test(lozinka)
            ) {
                return prikaziStranicu(req, res, {
                    authPoruka: "Lozinka mora imati barem 8 znakova, veliko i malo slovo, broj i poseban znak.",
                });
            }
            await pool.query(
                "INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3)",
                [username, email, hashPassword(lozinka)]
            );
        }
        await prikaziStranicu(req, res, { authPoruka: "Korisnik '" + username + "' registriran. Pogledaj tablicu ispod kako je lozinka spremljena." });
    } catch (err) { 
        await prikaziStranicu(req, res, { authPoruka: "Greska: korisnik vec postoji." });
    }
});

app.post("/bruteforce", async (req, res) => {
    const username = req.body.username; 

    const ranjivo = req.session.authRanjivo;
    const lozinke = ["123456", "password", "qwerty", "12345678", "lozinka", "admin", "admin123", "iloveyou", "111111", "Marko#2026!"];
    const log = [];

    for (const lozinka of lozinke) {
        const rez = await provjeriPrijavu(username, lozinka, ranjivo);
        log.push("Pokusaj '" + lozinka + "' -> " + rez.poruka);

        if (rez.uspjeh) {
            log.push(">>> NAPAD USPIO! Lozinka za '" + username + "' je: " + lozinka);
            break;
        }
        if (rez.zakljucan) {
            log.push(">>> Napad zaustavljen, racun je zakljucan.");
            break;
        }
    }

    await prikaziStranicu(req, res, { authLog: log });      
    
});

app.post("/reset", async (req, res) => {
    await resetDb();
    res.redirect("/");
});

await initDb();

app.listen(PORT, () => {
    console.log("Server radi na http://localhost:" + PORT);
});
