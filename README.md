# WEB2 - Lab 2: Sigurnosne ranjivosti

Web aplikacija koja demonstrira dvije ranjivosti:

1. **SQL Injection** (tautologija)
2. **Broken Authentication**

Svaka ranjivost ima checkbox "Ranjivost uključena" kojim se uključuje i isključuje.

Tehnologije: Node.js, Express, EJS, PostgreSQL (Neon).

## Pokretanje lokalno

```bash
npm install
```

Napraviti `.env` datoteku:

```
DATABASE_URL=postgresql://korisnik:lozinka@host/baza?sslmode=require
PORT=3000
SESSION_SECRET=neka-tajna
```

```bash
npm run dev
```

Aplikacija je na http://localhost:3000. Tablica `users` i testni korisnici se kreiraju automatski pri pokretanju.

## Testni korisnici

| korisnik | lozinka |
|---|---|
| admin | admin123 |
| ana | lozinka |
| marko | Marko#2026! |

## Testiranje

### SQL Injection
- Ranjivost uključena: u polje upisati `' OR '1'='1` i vratit će se svi korisnici.
- Ranjivost isključena: isti unos ne vraća ništa (parametrizirani upit).

### Broken Authentication
- Ranjivost uključena:
  - prijava s nepostojećim korisnikom javlja da korisnik ne postoji
  - registracija prihvaća lozinku "1", a lozinka se u tablici vidi u plain textu
  - brute force napad na `admin` pogodi lozinku
  - session ID je isti prije i poslije prijave
- Ranjivost isključena:
  - poruka je uvijek "Pogrešno korisničko ime ili lozinka"
  - registracija traži jaku lozinku, a sprema se samo hash
  - brute force se zaustavi nakon 3 pokušaja jer se račun zaključa na 1 minutu
  - nakon prijave se dobije novi session ID

Gumb "Resetiraj bazu" vraća bazu na početno stanje.
