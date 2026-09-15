# ArtifactRegistry — opis projekta

**Kolegij:** Blockchain aplikacije
**Tehnologije:** Solidity 0.8.24, OpenZeppelin 5, Foundry (forge, anvil, cast), ethers.js 6, MetaMask, HTML/JavaScript

## Sažetak

ArtifactRegistry je decentralizirana evidencija softverskih buildova (firmware,
paketi, instalacije) na Ethereum blockchainu. Svaki build upisuje se pod svojim
SHA-256 otiskom, a smatra se **odobrenim za objavu** tek kad ga potpišu tri
neovisne uloge: build server, QA i sigurnosni pregled. Potpisi se daju izvan
lanca (EIP-712) i besplatni su za potpisnike; jedna transakcija zatim šalje sve
potpise na lanac. Provjera bilo kojeg builda je besplatno čitanje, bez novčanika.

## Problem

Kad korisnik preuzme firmware ili instalaciju, postavljaju se dva pitanja: je li
datoteka *točno* ona koja je objavljena, i tko je odobrio objavu? Danas to
uglavnom jamči stranica za preuzimanje ili jedan potpisni ključ u rukama jednog
tima. Jedan kompromitirani ključ ili jedna nepažljiva osoba dovoljni su da se
objavi neispravan build.

## Cilj

Javna evidencija u kojoj build vrijedi kao objavljen samo nakon odobrenja tri
neovisne strane, pri čemu **nijedna od njih ne može krivotvoriti odobrenje
drugih**. Obična baza podataka to ne može pružiti: administrator baze može
upisati bilo koji redak, uključujući tuđe odobrenje. Na blockchainu je odobrenje
digitalni potpis koji nitko ne može proizvesti bez privatnog ključa te strane,
a pravila (tri potpisa, bez prepisivanja zapisa, trajno povlačenje) provodi
pametni ugovor, a ne onaj tko upravlja poslužiteljem.

## Kako radi

1. **Registracija.** Izdavač u ugovor upisuje SHA-256 otisak builda i oznaku
   verzije. Otisak se računa u pregledniku; sama datoteka nikad ne napušta
   računalo. Ovo je jedina plaćena transakcija izdavača.
2. **Potpisivanje.** Svaka od tri uloge u MetaMasku potpisuje strukturiranu
   poruku (EIP-712) s poljima *otisak, uloga, potpisnik, rok*. To nije
   transakcija: ne troši gas i račun potpisnika ne mora imati ETH.
3. **Slanje.** Jedna osoba (relayer) šalje sve prikupljene potpise u jednoj
   transakciji. Ugovor iz svakog potpisa rekonstruira adresu potpisnika
   (`ecrecover`) i provjerava ima li ta adresa navedenu ulogu. Kad su
   prikupljena tri različita potpisa, build je objavljen.
4. **Provjera.** Bilo tko može u stranicu ubaciti datoteku i dobiti odgovor:
   nije u evidenciji / čeka potpise (n od 3) / objavljeno / povučeno. To je
   `view` poziv — bez novčanika, bez gasa.
5. **Povlačenje.** Izvorni izdavač može build povući. Zapis ostaje, označen
   kao povučen, i takav build se nikad ne smatra objavljenim, bez obzira na
   broj potpisa.

## Što je EIP-712

EIP-712 je Ethereum standard za potpisivanje strukturiranih podataka. Umjesto
nečitljivog heksadecimalnog niza, novčanik korisniku prikaže čitljiva polja i
potpisuje točno njih. U potpis su uključeni i adresa ugovora i ID lanca, pa je
potpis napravljen za jedan ugovor ili jednu mrežu neupotrebljiv na bilo kojoj
drugoj.

## Struktura projekta

| Datoteka | Sadržaj |
|---|---|
| `src/ArtifactRegistry.sol` | pametni ugovor — jedino što se postavlja na lanac (oko 120 linija koda uz OpenZeppelin `EIP712` i `ECDSA`) |
| `test/ArtifactRegistry.t.sol` | 19 Foundry testova, uključujući potpisivanje pravim ključevima i fuzz test |
| `web/index.html` | frontend u jednoj datoteci: demo način bez lanca i pravi način preko MetaMaska |
| `tools/verify-frontend.mjs` | Node skripta koja provjerava da se ABI i EIP-712 definicije na stranici slažu s prevedenim ugovorom |
| `docs/screenshots/` | snimke zaslona pet stanja aplikacije |

## Testiranje

`forge test` pokreće 19 testova: registracija i zabrana prepisivanja, kvorum,
odbijanje potpisa s krivim ključem ili bez uloge, zabrana ponovnog slanja istog
potpisa, istek roka, neprenosivost potpisa na drugu instancu ugovora,
odbijanje "zrcalnog" (malleable) potpisa, skupno slanje, povlačenje i fuzz
test s 256 nasumičnih otisaka. Skripta `tools/verify-frontend.mjs` dodatno
provjerava JavaScript stranu na lokalnom Anvil lancu.

## Odluke u dizajnu

- **Bez nonce-a u potpisanoj poruci.** Svaki par (build, uloga) može se
  potpisati samo jednom, pa se potpis ne može ponovno iskoristiti.
- **OpenZeppelin `EIP712` i `ECDSA`** računaju domenski hash i iz potpisa
  vraćaju adresu potpisnika (provjera duljine, zrcalnog potpisa i nul-adrese);
  pravila o ulogama, kvorumu i ponovnoj uporabi potpisa su u samom ugovoru.
- **Kvorum je fiksan pri postavljanju** i ne može se kasnije smanjiti.
- **Popis buildova gradi se iz događaja** (events), a ne iz polja u ugovoru —
  jeftinije za ~29 000 gasa po registraciji.

## Ograničenja

Vlasnik ugovora je jedan ključ koji dodjeljuje sve uloge; u produkciji bi to
bio multisig novčanik. Skupno slanje nema gornju granicu broja potpisa. Stranica
učitava ethers.js s CDN-a, pa demo treba pristup internetu (ili lokalnu kopiju
biblioteke).

## Pokretanje

```bash
forge test                                   # testovi
anvil                                        # lokalni lanac
forge create src/ArtifactRegistry.sol:ArtifactRegistry \
  --rpc-url http://127.0.0.1:8545 --broadcast --constructor-args 3 \
  --private-key <anvil ključ 0>
cd web && python -m http.server 8000         # http://localhost:8000/?registry=<adresa>
```

Repozitorij: https://github.com/jseketa-fipu/BA-zavrsni-projekt
