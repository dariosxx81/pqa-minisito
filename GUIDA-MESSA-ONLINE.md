# Guida Operativa & Messa Online — Centro Analisi P.Q.A. S.r.l.

## 1. Accesso all'Area Riservata (`admin.php`)
- **Indirizzo pannello:** `/admin.php` (collegato anche nel footer del sito alla voce *Area Riservata*)
- **Password iniziale di primo avvio:** `PqaSiracusa2026!`
- **Primo passo consigliato prima del lancio pubblico:** accedere a `/admin.php?tab=security` e sostituire la password iniziale con una password riservata scelta dal cliente.

Dall'Area Riservata il cliente può in completa autonomia (senza database SQL né interventi sul codice):
1. Caricare o sostituire i PDF ufficiali (**Modello Organizzativo 231**, **Codice Etico**, **Informativa/Procedura Whistleblowing**), impostando numero di revisione e data di approvazione.
2. Inserire l'URL `https://` della piattaforma esterna **Whistleblowing (D.Lgs. 24/2023)** (finché il campo è vuoto, il sito mostra automaticamente lo stato istituzionale *"Canale telematico crittografato in attivazione"*).
3. Aggiornare recapiti, orari di apertura/accettazione campioni e visibilità/dettagli del box **Qualità UNI CEI EN ISO/IEC 17025 (ACCREDIA Lab N. 00859)**.
4. Sostituire in futuro il logo (versione fondo chiaro e fondo scuro) o ripristinare il marchio vettoriale **Goccia Molecolare**.
5. Consultare il registro di backup delle richieste inviate dal modulo contatti.

---

## 2. Configurazione Domini & 5 Caselle Email (GoDaddy / Hosting Linux PHP 8+)

### Strategia Domini
1. **`centroanalisipqa.it` (Dominio Primario):** puntare il record `A` (`@` e `www`) all'IP dell'hosting PHP 8+, attivare il certificato SSL/HTTPS gratuito (Let's Encrypt / AutoSSL) e decommentare le 3 righe di redirect HTTPS nel file `.htaccess` principale.
2. **`centroanalisipqa.com` (Tutela Brand):** impostare un **Inoltro Dominio con Redirect 301 permanente** verso `https://www.centroanalisipqa.it`.

### Schema Consigliato per le 5 Caselle Email
1. `info@centroanalisipqa.it` — Segreteria generale e destinatario del form contatti del sito.
2. `laboratorio@centroanalisipqa.it` — Accettazione campioni, comunicazioni tecniche e referti.
3. `direzione@centroanalisipqa.it` — Direzione Tecnica (Dott.ssa Maria Grazia Micieli).
4. `amministrazione@centroanalisipqa.it` — Fatturazione, fornitori e contabilità.
5. `odv@centroanalisipqa.it` — Casella dedicata all'**Organismo di Vigilanza ex D.Lgs. 231/2001**.

### Recapito Sicuro Posta (Anti-Spam DNS)
Nel pannello DNS del dominio `centroanalisipqa.it` verificare che siano attivi:
- **SPF** (autorizzazione sia del server posta GoDaddy sia dell'IP del server web per l'invio dal modulo contatti)
- **DKIM** (firma crittografica delle email in uscita)
- **DMARC** (`_dmarc.centroanalisipqa.it` TXT `v=DMARC1; p=quarantine; rua=mailto:info@centroanalisipqa.it`)

---

## 3. Avvio Locale Rapido per Test / Anteprima
Con PHP 8+ installato:
```powershell
C:\php82\php.exe -S 127.0.0.1:8080 router.php
```
Poi aprire `http://127.0.0.1:8080` per il sito pubblico e `http://127.0.0.1:8080/admin.php` per l'area riservata.
