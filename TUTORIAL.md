# SaQura PQC Scan — einfach erklärt

Ein Tutorial für alle, die kein Krypto-Experte sind, aber verstehen wollen,
**was dieses Werkzeug macht und warum es wichtig ist.**

---

## 1. Worum geht es hier überhaupt?

Fast jede Software benutzt **Verschlüsselung** — eine Art digitales Schloss.
Es schützt Passwörter, Nachrichten, Zahlungen, Verträge.

Die Schlösser, die heute fast überall stecken (sie heißen **RSA** und **ECC**),
gelten seit Jahrzehnten als sicher. Aber:

> **Ein neuer Computertyp — der Quantencomputer — wird diese Schlösser knacken können.**

Das ist keine Science-Fiction-Spinnerei, sondern der Grund, warum Behörden wie das
deutsche **BSI** und die EU-Richtlinie **NIS2** Unternehmen auffordern, rechtzeitig auf
**neue, quantensichere Schlösser** umzustellen.

### Warum „rechtzeitig"? Das Problem heißt *„heute klauen, später öffnen"*

Stellen Sie sich vor, ein Dieb kopiert heute Ihre verschlossene Schatztruhe.
Öffnen kann er sie (noch) nicht. Aber er hebt die Kopie auf — und in ein paar Jahren,
wenn er den passenden Generalschlüssel (den Quantencomputer) hat, öffnet er sie in Ruhe.

Genau das passiert gerade mit abgefangenen, verschlüsselten Daten. **Deshalb ist die
Umstellung schon heute relevant** — auch wenn der Quantencomputer erst später kommt.

---

## 2. Was macht dieses Werkzeug?

Bevor man etwas umstellt, muss man erst einmal wissen: **Wo stecken überhaupt die alten
Schlösser in meiner Software?** Das herauszufinden ist Handarbeit — oder man lässt es
dieses Werkzeug erledigen.

**SaQura PQC Scan liest Ihren Programm-Code durch und erstellt eine Liste:**

- 🔴 **Quantenverwundbar** — alte Schlösser (RSA, ECC …), die der Quantencomputer knacken wird. *Hier besteht Handlungsbedarf.*
- 🟠 **Schon heute unsicher** — veraltete Verfahren (z. B. MD5, DES), die bereits als gebrochen gelten.
- 🟡 **Unklar** — Bibliotheken, die beides können; bitte prüfen.
- 🟢 **Quantensicher** — moderne Verfahren (z. B. ML-KEM), die auch dem Quantencomputer standhalten.

Heraus kommen **zwei Dinge**:

1. Ein **leicht lesbarer Bericht** mit einer Prozent-Note („Quantum-Readiness-Score").
2. Eine **technische Inventarliste** (`cbom.json`) in einem offenen Standard-Format
   (CycloneDX) — die kann man z. B. einem Prüfer oder Berater geben.

Das Werkzeug ist **kostenlos** und **verändert nichts** an Ihrem Code — es schaut nur hin.

---

## 3. Was brauche ich, um es zu benutzen?

Es gibt zwei Wege. Suchen Sie sich den passenden aus:

| Weg | Für wen | Voraussetzung |
|---|---|---|
| **A) Einmal schnell prüfen** | „Ich will jetzt einmal wissen, wie es um mein Projekt steht." | Ein Computer mit [Node.js](https://nodejs.org) (kostenlos) |
| **B) Automatisch mitlaufen lassen** | „Mein Code liegt auf GitHub und soll bei jeder Änderung automatisch geprüft werden." | Ein GitHub-Konto/Projekt |

> Beides ist für Entwickler gedacht — aber die Schritte sind so einfach, dass Sie auch
> als technisch interessierter Laie mitkommen.

---

## 4. Weg A — Einmal schnell prüfen (ein Befehl)

1. **Node.js installieren** (falls noch nicht vorhanden): [nodejs.org](https://nodejs.org) → den großen Download-Knopf → installieren. Damit bekommen Sie auch den Befehl `npx`.
2. Ein **Terminal** öffnen (Windows: „Eingabeaufforderung" oder „PowerShell"; Mac: „Terminal").
3. In den Ordner Ihres Projekts wechseln und diesen **einen Befehl** eingeben:

```bash
npx saqura-pqc-scan .
```

Der Punkt `.` bedeutet „prüfe den aktuellen Ordner". Das Werkzeug lädt sich kurz selbst,
durchsucht den Code und zeigt den Bericht direkt im Fenster an. **Fertig.**

Möchten Sie den Bericht und die Inventarliste als Dateien speichern:

```bash
npx saqura-pqc-scan . --report bericht.md --cbom inventar.json
```

---

## 5. Weg B — Automatisch bei jeder Code-Änderung (GitHub)

Wenn Ihr Code auf **GitHub** liegt, kann die Prüfung **von selbst** bei jeder Änderung
laufen und das Ergebnis direkt an den Vorschlag (den „Pull Request") schreiben.

Legen Sie dazu im Projekt eine Datei `.github/workflows/pqc-scan.yml` mit diesem Inhalt an:

```yaml
name: PQC Scan
on: [pull_request]

permissions:
  contents: read
  pull-requests: write

jobs:
  pqc:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: kyototech/saqura-pqc-scan@v1
        with:
          comment-on-pr: 'true'
```

Ab jetzt erscheint bei jeder Änderung automatisch ein Kommentar mit dem aktuellen
Quantum-Readiness-Bericht. Man muss nichts weiter tun.

---

## 6. Den Bericht lesen (Beispiel)

So sieht ein Ergebnis aus — hier ein absichtlich „schlechtes" Beispielprojekt:

> ## 🛡️ SaQura PQC Scan — Quantum-Readiness Report
>
> **Quantum-Readiness Score: 🔴 10 %** (at risk)
>
> | Kategorie | Funde |
> |---|---:|
> | 🔴 Quantenverwundbar (RSA/ECC/DH) | 10 |
> | 🟠 Schon heute unsicher (MD5/DES/…) | 9 |
> | 🟢 Quantensicher (ML-KEM/…) | 2 |

**Wie ist das zu verstehen?**

- **Der Score (0–100 %)** sagt, *welcher Anteil* der gefundenen Verschlüsselung schon
  quantensicher ist. **Höher = besser.**
  - 🟢 **90–100 %** — größtenteils zukunftssicher
  - 🟡 **50–89 %** — teils sicher, es gibt etwas zu tun
  - 🔴 **unter 50 %** — viel alte Krypto, Handlungsbedarf
  - ⚪ **N/A** — es wurde gar keine Verschlüsselung gefunden
- **Jeder rote/orange Fund** kommt mit **Datei und Zeile**, damit ein Entwickler genau
  weiß, wo er nachschauen muss.

> 10 % heißt also: In diesem Beispiel ist fast alles alte, knackbare Krypto — höchster
> Handlungsbedarf. Bei Ihrem echten Projekt ist der Wert hoffentlich deutlich höher.

---

## 7. Und jetzt? Was tue ich mit dem Ergebnis?

Der Scan **findet** das Problem. Das Lösen ist der nächste Schritt:

- **Selbst umstellen:** SaQura bietet die quantensicheren Schlösser als fertigen Baustein
  für gängige Programmiersprachen — zum Ausprobieren kostenlos: **[saqura.de/docs](https://saqura.de/docs)**
- **Hilfe holen:** Wer eine vollständige Bestandsaufnahme und einen Umstellungsplan
  (inkl. der Bereiche, die dieser Gratis-Scan nicht sieht) möchte:
  **[saqura.de/contact](https://saqura.de/contact)**
- **In 30 Sekunden sehen, worum es geht:** alt vs. quantensicher nebeneinander:
  **[saqura.de/try](https://saqura.de/try)**

---

## 8. Ehrlich gesagt: Was der Scan *nicht* kann

Damit keine falschen Erwartungen entstehen:

- Er prüft **Programm-Code und dessen Bausteine** — **nicht** den laufenden Server,
  fertige Programmdateien, Geräte-Firmware, TLS-/Zertifikatseinstellungen oder
  zugekaufte Software ohne Quellcode.
- Er arbeitet mit **Mustererkennung** — ein guter, schneller erster Überblick, aber
  keine 100-%-Garantie und **kein** Zertifikat oder Prüfsiegel.

Sehen Sie ihn als **Gesundheits-Schnelltest**: Er zeigt schnell und kostenlos, ob und wo
es brennt — die gründliche Untersuchung ist der nächste Schritt.

---

**Kurzfassung:** Quantencomputer werden heutige Verschlüsselung knacken.
Dieses kostenlose Werkzeug zeigt Ihnen in einer Minute, wo in Ihrer Software noch die
alten, knackbaren Verfahren stecken — und SaQura hilft Ihnen, sie auszutauschen.
