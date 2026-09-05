(function(){
  "use strict";

  // ===================================================================
  // DATA
  // ===================================================================

  var EXTRACTION = [
    { id:"ext-pdf", title:"pdf2john.pl", meta:"→ -m 10400/10500/10600/10700", body:
      `<p>Für verschlüsselte PDFs. Der genaue hashcat-Modus hängt von der PDF-Revision/AES-Variante ab (steckt im Hash selbst — im Zweifel gegen <code>hashcat --example-hashes</code> abgleichen).</p>
      <div class="codewrap"><pre><code>pdf2john.pl Star.pdf &gt; star.john
sed -E "s/^[^:]+://" star.john &gt; star.hashcat</code></pre></div>` },
    { id:"ext-7z", title:"7z2john.pl", meta:"→ -m 11600", body:
      `<p>Für <code>.7z</code>-Archive.</p>
      <div class="codewrap"><pre><code>7z2john.pl Hurdle.jpg.7z &gt; hurdle.john
sed -E "s/^[^:]+://" hurdle.john &gt; hurdle.hashcat</code></pre></div>` },
    { id:"ext-zip", title:"zip2john", meta:"→ -m 17200/17225/13600", body:
      `<p>Für <code>.zip</code>-Archive — nicht Teil der aktuellen Aufgaben, aber Standard-Repertoire (PKZIP klassisch vs. WinZip/AES unterscheiden sich im Modus).</p>
      <div class="codewrap"><pre><code>zip2john Archiv.zip &gt; archiv.john
sed -E "s/^[^:]+://" archiv.john &gt; archiv.hashcat</code></pre></div>` },
    { id:"ext-keepass", title:"keepass2john", meta:"→ -m 13400", body:
      `<p>Für KeePass-Datenbanken. <strong>Achtung bei neueren <code>.kdbx</code>-Versionen/Argon2</strong> — siehe <a href="#" data-goto="sonder">Sonderheiten</a>.</p>
      <div class="codewrap"><pre><code>keepass2john "Max Müller.kdbx" &gt; kdbx.john
sed -E "s/^[^:]+://" kdbx.john &gt; kdbx.hashcat</code></pre></div>` },
    { id:"ext-libre", title:"libreoffice2john", meta:"→ -m 18400", body:
      `<p>Für ODF-Dateien (<code>.odt</code>/<code>.ods</code>/<code>.odp</code>) — <strong>Achtung:</strong> die <code>Numbers&lt;X&gt;</code>-Aufgabendateien sind trotz Namens echte ODF-Dateien, keine Apple-Numbers-Dateien. Braucht zusätzlich Suffix-Cleanup.</p>
      <div class="codewrap"><pre><code>libreoffice2john Numbers1.odt | sed -E -e 's/[^:]+://' -e 's/:::::[^:]+$//' &gt; Numbers1.hashcat</code></pre></div>` },
    { id:"ext-iwork", title:"iwork2john", meta:"→ -m 23300", body:
      `<p>Für echte Apple-iWork-Dateien: <code>.pages</code> / <code>.numbers</code> / <code>.key</code> (z. B. <code>Poem.pages</code>, <code>MySheet.numbers</code>, <code>Passwords.pages</code>).</p>
      <div class="codewrap"><pre><code>iwork2john Poem.pages &gt; poem.john
sed -E "s/^[^:]+://" poem.john &gt; poem.hashcat</code></pre></div>` },
    { id:"ext-office", title:"office2john.py", meta:"→ -m 9400/9500/9600", body:
      `<p>Für MS Office <code>.docx</code>/<code>.xlsx</code>/<code>.pptx</code> — nicht Teil der aktuellen Aufgaben.</p>
      <div class="codewrap"><pre><code>office2john.py Dokument.docx &gt; doc.john
sed -E "s/^[^:]+://" doc.john &gt; doc.hashcat</code></pre></div>` },
    { id:"ext-dmg", title:"dmg2john", meta:"→ -m 16400/16700 (oder direkt John)", body:
      `<p>Für verschlüsselte macOS-DMGs — nicht Teil der aktuellen Aufgaben. Wenn hashcat den Typ nicht kennt, direkt mit John angreifen.</p>
      <div class="codewrap"><pre><code>dmg2john Container.dmg &gt; dmg.john
john dmg.john --wordlist=/usr/share/wordlists/rockyou.txt</code></pre></div>` },
  ];

  var JOHN_ATTACK = [
    { id:"ja-wordlist", title:"john &lt;hash&gt; --wordlist=…", meta:"Wörterbuchangriff", body:
      `<div class="codewrap"><pre><code>john hurdle.john --wordlist=Passworte.txt</code></pre></div>
      <p>Sinnvoll direkt mit John, wenn hashcat den Hashtyp (noch) nicht unterstützt, oder für kleine, exakte Kandidatenlisten wie bei <code>Hurdle.jpg.7z</code>.</p>` },
    { id:"ja-rules", title:"john --rules=…", meta:"Regeln anwenden", body:
      `<div class="codewrap"><pre><code>john hurdle.john --wordlist=Passworte.txt --rules=best64</code></pre></div>` },
    { id:"ja-show", title:"john --show", meta:"Ergebnisse anzeigen", body:
      `<div class="codewrap"><pre><code>john --show hurdle.john</code></pre></div>` },
    { id:"ja-format", title:"john --format=…", meta:"Auto-Detect überstimmen", body:
      `<p>Falls John den Hashtyp falsch errät (z. B. bei generischen Hash-Strings ohne <code>*2john</code>-Kontext).</p>
      <div class="codewrap"><pre><code>john --format=Raw-SHA256 hash.txt --wordlist=/usr/share/wordlists/rockyou.txt</code></pre></div>` },
  ];

  var HC_MODES = [
    { id:"hm-a0", title:"-a0 — Wörterbuch", meta:"Standardfall", body:
      `<p>Beispiel: exakte 5-Wort-Kandidatenliste gegen <code>Hurdle.jpg.7z</code>.</p>
      <div class="codewrap"><pre><code>hashcat -m 11600 hurdle.hashcat -a0 Passworte.txt -r /usr/share/hashcat/rules/best64.rule</code></pre></div>` },
    { id:"hm-a1", title:"-a1 — Kombinationsangriff", meta:"Kreuzprodukt zweier Listen", body:
      `<p>Beispiel: zwei Wörter aneinandergehängt, wie bei <code>MySheet.numbers</code> (<code>HausMaus</code>, <code>AffeAffe</code>).</p>
      <div class="codewrap"><pre><code>hashcat -m 23300 mysheet.hashcat -a1 woerter.txt woerter.txt</code></pre></div>` },
    { id:"hm-a3", title:"-a3 — Brute-Force / Maske", meta:"alle Kandidaten gemäß Maske", body:
      `<p>Einfaches Beispiel: 5-stellige PIN als SHA-256.</p>
      <div class="codewrap"><pre><code>hashcat -m 1400 pin.sha256 -a3 "?d?d?d?d?d"</code></pre></div>
      <p class="hint">Für komplexere Policy-Masken (Großbuchstaben, Sonderzeichen-Klassen etc.) siehe <a href="#" data-goto="rest">Der Rest → Star.pdf</a>.</p>` },
    { id:"hm-a6", title:"-a6 — Hybrid (Wort + Maske)", meta:"Wort zuerst", body:
      `<div class="codewrap"><pre><code># Wort + 4 Ziffern
hashcat -m 1400 hash.sha256 candidates.txt -a6 "?d?d?d?d"</code></pre></div>` },
    { id:"hm-a7", title:"-a7 — Hybrid (Maske + Wort)", meta:"Maske zuerst", body:
      `<p>Beispiel: Jahreszahl vor ein Wort aus der Städteliste (Baustein der <code>Star.pdf</code>-Strategie).</p>
      <div class="codewrap"><pre><code>hashcat -m 10700 star.hashcat -a7 staedte.txt "202?d" -1 "0123456789"</code></pre></div>` },
  ];

  var HC_MASKS = [
    { id:"mk-builtin", title:"Eingebaute Zeichensätze", meta:"?l ?u ?d ?s ?a", body:
      `<div class="codewrap"><pre><code># 4-stellige PIN, nur Ziffern
hashcat -m 1400 pin.sha256 -a3 "?d?d?d?d"</code></pre></div>` },
    { id:"mk-custom", title:"Eigene Zeichensätze (-1…-4)", meta:"bis zu 4 eigene Klassen", body:
      `<p>Beispiel: nur <code>$</code>, <code>€</code>, <code>!</code> als Sonderzeichen-Klasse (Policy von <code>Star.pdf</code>).</p>
      <div class="codewrap"><pre><code>hashcat -m 10700 star.hashcat -a3 -1 '$€!' "?u?l?u?l?d?d?d?d?1?1?1?1"</code></pre></div>` },
  ];

  var HC_RULES = [
    { id:"rl-best64", title:"-r best64.rule", meta:"vortrainiert, guter Default", body:
      `<div class="codewrap"><pre><code>hashcat -m 0 hash.md5 -a0 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule</code></pre></div>` },
    { id:"rl-cross", title:"zwei -r kombinieren", meta:"Kreuzprodukt der Regelsätze", body:
      `<div class="codewrap"><pre><code>hashcat -m 1400 hash.sha256 candidates.txt -r number_prepend.rule -r sc_append.rule</code></pre></div>
      <div class="callout warn"><div class="kicker">Duplikate vermeiden</div><code>$1:</code> und <code>:$1</code> liefern dasselbe Ergebnis — kostet nur doppelt Rechenzeit.</div>` },
  ];

  var HC_BUILD = [
    { id:"bd-stdout", title:"--stdout — Kandidaten nur ausgeben", meta:"Zwischenwörterbuch bauen", body:
      `<p>Beispiel: Städteliste mit sich selbst kombinieren (Baustein der <code>Star.pdf</code>-Strategie).</p>
      <div class="codewrap"><pre><code>hashcat --stdout staedte.txt staedte.txt -j '$-' | tr -d '-' &gt; staedte-kombis.txt</code></pre></div>` },
    { id:"bd-prince", title:"princeprocessor", meta:"Fragment-Kombinatorik, pipebar", body:
      `<p>Beispiel: OSINT-Fragmente aus dem Profil von <code>Max Müller.md</code> kombinieren, direkt an hashcat pipen.</p>
      <div class="codewrap"><pre><code>princeprocessor --pw-min=6 --pw-max=20 osint.txt \\
  | hashcat -m 13400 kdbx.hashcat -r /usr/share/hashcat/rules/best64.rule</code></pre></div>` },
  ];

  var SONDER = [
    { id:"so-java", title:"Java String.hashCode() — kein Krypto-Hash", meta:"JavaHashcodes.txt", body:
      `<p><code>String.hashCode()</code> ist 32 Bit, unsalted, kollisionsanfällig — <strong>kein hashcat-Modus dafür.</strong> Richtiger Weg: Formel selbst nachbauen und Kandidaten durchtesten.</p>
      <div class="codewrap"><pre><code>s[0]*31^(n-1) + s[1]*31^(n-2) + ... + s[n-1]   (32-bit signed, mit Overflow)</code></pre></div>
      <div class="codewrap"><pre><code>def java_hashcode(s: str) -&gt; int:
    h = 0
    for c in s:
        h = (31 * h + ord(c)) &amp; 0xFFFFFFFF
    return h - 0x100000000 if h &gt;= 0x80000000 else h

target = {-1200548278, 1234567}  # aus JavaHashcodes.txt geladen
with open("/usr/share/wordlists/rockyou.txt", encoding="latin-1") as f:
    for word in f:
        word = word.rstrip("\\n")
        if java_hashcode(word) in target:
            print("Treffer:", word)</code></pre></div>
      <div class="callout warn"><div class="kicker">Kollisionen einplanen</div>32 Bit ⇒ ab ca. <code>2^16</code> Kandidaten wird ein Kollisionstreffer wahrscheinlich (Geburtstagsparadoxon, vgl. <a href="#" data-goto="theorie">Theorie → Hashfunktionen</a>). Jeden Treffer gegen den echten Kontext verifizieren. Reines Python ist für Millionen Kandidaten langsam — mit <code>multiprocessing</code> parallelisieren oder in C/Java nachbauen.</div>` },

    { id:"so-kdbx", title:"KeePass .kdbx — zu neue Datei-Version", meta:"Max Müller.kdbx", body:
      `<p><strong>Problem:</strong> <code>keepass2john</code> bricht ab oder liefert einen Hash, den die installierte hashcat-Version nicht kennt — wenn die <code>.kdbx</code>-Datei mit einer neueren KDBX-Version bzw. einem neueren KDF (Argon2d/Argon2id statt klassischem AES-KDF) erstellt wurde, als das lokale Tooling unterstützt.</p>
      <p><strong>Diagnose</strong> — Version steht im Header:</p>
      <div class="codewrap"><pre><code>xxd -l 12 "Max Müller.kdbx"
# Byte 0-3: Signature1 = 03 D9 A2 9A (immer)
# Byte 4-7: Signature2 = 67 FB 4B B5 (KDBX ≥ 3)
# Byte 8-11: Version, little-endian — 03 00 xx xx = KDBX3, 04 00 xx xx = KDBX4</code></pre></div>
      <ul>
        <li><strong>KDBX3</strong> → immer AES-KDF, von <code>-m 13400</code> in jeder halbwegs aktuellen hashcat-Version unterstützt.</li>
        <li><strong>KDBX4</strong> → KDF konfigurierbar: AES-KDF, Argon2d oder Argon2id. Argon2-Support in <code>-m 13400</code> gibt es erst ab neueren hashcat-Releases — ein veraltetes Distro-Paket (z. B. Kalis <code>apt</code>-Version) kann den Hash mit „Line-length exception" o. ä. ablehnen.</li>
      </ul>
      <p><strong>Fix:</strong></p>
      <ol>
        <li>Aktuellstes hashcat-Release direkt von <a href="https://hashcat.net/hashcat/" target="_blank" rel="noopener">hashcat.net</a> statt <code>apt</code>-Paket verwenden.</li>
        <li>John (jumbo) ebenfalls aktuell halten — bei Bedarf aus dem <a href="https://github.com/openwall/john" target="_blank" rel="noopener">GitHub-Repo</a> selbst bauen (<code>./configure &amp;&amp; make -sj4</code>).</li>
        <li>Erneut extrahieren, Hash gegen <code>hashcat --example-hashes -m 13400</code> (zeigt AES-KDF- <em>und</em> Argon2-Beispiel) abgleichen.</li>
      </ol>
      <div class="callout tip"><div class="kicker">Nebeneffekt</div>Argon2 ist absichtlich speicherhart — GPU-Beschleunigung bringt kaum etwas, ein Angriff auf eine Argon2-kdbx ist realistisch <em>viel</em> langsamer als auf eine AES-KDF-kdbx. Siehe <a href="#" data-goto="theorie">Theorie → Argon2 &amp; LUKS2</a>.</div>` },

    { id:"so-openssl", title:"OpenSSL — False Positives durch Padding", meta:"personal_information.aes256cbc_sha1", body:
      `<p>Dateiname verrät das Verfahren: <strong>OpenSSL <code>enc -aes-256-cbc -md sha1</code></strong> (klassischer SHA1-<code>EVP_BytesToKey</code>-KDF, Default vor OpenSSL 1.1.0). Kein hashcat-Modus nötig — direkt gegen <code>openssl</code> selbst testen.</p>
      <div class="codewrap"><pre><code>xxd personal_information.aes256cbc_sha1.encrypted | head -1   # "Salted__"-Header prüfen

while IFS= read -r pass; do
  if openssl enc -d -aes-256-cbc -md sha1 -pass "pass:$pass" \\
      -in personal_information.aes256cbc_sha1.encrypted \\
      -out /tmp/try.bin 2&gt;/dev/null; then
    typ=$(file -b /tmp/try.bin)
    echo "$typ" | grep -qv "^data$" &amp;&amp; echo "KANDIDAT: '$pass' -&gt; $typ"
  fi
done &lt; personal_information.aes256cbc_sha1.password_candidates.txt</code></pre></div>
      <div class="callout warn"><div class="kicker">Padding-Oracle</div><code>openssl</code> meldet auch bei <strong>falschem</strong> Passwort gelegentlich „Erfolg" — gültiges PKCS#7-Padding der letzten 1–16 Byte kann rein zufällig entstehen (~1/256 Wahrscheinlichkeit pro Kandidat). Bei größeren Kandidatenlisten sind mehrere Scheintreffer normal. <strong>Immer den entschlüsselten Inhalt prüfen</strong> (<code>file</code>-Typ, lesbarer Text) — nicht nur den Exit-Code. Gleiches Prinzip bei Archiven/Containern ohne Integritätsprüfung: erst der erfolgreiche Entpack-/Mount-Vorgang zählt.</div>` },

    { id:"so-mode", title:"Falscher/veralteter Hash-Modus geraten", meta:"PDF-Revision, ZIP-Variante", body:
      `<p>Häufige Fehlerquelle: der falsche <code>-m</code>-Wert für eine an sich richtig extrahierte Datei.</p>
      <ul>
        <li><strong>PDF:</strong> <code>-m 10500</code> (Acrobat 5–8, RC4/AES-128) vs. <code>-m 10700</code> (Acrobat 9+, AES-256) — <code>pdf2john</code>s Ausgabe selbst enthält die Revision/V-Nummer, die den Unterschied verrät.</li>
        <li><strong>ZIP:</strong> klassisches PKZIP (<code>-m 17200/17210/17220/17225/17230</code>, je nach Kompressionsverfahren) vs. WinZip/AES (<code>-m 13600</code>).</li>
      </ul>
      <p>Bei Unsicherheit: bereinigten Hash-String Zeichen für Zeichen gegen <code>hashcat --example-hashes</code> für die in Frage kommenden Modi vergleichen, statt zu raten und Rechenzeit zu verschwenden.</p>` },
  ];

  var TASKS = [
    { id:"tk-numbers", title:"Numbers&lt;X&gt; (.odt/.ods) &amp; Poem.pages", meta:"Dateiendung lügt", body:
      `<p>Keine Kontextinfos vorhanden → allgemeine Best Practices. <strong>Wichtigster Schritt zuerst:</strong> <code>file</code> statt der Endung glauben — die <code>Numbers&lt;X&gt;</code>-Dateien sind trotz Namens echte <strong>LibreOffice/ODF</strong>-Dateien (siehe Basics → <code>libreoffice2john</code>), <code>Poem.pages</code> ist eine echte <strong>Apple-Pages</strong>-Datei (→ <code>iwork2john</code>). Danach: rockyou + <code>best64</code>, bei Erfolglosigkeit Hybrid/Maske.</p>` },
    { id:"tk-star", title:"Star.pdf — vollständige Masken-/Kombinationsstrategie", meta:"Policy bekannt", body:
      `<p>Policy: ≥2 Großbuchst., ≥2 Kleinbuchst., ≥4 Ziffern, ≥4 Sonderzeichen (<code>$ € !</code>, oft wiederholt), Mindestlänge 16, Muster <code>&lt;Jahr&gt;&lt;Stadt1&gt;&lt;Stadt2&gt;&lt;Sonderzeichen&gt;</code>.</p>
      <div class="codewrap"><pre><code># 1) Städteliste (große dt. Städte) mit sich selbst kombinieren
hashcat --stdout staedte.txt staedte.txt -j '$-' | tr -d '-' &gt; stadt-kombis.txt

# 2) Jahreszahl voranstellen (Hybrid, Maske zuerst)
hashcat -m 10700 star.hashcat -a7 stadt-kombis.txt "202?d" -1 "0123456789"

# 3) Sonderzeichen-Suffix ergänzen (eigener Zeichensatz nur $/€/!)
hashcat -m 10700 star.hashcat -a6 jahr-stadt-kombis.txt "?1?1?1?1" -1 '$€!'</code></pre></div>
      <p>Alternativ alles in einem <code>-a3</code>-Maskenlauf, wenn die Städteliste kurz genug ist, um sie direkt als Maskenteil zu behandeln — meist ist Kombinieren-dann-Anhängen aber schneller.</p>` },
    { id:"tk-mysheet", title:"MySheet.numbers — Kombinator + Case-Regel im Detail", meta:"nur Buchstaben, ≥8 Zeichen", body:
      `<p>Nur Buchstaben, korrekte Groß-/Kleinschreibung (<code>Frankfurt</code>), Wörter oft zusammengezogen (<code>HausMaus</code>, <code>AffeAffe</code>, <code>alleLieben</code>).</p>
      <div class="codewrap"><pre><code># Basisliste bereits korrekt großgeschrieben
hashcat -m 23300 mysheet.hashcat -a1 woerter.txt woerter.txt

# Falls Basisliste kleingeschrieben vorliegt: erst Capitalize-Regel anwenden
hashcat --stdout woerter_lower.txt -r &lt;(echo c) &gt; woerter_cap.txt
hashcat -m 23300 mysheet.hashcat -a1 woerter_cap.txt woerter_cap.txt</code></pre></div>` },
    { id:"tk-passwords", title:"Passwords.pages — Köder-Dateiname", meta:"nicht täuschen lassen", body:
      `<p>Der Dateiname ist ein Köder — nicht davon ausgehen, dass das Passwort trivial ist, nur weil die Datei „Passwords" heißt. Kurzer Trivial-Check (leer, <code>password</code>, Dateiname selbst) lohnt sich trotzdem, bevor der Standardweg (rockyou + <code>best64</code> über <code>iwork2john</code>) läuft.</p>` },
    { id:"tk-kdbx-osint", title:"Max Müller.kdbx — OSINT-Wortliste aus dem Profil bauen", meta:"Max Müller.md als Basis", body:
      `<p>Profilbeschreibung auswerten: Vornamen, Nachname, Geburtsdatum, Ort, Straße, Haustiername, Hobbys → als Fragmente in <code>osint.txt</code> sammeln, mit Princeprocessor kombinieren (siehe Basics → <code>princeprocessor</code>).</p>
      <div class="callout tip"><div class="kicker">Datumsformate nicht vergessen</div>Geburtsdaten in mehreren Schreibweisen aufnehmen: <code>1990</code>, <code>90</code>, <code>19900504</code>, <code>04051990</code>, <code>0405</code> — Menschen variieren das kaum, aber unvorhersehbar genug, dass man alle Varianten braucht.</div>` },
  ];

  var THEORIE = [
    { id:"th-usage", title:"Warum Passwörter noch überall sind", meta:"Verwendung & Biometrie-Grenzen", body:
      `<ul>
        <li>Passwörter sind trotz Alternativen weiterhin allgegenwärtig: Smartphones, Cryptosticks, Logins, verschlüsselte Dateien/Datenträger (FileVault, VeraCrypt).</li>
        <li>Biometrie ist oft kein vollständiger Ersatz, nur Ergänzung. Rechtslage DE (Stand 2025): ein Beschuldigter darf ggf. gezwungen werden, das Gesicht/den Finger zum Entsperren herzuhalten — die <em>Preisgabe eines Passworts</em> kann er dagegen verweigern, ohne dass es eine direkte Handhabe dagegen gibt.</li>
      </ul>` },
    { id:"th-threat", title:"Die Bedrohungslage ist real", meta:"Spraying, Leaks, GPU-Realität", body:
      `<ul>
        <li><strong>Password Spraying:</strong> Microsoft meldete 2024 einen Einbruch russischer Angreifer über ein altes Testkonto per Password Spraying — kein Software-Bug, sondern schwaches Passwort-Hygiene-Problem.</li>
        <li><strong>NTLM-Leaks:</strong> ein Outlook-Bug (2024) erlaubte das Auslesen von NTLMv2-Hashes beim Öffnen präparierter Dateien.</li>
        <li><strong>GPU-Realität:</strong> Kaspersky knackte 2024 mit einer RTX 4090 knapp 59 % einer 193-Mio.-Passwort-Datenbank (gesalzene MD5-Hashes) innerhalb einer Stunde.</li>
        <li><strong>RockYou2024:</strong> ~9,95 Mrd. Klartext-Passwörter aus alten und neuen Leaks kompiliert und veröffentlicht — riesiges Trainingsmaterial für Angreifer <em>und</em> Verteidiger.</li>
        <li><strong>Faustregel Crack-Zeit</strong> (grob, hardwareabhängig): 6-stellig nur Ziffern/Kleinbuchstaben → praktisch sofort; 8-stellig gemischt mit Sonderzeichen → Stunden; 12-stellig gemischt mit Sonderzeichen → Jahrtausende. Länge schlägt Komplexität.</li>
      </ul>` },
    { id:"th-searchspace", title:"Suchraum & Mathematik", meta:"Formeln + Beispielzahlen", body:
      `<ul>
        <li>Grundformel: <code>Zeichensatzgröße^Länge</code> bzw. für Passphrasen <code>Wörterbuchgröße^Wortanzahl</code>.</li>
        <li>4-stellige PIN: 10.000 Kombinationen — <strong>niemals sicher</strong>, selbst bei nur 4–5 Versuchen/Stunde in wenigen Monaten brechbar.</li>
        <li>8 Zeichen, 70er-Zeichensatz: 70⁸ ≈ 5,7 × 10¹⁴.</li>
        <li>Passphrase, 6 Wörter aus 2.000-Wörter-Liste: 2.000⁶ ≈ 6,4 × 10¹⁹.</li>
        <li>Passphrase, 4 Wörter aus 100.000-Wörter-Liste: 100.000⁴ = 1 × 10²⁰.</li>
        <li>16 Zeichen, 84er-Zeichensatz: 84¹⁶ ≈ 6,14 × 10³⁰.</li>
        <li>Diceware (6 Würfelwörter aus 6⁵-Wörterbuch): (6⁵)⁶ ≈ 2,21 × 10²³ — selbst mit 1 Billion Hashes/s über 7.000 Jahre für den vollen Suchraum.</li>
      </ul>` },
    { id:"th-hashfn", title:"Hashfunktionen & warum Standard-Hashes ungeeignet sind", meta:"H(M)=h, KDF-Überblick", body:
      `<ul>
        <li>Eine Hashfunktion <code>H</code> bildet beliebig lange Nachrichten <code>M</code> auf einen Wert fester Länge ab: <code>h = H(M)</code>. Eine Bitänderung in <code>M</code> soll <code>h</code> mit hoher Wahrscheinlichkeit ändern (Lawineneffekt).</li>
        <li>Kollisionen sind bei jeder Hashfunktion unvermeidbar; kryptografische Hashfunktionen machen das Finden einer Kollision in der Praxis unmöglich — eine „normale" Hashfunktion (wie <code>String.hashCode()</code>) bietet diesen Schutz nicht.</li>
        <li><strong>MD5, SHA-256, SHA-512, RIPE-MD sind für Passwort-Hashing ungeeignet</strong> — zu schnell berechenbar, kein eingebautes Key-Stretching.</li>
        <li>Spezialisierte KDFs: <strong>PBKDF2</strong> (Ethereum-Wallets), <strong>bcrypt</strong> (Blowfish-basiert, OpenBSD), <strong>scrypt</strong> (u. a. Smartphone-Passwort-Hashing), <strong>Argon2</strong> (z. B. LUKS2), <strong>yescrypt</strong> (moderne Linux-Distros). Alle sind parametrisierbar (Laufzeit/Speicher), um Angriffe zu verlangsamen.</li>
      </ul>` },
    { id:"th-pbkdf2", title:"PBKDF2 im Detail", meta:"5 Parameter, HMAC, OWASP", body:
      `<ul>
        <li><code>DK = PBKDF2(PRF, Password, Salt, c, dkLen)</code> — PRF (meist HMAC), Passwort, Salt, Rundenzähler <code>c</code>, gewünschte Schlüssellänge <code>dkLen</code>.</li>
        <li>PBKDF2 hasht nicht selbst, sondern iteriert eine Basis-Hashfunktion (Key-Stretching).</li>
        <li>Bei einer Runde entspricht das Ergebnis exakt einem HMAC, wobei die Blocknummer (<code>\\x00\\x00\\x00\\x01</code>) an den Salt angehängt wird — Passwort ist der HMAC-Key, Salt(+Blocknummer) die Nachricht.</li>
        <li><strong>OWASP-Empfehlung:</strong> PBKDF2-HMAC-SHA512 mit ≥ 600.000 Iterationen.</li>
      </ul>` },
    { id:"th-saltpepper", title:"Salt & Pepper", meta:"Zweck, Anforderungen, Rainbow Tables", body:
      `<ul>
        <li><strong>Salt:</strong> verhindert, dass identische Passwörter identische Hashes ergeben → macht Rainbow-Table-Angriffe (heute fast nur historisch relevant) wirkungslos. Anforderungen: einzigartig pro Nutzer, ausreichend lang (≥16 Byte), keine Geheimhaltung nötig, wird zusammen mit dem Hash gespeichert.</li>
        <li><strong>Pepper (Secret Key):</strong> geht wie ein Salt in den Hash ein, wird aber <strong>nicht</strong> mit den Hashes gespeichert — idealerweise in einem HSM/TPM. Sollte zufällig, ≥16 Byte lang und pro Anwendungsinstanz einmalig sein. Schützt selbst dann noch, wenn Hash+Salt und sogar das Klartextpasswort einem Angreifer bekannt werden (Brute-Force auf den Pepper selbst wird durch die Länge verhindert).</li>
      </ul>` },
    { id:"th-argon2", title:"Argon2 & LUKS2", meta:"Speicherhärte gegen GPU", body:
      `<ul>
        <li>LUKS2 nutzt standardmäßig Argon2 als KDF — bewusst so gestaltet, dass GPU-Beschleunigung praktisch nicht greift (Speicherhärte).</li>
        <li>Reale Zahl (Elcomsoft): auf einem Intel i7-9700K lassen sich nur ~2 Passwörter/Sekunde gegen LUKS2/Argon2 testen — im Kontrast zu Millionen/Sekunde bei ungesalzenen schnellen Hashes.</li>
        <li>Praxisrelevanz: siehe <a href="#" data-goto="sonder">Sonderheiten → KDBX zu neue Version</a> — dasselbe Prinzip gilt für KeePass-4-Datenbanken mit Argon2d/id.</li>
      </ul>` },
    { id:"th-structure", title:"Wie echte Passwörter aufgebaut sind", meta:"RockYou-Strukturanalyse", body:
      `<ul>
        <li>Menschliche Passwörter kombinieren häufig: PINs, Keyboard-Walks (<code>asdfg</code>), Patterns (<code>abcabc</code>), Wörterbuchwörter, Kontextinfos (Szene-Codes wie <code>1488</code>/<code>acab</code>, privates Umfeld: Namen, Geburtsort).</li>
        <li>Im RockYou-Leak: nur ~16 % reine PINs, ~83 % enthalten Buchstaben. Von den Buchstaben-Passwörtern sind <strong>~50 % komplexe Wortkombinationen</strong> (z. B. <code>kelseylovesbarry</code>) und ~41 % einzelne reguläre/populäre Wörter — Leetspeak, Sequenzen und Keyboard-Walks sind dagegen selten (&lt;1 % je Kategorie).</li>
        <li><strong>Policy-Effekt:</strong> zwingt eine Richtlinie zur Erweiterung eines bereits gewählten Passworts, wird meist mit minimalem Aufwand erweitert (<code>Password11##</code> → <code>Password12!!</code>) statt ein neues Passwort zu wählen.</li>
      </ul>` },
    { id:"th-methodik", title:"Angreifer-Methodik jenseits Brute-Force", meta:"Prince, OMEN, PCFG, SePass", body:
      `<ul>
        <li>Prinzip: Kontextwissen nutzen, nur technisch valide Kandidaten testen, keine Duplikate, absteigende Wahrscheinlichkeit, effiziente Generierung.</li>
        <li><strong>Prince:</strong> kombiniert Fragmente einer Wortliste zu neuen Kandidaten (siehe Basics → <code>princeprocessor</code>).</li>
        <li><strong>OMEN (Markov-Ketten):</strong> lernt Wahrscheinlichkeiten für aufeinanderfolgende Bi-/Trigramme aus Leaks und generiert damit neue, statistisch plausible Kandidaten.</li>
        <li><strong>PCFG:</strong> lernt Basisstrukturen (z. B. <code>L3S1D3</code> für <code>cat!123</code>) mit Wahrscheinlichkeiten aus Leaks und füllt sie aus Wortlisten — generiert Kandidaten in absteigender Wahrscheinlichkeit.</li>
        <li><strong>SePass:</strong> nutzt Word-Embeddings (k-NN-Ähnlichkeitssuche), um thematisch verwandte Wörter zu finden, ohne menschliche Voreingenommenheit — z. B. aus <code>Ferrari01</code>/<code>Mercedes88</code> automatisch <code>Porsche</code>/<code>Lamborghini</code> als Kandidaten ableiten.</li>
      </ul>` },
    { id:"th-quality", title:"Passwortqualität einschätzen — Beispiele aus der VL", meta:"Bewertungsmuster erkennen", body:
      `<ul>
        <li><code>Donaudampfschifffahrt</code>: selten/kein Leak-Treffer, aber ein einzelnes echtes Wort — falsche Sicherheit.</li>
        <li><code>Emily060218</code>: Name + Datum-Muster (6. Feb. 2018) — Datum ist oft ein bedeutsames Ereignis, nicht zufällig.</li>
        <li><code>MuenchenHamburg2023!!!!</code>: lang, aber erkennbares Muster aus zwei bedeutsamen Orten + policy-getriebenem Zahlen-/Sonderzeichen-Anhang.</li>
        <li><code>Baum Lampe Haus Steak Eis Berg</code>: 6-Wort-Diceware-Passphrase — selbst mit bekannter Methode, Wortliste und Wortanzahl bleibt der Suchraum (6⁵)⁶ ≈ 2,21 × 10²³ riesig.</li>
      </ul>` },
    { id:"th-secure", title:"Empfehlungen & Passwortmanager-Realität", meta:"Was wirklich hilft", body:
      `<ul>
        <li>Kein 1:1-Wörterbuch-/Verzeichnis-/Leak-Passwort (vgl. haveibeenpwned.com), keine Szene-Begriffe.</li>
        <li>Länge schlägt Komplexität — aber keine trivialen, vorhersehbaren Sätze.</li>
        <li>Gut merkbare, aber niemand-erratbare private Kombinationen (nicht Kindername/Haustiername direkt, eher z. B. Fernseher-Modell + PIN + Name des ersten Smartphones, getrennt durch Sonderzeichen).</li>
        <li>Passwortmanager nutzen — aber auch die sind kein Allheilmittel: das BSI fand 2024 bei Vaultwarden u. a. einen fehlenden Offboarding-Prozess (ausgeschiedene Mitglieder behalten den Master-Schlüssel) und eine HTML-Injection-Lücke im Admin-Dashboard (CVE-2024-39926).</li>
      </ul>` },
  ];

  // ===================================================================
  // ACCORDION RENDERING
  // ===================================================================

  function renderAccordion(containerId, items){
    var container = document.getElementById(containerId);
    if(!container) return;
    items.forEach(function(item){
      var el = document.createElement("div");
      el.className = "acc";
      el.id = item.id;
      el.setAttribute("data-idx", "1");
      el.innerHTML =
        '<div class="acc-head" role="button" tabindex="0">' +
          '<span class="ttitle" data-idx-title>' + item.title + '</span>' +
          (item.meta ? '<span class="tmeta">' + item.meta + '</span>' : '') +
          '<span class="chev">▸</span>' +
        '</div>' +
        '<div class="acc-body"><div class="acc-body-inner">' + item.body + '</div></div>';
      container.appendChild(el);
      var head = el.querySelector(".acc-head");
      var body = el.querySelector(".acc-body");
      function toggle(forceOpen){
        var open = forceOpen === true ? true : (forceOpen === false ? false : !el.classList.contains("open"));
        el.classList.toggle("open", open);
        body.style.maxHeight = open ? body.scrollHeight + "px" : "0px";
      }
      head.addEventListener("click", function(){ toggle(); });
      head.addEventListener("keydown", function(e){ if(e.key==="Enter"||e.key===" "){ e.preventDefault(); toggle(); } });
      el._toggle = toggle;
    });
  }

  renderAccordion("acc-extraction", EXTRACTION);
  renderAccordion("acc-john-attack", JOHN_ATTACK);
  renderAccordion("acc-hc-modes", HC_MODES);
  renderAccordion("acc-hc-masks", HC_MASKS);
  renderAccordion("acc-hc-rules", HC_RULES);
  renderAccordion("acc-hc-build", HC_BUILD);
  renderAccordion("acc-sonder", SONDER);
  renderAccordion("acc-tasks", TASKS);
  renderAccordion("acc-theorie", THEORIE);

  // ===================================================================
  // VIEW SWITCHING
  // ===================================================================

  var views = Array.prototype.slice.call(document.querySelectorAll(".view"));
  var tabbtns = Array.prototype.slice.call(document.querySelectorAll(".tabbtn"));

  function switchView(viewId){
    views.forEach(function(v){ v.classList.toggle("active", v.id === viewId); });
    tabbtns.forEach(function(b){ b.classList.toggle("active", b.dataset.view === viewId); });
  }
  tabbtns.forEach(function(b){ b.addEventListener("click", function(){ switchView(b.dataset.view); }); });
  switchView("basics");

  // cross-reference links inside content: <a data-goto="sonder">
  document.addEventListener("click", function(e){
    var a = e.target.closest && e.target.closest("[data-goto]");
    if(a){
      e.preventDefault();
      switchView(a.getAttribute("data-goto"));
      window.scrollTo({ top: 0, behavior: "smooth" });
    }
  });

  // ===================================================================
  // COPY BUTTONS
  // ===================================================================

  function wireCopyButtons(){
    document.querySelectorAll("pre").forEach(function(pre){
      if(pre.dataset.wired) return;
      pre.dataset.wired = "1";
      var wrap = pre.parentElement.classList.contains("codewrap") ? pre.parentElement : (function(){
        var w = document.createElement("div");
        w.className = "codewrap";
        pre.parentNode.insertBefore(w, pre);
        w.appendChild(pre);
        return w;
      })();
      var btn = document.createElement("button");
      btn.className = "copybtn";
      btn.textContent = "Kopieren";
      btn.addEventListener("click", function(){
        navigator.clipboard.writeText(pre.innerText).then(function(){
          btn.textContent = "Kopiert!";
          setTimeout(function(){ btn.textContent = "Kopieren"; }, 1200);
        });
      });
      wrap.appendChild(btn);
    });
  }
  wireCopyButtons();

  // ===================================================================
  // THEME TOGGLE (light default, dark opt-in)
  // ===================================================================

  var root = document.documentElement;
  var themeBtn = document.getElementById("themeBtn");
  function applyTheme(t){
    if(t === "dark"){ root.setAttribute("data-theme", "dark"); } else { root.removeAttribute("data-theme"); }
  }
  try {
    var saved = localStorage.getItem("theme");
    if(saved === "dark") applyTheme("dark");
  } catch(e){}
  themeBtn.addEventListener("click", function(){
    var next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
    applyTheme(next);
    try { localStorage.setItem("theme", next); } catch(e){}
  });

  // ===================================================================
  // GLOBAL SEARCH
  // ===================================================================

  var searchIndex = [];
  function buildSearchIndex(){
    searchIndex = [];
    views.forEach(function(view){
      var label = view.dataset.label;
      view.querySelectorAll("[data-idx]").forEach(function(el){
        var titleEl = el.querySelector("[data-idx-title]");
        searchIndex.push({
          view: view.id,
          viewLabel: label,
          id: el.id,
          title: titleEl ? titleEl.textContent : el.id,
          text: el.textContent
        });
      });
      // also index plain headings (h2) as jump targets for top-level topics
      view.querySelectorAll("h2[id]").forEach(function(h){
        searchIndex.push({ view: view.id, viewLabel: label, id: h.id, title: h.textContent, text: h.textContent });
      });
    });
  }
  buildSearchIndex();

  var searchInput = document.getElementById("search");
  var searchResults = document.getElementById("searchresults");

  function renderResults(query){
    var q = query.trim().toLowerCase();
    if(!q){ searchResults.hidden = true; searchResults.innerHTML = ""; return; }
    var matches = searchIndex.filter(function(item){
      return item.title.toLowerCase().indexOf(q) !== -1 || item.text.toLowerCase().indexOf(q) !== -1;
    }).slice(0, 8);
    if(matches.length === 0){
      searchResults.innerHTML = '<div class="sr-empty">Keine Treffer.</div>';
      searchResults.hidden = false;
      return;
    }
    searchResults.innerHTML = matches.map(function(m, i){
      var snippet = m.text.replace(/\\s+/g, " ").trim().slice(0, 140);
      return '<div class="sr-item' + (i===0?' active':'') + '" data-view="' + m.view + '" data-id="' + m.id + '">' +
        '<div class="sr-view">' + m.viewLabel + '</div>' +
        '<div class="sr-title">' + m.title + '</div>' +
        '<div class="sr-snippet">' + snippet + '</div>' +
      '</div>';
    }).join("");
    searchResults.hidden = false;
  }

  function jumpTo(viewId, id){
    switchView(viewId);
    searchResults.hidden = true;
    setTimeout(function(){
      var target = document.getElementById(id);
      if(!target) return;
      target.scrollIntoView({ behavior: "smooth", block: "start" });
      if(target.classList.contains("acc") && target._toggle) target._toggle(true);
      target.classList.add("flash");
      setTimeout(function(){ target.classList.remove("flash"); }, 1600);
    }, 30);
  }

  searchInput.addEventListener("input", function(){ renderResults(searchInput.value); });
  searchInput.addEventListener("keydown", function(e){
    if(e.key === "Escape"){ searchResults.hidden = true; searchInput.blur(); }
    if(e.key === "Enter"){
      var first = searchResults.querySelector(".sr-item");
      if(first){ jumpTo(first.dataset.view, first.dataset.id); searchInput.value = ""; }
    }
  });
  searchResults.addEventListener("click", function(e){
    var item = e.target.closest(".sr-item");
    if(item){ jumpTo(item.dataset.view, item.dataset.id); searchInput.value = ""; }
  });
  document.addEventListener("click", function(e){
    if(!e.target.closest(".searchwrap")) searchResults.hidden = true;
  });

})();
