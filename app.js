(function(){
  "use strict";

  // ===================================================================
  // DATA
  // ===================================================================

  var EXTRACTION = [
    { id:"ext-pdf", title:"pdf2john.pl — Star.pdf", meta:"→ -m 10400–10700", body:
      `<p><strong>Wofür:</strong> verschlüsselte PDF-Dateien. Der genaue hashcat-Modus hängt von der PDF-Revision/AES-Variante ab — er steckt im Hash selbst (P = RC4-128, ev. AES-256).</p>
       <p><strong>Hintergrund der Aufgabe Star.pdf:</strong> Die PDF ist mit einer Policy-Maske verschlüsselt (<code>&lt;Jahr&gt;&lt;Stadt1&gt;&lt;Stadt2&gt;&lt;Sonderzeichen&gt;</code>), d. h. das Passwort folgt einem bekannten Muster, das sich als Masken-/Kombinationsangriff ausnutzen lässt. Du brauchst also den Hash, um mit <code>-a3</code>/<code>-a6</code>/<code>-a7</code> gezielt das Muster zu durchsuchen.</p>
       <p><strong>Die Syntax im Detail:</strong></p>
       <ul>
         <li><code>pdf2john.pl Star.pdf</code> — liest die PDF-Datei, extrahiert den Verschlüsselungs-Hash, gibt ihn im John-Format aus.</li>
         <li><code>&gt; star.john</code> — Umleitung in eine Datei. Der Name ist <em>deine</em> Wahl; John will die Original-Datei später anhand des Dateinamens im Hash wiederfinden.</li>
         <li><code>sed -E "s/^[^:]+://"</code> — <code>/^[^:]+:/</code> sucht von Zeilenanfang alles bis zum ersten Doppelpunkt (das ist der Dateiname), <code>/</code> ersetzt es durch nichts (<code>//</code>). Ergebnis: nur noch der Hash-String.</li>
       </ul>
      <div class="codewrap"><pre><code># Schritt 1: John-Extrakt (Original-Hash mit Dateinamen)
pdf2john.pl Star.pdf &gt; star.john
# Schritt 2: sed — Dateinamen-Präfix entfernen, nur Hash übriglassen
sed -E "s/^[^:]+://" star.john &gt; star.hashcat
# Schritt 3: Angriff (später ausführlich unter "Basics → Angriffsmodi")
# hashcat -m 10700 star.hashcat -a7 stadt-kombis.txt "202?d"</code></pre></div>
      <div class="callout tip"><div class="kicker">Warum sed und nicht John direkt?</div>hashcat versteht die John-Ausgabe nicht — er erwartet <em>nur</em> den Hash, nichts anderes pro Zeile. Der Dateiname als Präfix würde den Hash ungültig machen.</div>` },
    { id:"ext-7z", title:"7z2john.pl — Hurdle.jpg.7z", meta:"→ -m 11600", body:
      `<p><strong>Wofür:</strong> 7-Zip-Archive. <code>Hurdle.jpg.7z</code> ist ein Bild-Archiv, das mit einem Passwort geschützt ist.</p>
       <p><strong>Hintergrund:</strong> Für diese Aufgabe gibt es eine kleine, exakte Kandidatenliste (<code>Passworte.txt</code>), die du direkt als Wörterbuch einsetzen kannst — kein Brute-Force nötig.</p>
       <p><strong>Syntax:</strong></p>
       <ul>
         <li><code>7z2john.pl Hurdle.jpg.7z</code> — liest das 7z-Archiv und extrahiert den CRC/Hash der verschlüsselten Header.</li>
         <li><code>&gt; hurdle.john</code> — Ausgabe in Datei; die Präfix-Hash-Syntax wie bei PDF, nur der Modus ändert sich.</li>
       </ul>
      <div class="codewrap"><pre><code>7z2john.pl Hurdle.jpg.7z &gt; hurdle.john
sed -E "s/^[^:]+://" hurdle.john &gt; hurdle.hashcat
# Angriff: hashcat -m 11600 hurdle.hashcat -a0 Passworte.txt</code></pre></div>` },
    { id:"ext-zip", title:"zip2john — Archiv.zip", meta:"→ -m 17200–17230 / 13600", body:
      `<p><strong>Wofür:</strong> ZIP-Archive — nicht Teil der aktuellen Aufgaben, aber Standard-Repertoire.</p>
       <p><strong>Hintergrund:</strong> ZIP-Varianten unterscheiden sich im Hash-Modus: klassisches PKZIP (je nach Kompressionsverfahren <code>-m 17200/17210/17220/17225/17230</code>) vs. WinZip/AES (<code>-m 13600</code>). Der Hash selbst verrät die Variante — gegen <code>hashcat --example-hashes</code> abgleichen.</p>
       <p><strong>Syntax-Hinweis:</strong> <code>zip2john</code> kann mehrere Dateien pro Archiv ausgeben — bei mehreren Treffern braucht hashcat eine Datei pro Zeile.</p>
      <div class="codewrap"><pre><code>zip2john Archiv.zip &gt; archiv.john
sed -E "s/^[^:]+://" archiv.john &gt; archiv.hashcat</code></pre></div>` },
    { id:"ext-keepass", title:"keepass2john — Max Müller.kdbx", meta:"→ -m 13400", body:
      `<p><strong>Wofür:</strong> KeePass-Datenbanken (<code>.kdbx</code>). Hier <code>Max Müller.kdbx</code>.</p>
       <p><strong>Hintergrund:</strong> Die KDBX-Version entscheidet über den KDF (siehe <a href="#" data-goto="sonder">Sonderheiten → KDBX</a>): KDBX3 = AES-KDF, KDBX4 = AES-KDF <em>oder</em> Argon2d/id. Die <code>Max Müller.md</code>-Profilbeschreibung liefert den OSINT-Kontext für die Wortliste.</p>
       <p><strong>Syntax:</strong> Der Hash-Payload liegt — wie bei 7z — <em>nach dem ersten Doppelpunkt</em>. Ein einfaches <code>s/^[^:]+://</code> reicht. <em>Wichtig:</em> Der Dateiname mit Leerzeichen muss in Anführungszeichen — sonst interpretiert die Shell zwei Dateinamen.</p>
      <div class="codewrap"><pre><code>keepass2john "Max Müller.kdbx" &gt; kdbx.john
sed -E "s/^[^:]+://" kdbx.john &gt; kdbx.hashcat
# Angriff: hashcat -m 13400 kdbx.hashcat -a0 osint.txt</code></pre></div>` },
    { id:"ext-libre", title:"libreoffice2john — Numbers1.odt", meta:"→ -m 18400", body:
      `<p><strong>Wofür:</strong> ODF-Dateien (<code>.odt</code>/<code>.ods</code>/<code>.odp</code>).</p>
       <p><strong>Hintergrund der Aufgabe:</strong> Die <code>Numbers&lt;X&gt;</code>-Dateien sind trotz des Namens <em>keine</em> Apple-Numbers-Dateien, sondern echte LibreOffice-Dokumente — ein klassisches Dateityp-Verarsche-Problem, das <code>file</code> aufdeckt. ODF hat einen besonderen Hash: Er enthält einen Hash-Präfix (Dateiname), den eigentlichen Verifikations-Hash (nach dem ersten <code>:</code>) und ein redundantes Suffix am Ende.</p>
       <p><strong>Die sed-Kette im Detail:</strong> <code>sed -E -e 's/[^:]+://' -e 's/:::::[^:]+$//'</code></p>
       <ul>
         <li><code>-e 's/[^:]+://'</code> — entfernt den Dateinamen-Präfix (alles bis zum ersten <code>:</code>).</li>
         <li><code>-e 's/:::::[^:]+$//'</code> — entfernt ein Trenn-Suffix am Zeilenende: Fünf Doppelpunkte gefolgt von beliebigen Nicht-Doppelpunkten bis Zeilenende werden gelöscht. Das ist die von LibreOffice angehängte, für hashcat irrelevante Zusatzinformation.</li>
       </ul>
      <div class="codewrap"><pre><code>libreoffice2john Numbers1.odt | sed -E -e 's/[^:]+://' -e 's/:::::[^:]+$//' &gt; Numbers1.hashcat
# Angriff: hashcat -m 18400 Numbers1.hashcat -a0 rockyou.txt</code></pre></div>` },
    { id:"ext-office", title:"office2john.py — Dokument.docx", meta:"→ -m 9400/9500/9600", body:
      `<p><strong>Wofür:</strong> MS-Office-<code>.docx</code>/<code>.xlsx</code>/<code>.pptx</code>. Nicht Teil der aktuellen Aufgaben, aber Standard-Repertoire.</p>
       <p><strong>Syntax:</strong> Office-Dokumente sind ZIP-Container (<code>PK</code>-Header). In modernen Dateien (Office 2007+) ist der eigentliche Hash im <code>docProps</code>- oder <code>EncryptedPackage</code>-Teil. <code>office2john.py</code> extrahiert und formatiert das korrekt.</p>
      <div class="codewrap"><pre><code>office2john.py Dokument.docx &gt; doc.john
sed -E "s/^[^:]+://" doc.john &gt; doc.hashcat</code></pre></div>` },
    { id:"ext-iwork", title:"iwork2john — Poem.pages / MySheet.numbers / Passwords.pages", meta:"→ -m 23300", body:
      `<p><strong>Wofür:</strong> echte Apple-iWork-Dateien: <code>.pages</code> / <code>.numbers</code> / <code>.key</code>. Im Lab sind das <code>Poem.pages</code>, <code>MySheet.numbers</code> und <code>Passwords.pages</code>.</p>
       <p><strong>Hintergrund:</strong> iWork-Dokumente sind auch ZIP-Container, aber mit einem eigenen Verschlüsselungsformat (ICGCrypt). Der Hash-Modus <code>-m 23300</code> deckt alle iWork-Typen ab.</p>
       <p><strong>Syntax:</strong> Dateiname-Präfix per sed entfernen — <strong>Achtung, das Suffix ist nicht immer gleich</strong>, das reale Output-Format von <code>iwork2john</code> hängt von der Datei ab:</p>
       <ul>
         <li>Poem.pages: kein Suffix, einfacher Cut reicht: <code>s/^[^:]+://</code></li>
         <li>MySheet.numbers: 4-<em>oder-mehr</em>-Doppelpunkt-Suffix: <code>s/:{4,}.*$//</code></li>
         <li>Passwords.pages: <em>genau</em> 4-Doppelpunkt-Suffix: <code>s/:{4}.*$//</code></li>
       </ul>
       <p>Im Zweifel die Hash-Datei einmal ansehen (<code>cat *.john</code>) und das Suffix-Muster passend wählen, bevor blind gecuttet wird.</p>
      <div class="codewrap"><pre><code>iwork2john Poem.pages &gt; poem.john
sed -E "s/^[^:]+://" poem.john &gt; poem.hashcat
# Angriff: hashcat -m 23300 poem.hashcat -a0 rockyou.txt -r rulefile

iwork2john MySheet.numbers &gt; mysheet.hash
sed -E 's/^[^:]+://; s/:{4,}.*$//' mysheet.hash &gt; mysheet.hashcat

iwork2john Passwords.pages &gt; passwords.hash
sed -E 's/^[^:]+://; s/:{4}.*$//' passwords.hash &gt; passwords.hashcat</code></pre></div>` },
    { id:"ext-openssl", title:"openssl2john — personal_information.*.encrypted", meta:"kein hashcat-Modus nötig", body:
      `<p><strong>Wofür:</strong> mit <code>openssl enc</code> verschlüsselte Dateien (hier: <code>personal_information.aes256cbc_sha1.encrypted</code>, AES-256-CBC mit SHA-1-KDF).</p>
       <p><strong>Hintergrund:</strong> <code>openssl2john</code> extrahiert Salt + Ciphertext-Präfix als hashcat-kompatiblen Hash. In der Praxis lieferte der hashcat-Weg hier aber <strong>50 Treffer</strong> gegen die Kandidatenliste — die PKCS#7-Padding-Prüfung, die hashcat als Erfolgskriterium nutzt, hat eine ~1/256-Fehlerquote und bei genug Kandidaten kippt das. Der zuverlässige Weg war ein eigenes Python-Skript, das direkt <code>EVP_BytesToKey</code> (OpenSSL-Standard-KDF) nachbildet und den Klartext inhaltlich prüft (lesbarer Text vs. Datenmüll) statt nur auf Padding zu vertrauen. Siehe <a href="#" data-goto="sonder">Sonderheiten → OpenSSL EVP_BytesToKey</a>.</p>
      <div class="codewrap"><pre><code>openssl2john personal_information.aes256cbc_sha1.encrypted &gt; personal.hash
sed -E 's/^[^:]+://; s/:::::[^:]+$//' personal.hash &gt; personal.hashcat
# Testweise (unzuverlässig, False Positives moeglich):
hashcat -a0 personal.hashcat personal_information.aes256cbc_sha1.password_candidates.txt
# Zuverlaessig: eigenes Skript mit EVP_BytesToKey/SHA-1 + Klartext-Check
python3 openssl_crack.py personal_information.aes256cbc_sha1.encrypted personal_information.aes256cbc_sha1.password_candidates.txt</code></pre></div>` },
  ];

  var JOHN_ATTACK = [
    { id:"ja-wordlist", title:"john &lt;hash&gt; --wordlist=…", meta:"Wörterbuchangriff", body:
      `<div class="codewrap"><pre><code>john hurdle.john --wordlist=Passworte.txt</code></pre></div>
      <p>Sinnvoll direkt mit John, wenn hashcat den Hashtyp (noch) nicht unterstützt, oder für kleine, exakte Kandidatenlisten wie bei <code>Hurdle.jpg.7z</code>. John liest den Dateinamen aus dem Hash und sucht sich die Ziel-Datei selbst.</p>` },
    { id:"ja-rules", title:"john --rules=…", meta:"Regeln anwenden", body:
      `<div class="codewrap"><pre><code>john hurdle.john --wordlist=Passworte.txt --rules=best64</code></pre></div>
      <p>John hat eigene Regel-Sets (<code>--rules=best64</code>, <code>--rules=Single</code> etc.), die unter <code>/etc/john/john.conf</code> definiert sind. Bei hashcat heißen dieselben Regeln <code>-r</code> — siehe <a href="#" data-goto="basics">Basics → Regeln</a>.</p>` },
    { id:"ja-show", title:"john --show", meta:"Ergebnisse anzeigen", body:
      `<div class="codewrap"><pre><code>john --show hurdle.john</code></pre></div>
      <p>Zeigt bereits geknackte Passwörter aus dem Potfile. Wenn John ständig „Keine Hashes geladen" sagt, meist ein Format-Problem — <code>--format=</code> hilft.</p>` },
    { id:"ja-format", title:"john --format=…", meta:"Auto-Detect überstimmen", body:
      `<p>Falls John den Hashtyp falsch errät (z. B. bei generischen Hash-Strings ohne <code>*2john</code>-Kontext).</p>
      <div class="codewrap"><pre><code>john --format=Raw-SHA256 hash.txt --wordlist=/usr/share/wordlists/rockyou.txt</code></pre></div>
      <p>Mit <code>--show --format=…</code> kann man auch gespeicherte Ergebnisse nach Format filtern.</p>` },
  ];

  var HC_MODES = [
    { id:"hm-a0", title:"-a0 — Wörterbuch", meta:"Standardfall", body:
      `<p><strong>Was es tut:</strong> Testet jeden Kandidaten aus der Wortliste (und optional: gegen jede Regel) gegen den Hash. Der schnellste Angriff — nutze ihn, wenn du denkst, das Passwort ist ein „echtes" Wort oder in einer Liste.</p>
      <p><strong>Hintergrund:</strong> Bei <code>Hurdle.jpg.7z</code> gibt eine exakte <code>Passworte.txt</code> die Kandidaten vor — der ideale Fall für einen reinen Wörterbuchangriff.</p>
      <div class="codewrap"><pre><code>hashcat -m 11600 hurdle.hashcat -a0 Passworte.txt -r /usr/share/hashcat/rules/best64.rule</code></pre></div>
      <p><code>-r best64.rule</code> wendet zusätzlich 64 vortrainierte Transformationen (z.B. <code>Passwort1</code>, <code>passwort!</code>) auf jedes Wörterbuch-Wort an — erweitert den Suchraum erheblich.</p>` },
    { id:"hm-a1", title:"-a1 — Kombinationsangriff", meta:"Kreuzprodukt zweier Listen", body:
      `<p><strong>Was es tut:</strong> Bildet jedes Element aus Liste 1 × jedes Element aus Liste 2 und testet die Verkettung — sehr effizient für zusammengesetzte Passwörter.</p>
      <p><strong>Hintergrund:</strong> Bei <code>MySheet.numbers</code> sind Passwörter aus zwei Wörtern zusammengezogen (<code>HausMaus</code>, <code>AffeAffe</code>, <code>alleLieben</code>) — genau das Kreuzprodukt, das <code>-a1</code> abdeckt.</p>
      <div class="codewrap"><pre><code>hashcat -m 23300 mysheet.hashcat -a1 woerter.txt woerter.txt</code></pre></div>
      <p>Ein Aufruf von <code>-a1 listeA listeB</code> erzeugt <code>listeA[i] + listeB[j]</code> für alle Paare. Gleiche Liste zweimal = alle Kombinationen aus zwei Wörtern.</p>` },
    { id:"hm-a3", title:"-a3 — Brute-Force / Maske", meta:"alle Kandidaten gemäß Maske", body:
      `<p><strong>Was es tut:</strong> Probiert systematisch alle Kombinationen, die zur Maske passen. Drei interpretierbare Zeichensatz-Specials: eingebaute Klassen (<code>?l ?u ?d ?s ?a</code>), eigene Klassen (<code>-1</code> bis <code>-4</code>), und Längensteuerung (<code>--increment</code>).</p>
      <p><strong>Einfaches Beispiel:</strong> 5-stellige PIN als SHA-256 — <code>hash.sha256</code> ist hier einfach die Datei, die einen rohen SHA-256-Hashstring enthält (der zu knackende Hash in hex).</p>
      <div class="codewrap"><pre><code>hashcat -m 1400 hash.sha256 -a3 "?d?d?d?d?d"</code></pre></div>
      <p><code>--increment</code> startet mit der kürzesten Länge (<code>--increment-min</code>) und erhöht bis zur Vollmaske (<code>--increment-max</code>):</p>
      <div class="codewrap"><pre><code>hashcat -m 1400 hash.sha256 -a3 "?u?l?d?d?d?d?d?d" --increment --increment-min 1 --increment-max 6
# testet zuerst 1 Zeichen, dann 2, …, bis 6 — statt immer 6 zu erwarten
# perfekt wenn die Länge unbekannt ist, aber die Zeichenklassen klar sind</code></pre></div>
      <p class="hint">Für komplexere Policy-Masken siehe <a href="#" data-goto="rest">Der Rest → Star.pdf</a>.</p>` },
    { id:"hm-a5", title:"-a5 — Galerie (Hashattacks)", meta:"GPG-Wortliste als Maske", body:
      `<p><strong>Was es tut:</strong> Nimmt die vordefinierten „Galerie"-Masken von Hashattacks (über <code>--gpu-accel</code>) — selten gebraucht, aber es gibt sie.</p>` },
    { id:"hm-a6", title:"-a6 — Hybrid (Wort + Maske)", meta:"Wort zuerst", body:
      `<p><strong>Was es tut:</strong> Hängt an jedes Wort eine Maske an: <code>Wort + Maskenteil</code>. Bei <code>-a6</code> kommt die Wortliste <em>vor</em> die Maske.</p>
      <div class="codewrap"><pre><code># Wort + 4 Ziffern: p@ssW0rd + 1234
hashcat -m 1400 hash.sha256 candidates.txt -a6 "?d?d?d?d"
# Wort + Sonderzeichen-Suffix: p@ssW0rd + !!!!
hashcat -m 1400 hash.sha256 candidates.txt -a6 "?s?s?s?s"</code></pre></div>
      <p>Deckelt den Fall ab, dass ein Basiswort plus ein policy-getriebener Anhang existiert.</p>` },
    { id:"hm-a7", title:"-a7 — Hybrid (Maske + Wort)", meta:"Maske zuerst", body:
      `<p><strong>Was es tut:</strong> Setzt die Maske <em>vor</em> das Wort: <code>Maskenteil + Wort</code>.</p>
      <p><strong>Hintergrund:</strong> Die <code>Star.pdf</code>-Policy beginnt mit <code>&lt;Jahr&gt;</code> (z.B. <code>202?</code>), danach kommen die Städte — für diese Reihenfolge braucht es <code>-a7</code>, nicht <code>-a6</code>.</p>
      <div class="codewrap"><pre><code>hashcat -m 10700 star.hashcat -a7 staedte.txt "202?d" -1 "0123456789"
# Jahr als erste Maske "202?d" = 2020–2029, dann kommt ein Städtewort aus der Liste</code></pre></div>` },
  ];

  var HC_MASKS = [
    { id:"mk-builtin", title:"Eingebaute Zeichensätze", meta:"?l ?u ?d ?s ?a", body:
      `<p><strong>Was sie bedeuten:</strong> Die eingebauten Masken-Platzhalter decken die vier Grundklassen ab — jeder wird beim Angriff durch ein Zeichen aus der Klasse ersetzt. Beispiel: 4-stellige PIN = nur Ziffern.</p>
      <div class="codewrap"><pre><code>hashcat -m 1400 pin.sha256 -a3 "?d?d?d?d"</code></pre></div>
      <p>Sonderkombination <code>?a</code> = <code>?l?u?d?s</code> — alle Zeichen, die auf einer US-Tastatur liegen (95 Zeichen). 8 Zeichen mit <code>?a</code> = 95⁸ Möglichkeiten — nicht trivial.</p>` },
    { id:"mk-custom", title:"Eigene Zeichensätze (-1…-4)", meta:"bis zu 4 eigene Klassen", body:
      `<p><strong>Was es tut:</strong> Definiert eigene Klassen, die in der Maske als <code>?1</code>/<code>?2</code>/… referenziert werden. Nützlich, wenn nur bestimmte Sonderzeichen erlaubt sind (Policy!) oder eine unübliche Klasse exakt bekannt ist.</p>
      <p><strong>Beispiel Star.pdf:</strong> Die Policy erlaubt im Sonderzeichen-Feld nur <code>$</code>, <code>€</code>, <code>!</code> — das sind die Sonderzeichen, die in den Übungen verwendet wurden. Statt alle ~32 Sonderzeichen zu testen, grenzt man in einer eigenen Klasse exakt auf diese drei ein. Rechenzeitersparnis: 3⁴ statt 32⁴ ≈ 2 Mio. weniger Kandidaten.</p>
      <div class="codewrap"><pre><code>hashcat -m 10700 star.hashcat -a3 -1 '$€!' "?u?l?u?l?d?d?d?d?1?1?1?1"
# ?1 referenziert auf die mit -1 '$€!' definierte Klasse
# Maske: GroßBuchstabe-KleinBuchstabe-GroßBuchstabe-KleinBuchstabe-4 Ziffern-4 Sonderzeichen($€!)</code></pre></div>
      <p><code>--increment</code> nutzt dieselben Masken-Slots und erlaubt Längensteuerung (siehe <a href="#" data-goto="basics">-a3</a>).</p>` },
  ];

  var HC_RULES = [
    { id:"rl-inline", title:"-j — Inline-Regel auf Kommandozeile", meta:"ohne extra .rule-Datei", body:
      `<p><strong>Warum -j statt -r?</strong> Manchmal braucht man nur <em>eine</em> schnelle Transformation pro Wort, ohne eine eigene <code>.rule</code>-Datei anzulegen. Die <code>-j</code>-Regel wird auf jedes Kandidatenwort angewendet, <em>bevor</em> es mit dem zweiten Wort kombiniert wird (bei <code>-a1</code>) oder direkt (bei <code>-a0</code>).</p>
      <p><strong>Hurdle.jpg.7z — echtes Beispiel aus dem Lab:</strong></p>
      <div class="codewrap"><pre><code># Lösungsweg: Custom-Wortliste (Lauf, Flug, Gesang, Fund, Stand, ...)
# + Regel die Buchstaben-Ersetzungen macht:
hashcat -m 11600 hurdle.hashcat wortliste.txt -j '^ ^r^e^D' --show</code></pre></div>
      <ul>
        <li><code>^</code> = Präfix-Befehl (folgendes Zeichen wird voranestellt)</li>
        <li><code> </code> (Leerzeichen) = Leerzeichen voranstellen</li>
        <li><code>r</code> = Toggle Case des letzten Zeichens (r → R oder umgekehrt)</li>
        <li><code>e</code> = Toggle Case (e → E)</li>
        <li><code>D</code> = Toggle Case (D → d)</li>
        <li>Ergebnis: <code>Lauf</code> → <code> LaRueD</code> (mit führendem Leerzeichen)</li>
      </ul>
      <p><strong>Passwords.pages — echtes Beispiel aus dem Lab:</strong> Zwei <code>-j</code>-Regeln <em>kombiniert</em> — das geht, hashcat erlaubt mehrere <code>-j</code>-Flags!</p>
      <div class="codewrap"><pre><code># Hint: "#j *** j *** 1" — Passwort beginnt mit #, enthält j, endet mit 1
# Custom-Wortliste: 4-buchstabige Woerter die mit j anfangen
hashcat -m 23300 passwords.hashcat jwords.txt -j '$1' -j '^#'</code></pre></div>
      <ul>
        <li><code>-j '$1'</code> — <code>$</code> = Suffix-Befehl → haengt <code>1</code> an jedes Wort an</li>
        <li><code>-j '^#'</code> — <code>^</code> = Praefix-Befehl → haengt <code>#</code> vor jedes Wort</li>
        <li>Reihenfolge: Erst <code>$1</code> (Suffix), dann <code>^#</code> (Praefix) — Ergebnis: <code>jane</code> → <code>#jane1</code></li>
      </ul>` },
    { id:"rl-basics", title:"Regel-Datei selbst anlegen", meta:"eigenes .rule-File", body:
      `<p><strong>Warum eine eigene Datei?</strong> Statt für jede Transformation eine eigene Wörterbuch-Datei zu erzeugen, legt man Regeln in einer Textdatei ab und lässt hashcat sie pro Wort anwenden — der Angriff wird dadurch massiv schneller, weil die Kandidaten im Speicher erzeugt werden statt auf Platte.</p>
      <p><strong>Workflow:</strong> Datei <code>meine.rule</code> mit einer Regel pro Zeile — dann mit <code>-r</code> referenzieren.</p>
      <div class="codewrap"><pre><code>cat &gt; prefix-suffix.rule &lt;&lt;'EOF'
c                          # 1. Großbuchstabe (Capitalize)
$1 $2 $3                   # Ziffern 1–3 anhängen (Suffix)
^S                         # Groß-S voranstellen (Präfix)
^S $1 $2 $3                # Kombination: Präfix S + Ziffern
EOF
hashcat -m 1400 hash.sha256 candidates.txt -r prefix-suffix.rule</code></pre></div>
      <p><strong>Fokus Prefix/Suffix/Kapitalisierung:</strong></p>
      <div class="codewrap"><pre><code>cat &gt; kapital.rule &lt;&lt;'EOF'
c          # Passwort → Passwort (Erster Buchstabe groß)
l          # Passwort → passwort
u          # Passwort → PASSWORT
t          # Passwort → pASSWORT (Toggle Case)
^S         # Passwort → SPasswort  (S voranstellen — z.B. S als Firmen-Initiale)
$!         # Passwort → Passwort!  (! anhängen)
EOF</code></pre></div>` },
    { id:"rl-cross", title:"zwei -r kombinieren", meta:"Kreuzprodukt der Regelsätze", body:
      `<div class="codewrap"><pre><code>hashcat -m 1400 hash.sha256 candidates.txt -r number_prepend.rule -r sc_append.rule</code></pre></div>
      <div class="callout warn"><div class="kicker">Duplikate vermeiden</div><code>$1:</code> und <code>:$1</code> liefern dasselbe Ergebnis — kostet nur doppelt Rechenzeit.</div>` },
    { id:"rl-combinator", title:"-j / -k — Kombinator-Regeln", meta:"vor dem/ - nach Verbinden", body:
      `<p><strong>Warum?</strong> Bei <code>-a1</code> (Kombination) kann man mit <code>-j</code> und <code>-k</code> Bearbeitungen direkt im Kombinationsschritt anwenden — statt ein Zwischenwörterbuch auszugeben und zu bereinigen.</p>
      <p><strong>Was ist was:</strong></p>
      <ul>
        <li><code>-j &lt;regel&gt;</code> — wendet die Regel auf das <em>erste</em> Wort an (aus Liste A).</li>
        <li><code>-k &lt;regel&gt;</code> — wendet die Regel auf das <em>zweite</em> Wort an (aus Liste B).</li>
      </ul>
      <p><strong>Beispiel — MySheet.numbers:</strong> Wörter sind kleingeschrieben in der Liste, aber korrekt großgeschrieben im Passwort. <code>-j c</code> kapitalisiert das zweite Wort der Kombination.</p>
      <div class="codewrap"><pre><code># ohne Regel:  hausmaus  →  falsch
# mit -j c:    hausMaus   →  richtig
hashcat -m 23300 mysheet.hashcat lowercase.txt lowercase.txt -j c

# Beispiel Star.pdf-Strategie: Bindestrich statt Leerzeichen verbinden
hashcat --stdout staedte.txt staedte.txt -j '$x'  # x als Trennzeichen (aber: x != "-", siehe unten)

# Präfix S an das ERSTE Wort (Liste A anfassen):
hashcat -m 1400 hash.sha256 listeA.txt listeB.txt -j '^S'</code></pre></div>
      <div class="callout tip"><div class="kicker">Klassiker-Falle: Bindestrich</div>Ein Literal-Bindestrich in einer Regel ist schwierig — besser das Trennzeichen per <code>tr -d</code> entfernen oder ein anderes Zeichen wählen bei <code>--stdout</code>. Du musst das Trennzeichen am Ende entfernen, weil es nicht zum Passwort gehört.</div>` },
  ];

  var HC_BUILD = [
    { id:"bd-stdout", title:"--stdout — Kandidaten nur ausgeben", meta:"Zwischenwörterbuch bauen", body:
      `<p><strong>Was es tut:</strong> Ohne Hash-Datei erzeugt hashcat nur die Kandidaten (Wörterbuch + Regeln + Kombination) und schreibt sie auf <code>stdout</code> — perfekt, um ein Zwischenwörterbuch zu bauen oder die Kandidatenliste zu prüfen, BEVOR man rechnen lässt.</p>
      <p><strong>Beispiel — Star.pdf:</strong> Städteliste mit sich selbst kombinieren, Trennzeichen direkt in der Regeln und danach entfernen:</p>
      <div class="codewrap"><pre><code># ohne Regeln: staedte×staedte als reines Kreuzprodukt, Trennzeichen erst in der Pipe:
hashcat --stdout staedte.txt staedte.txt | tr -d '-' &gt; staedte-kombis.txt
# oder kompakter in einem Rutsch MIT Regel (Präfix-/Suffix-Behandlung inline):
hashcat --stdout staedte.txt staedte.txt -j '$-' | tr -d '-' &gt; staedte-kombis.txt</code></pre></div>
      <p><strong>Warum <code>-j '$-'</code> + <code>tr -d</code>?</strong> <code>-j</code> regelt die PAAR-Verbindung: <code>$-</code> heißt „ans Ende des ersten Worts das Zeichen &lt;-&gt; hängen". Damit bekommst du <code>Stadt-Stadt</code> als Zwischenkandidation; <code>tr -d '-'</code> entfernt den Bindestrich wieder, weil er nur als Trenner diente. Ohne die Regel-Verarbeitung bleibt es ein echtes reines Kreuzprodukt — je nachdem, was du brauchst.</p>` },
    { id:"bd-increment-mask", title:"--increment + --increment-min/max", meta:"Länge unbekannt? gestaffelt suchen", body:
      `<p><strong>Warum?</strong> Wenn du die Länge des Passworts nicht kennst, aber die Zeichenklassen (z.B. „nur Ziffern"), ist eine Vollmaske zu lang, eine kurze zu kurz. <code>--increment</code> durchläuft alle Längen systematisch — von der kürzesten bis zur vollen Maske.</p>
      <div class="codewrap"><pre><code># Testet ALLE PIN-Längen 1–6, nur Ziffern:
hashcat -m 1400 hash.sha256 -a3 "?d?d?d?d?d?d" --increment --increment-min 1 --increment-max 6
# 1 Stelle (10), 2 Stellen (100), ... 6 Stellen (1.000.000) — sucht vorher kürzer

# Kombiniert mit eigener Klasse und Masken-Verkürzung:
hashcat -m 10700 star.hashcat -a3 -1 '$€!' "?1?1?1?1" --increment --increment-min 1 --increment-max 4</code></pre></div>
      <p><strong>Tipp:</strong> <code>--increment</code> testet in beide Richtungen — sucht zuerst kürzer. Bei unbekannter Länge IMMER verwenden statt raten.</p>` },
    { id:"bd-prince", title:"princeprocessor", meta:"Fragment-Kombinatorik, pipebar", body:
      `<p><strong>Was es tut:</strong> Zerlegt eine Wortliste in Fragmente und kombiniert sie zu plausiblen neuen Passwörtern („Gordon's Ansatz"). Sehr effektiv bei Passwörtern, die aus mehreren Wörtern/Bausteinen zusammengesetzt sind.</p>
      <p><strong>Beispiel — Max Müller.kdbx:</strong> OSINT-Fragmente aus der Profildatei (<code>Max</code>, <code>Müller</code>, <code>Mannheim</code>, Geburtsjahr, Haustiername) kombiniert Prince in allen sinnvollen Längen und verkettet sie.</p>
      <div class="codewrap"><pre><code>princeprocessor --pw-min=6 --pw-max=20 osint.txt \
  | hashcat -m 13400 kdbx.hashcat -r /usr/share/hashcat/rules/best64.rule</code></pre></div>
      <p><code>--pw-min/--pw-max</code> begrenzen die Gesamtlänge der kombinierten Fragmente; <code>-r</code> ergänzt die Basic-Transformationen.</p>` },
  ];

  var HC_BENCHMARK = [
    { id:"bm-single", title:"Einen Modus benchmarken", meta:"z.B. -m 1400 (SHA-256)", body:
      `<p><strong>Warum?</strong> Die Zahl „X Millionen Hashes/Sekunde" bestimmt, wie realistisch ein Angriff ist — und sie variiert massiv je nach Hash-Typ, Hardware und Treiber. Vor einer schwierigen Aufgabe misst man kurz die eigene Leistung, um die Zeiten im Lösungsweg angeben zu können.</p>
      <div class="codewrap"><pre><code># Schnelltest für einen bestimmten Hash-Modus, mit nativer Beschleunigung:
hashcat -b -m 1400 --backend-ignore-opencl
# Ausgabe (Beispiel):  SHA256 ... H/s:  1.2 Gh/s

# Genauer: klassischer Benchmark für Garnichts (alle Modi) — oder gezielt:
hashcat -b -m 11600 --backend-ignore-opencl   # 7-Zip
hashcat -b -m 13400 --backend-ignore-opencl   # KeePass (KDBX3/KDBX4)
hashcat -b -m 23300 --backend-ignore-opencl   # iWork</code></pre></div>
      <p><strong>Was die Ausgabe sagt:</strong> <code>-b</code> / <code>--benchmark</code> mixt eine synthetische Wörterbuch-Wortliste durch einen bestimmten Modus und misst die Geschwindigkeit in Hashes pro Sekunde (H/s), Kilo-, Mega- oder Giga-H/s. Das ist die Zahl, die du für die „Angriffsdauer"-Berechnung brauchst.</p>
      <div class="callout tip"><div class="kicker">Angriffsdauer abschätzen</div>Wenn du den Kandidaten-Suchraum kennst (<code>Zeichensatz^Länge</code> oder Wortlistenlänge + Regeln), teilst du ihn durch die H/s-Zahl:</div>
      <div class="codewrap"><pre><code># Kandidaten / Hashes pro Sekunde = Sekunden
#   z.B. 1 Mio Kandidaten bei 500.000 H/s → 2 Sekunden
#   z.B. 95^8 Kandidaten bei 1.2 Gh/s  → ~1 Woche</code></pre></div>` },
  ];

  var SONDER = [
    { id:"so-java", title:"Java String.hashCode() — kein Krypto-Hash", meta:"JavaHashcodes.txt", body:
      `<p><strong>Warum kein hashcat-Modus?</strong> <code>String.hashCode()</code> ist eine 32-Bit-Zahl mit einer besonderen (linearen) Konstruktion — <em>keine</em> kryptografische Hashfunktion. hashcat kennt keinen Modus dafür, weil der Algorithmus zu trivial und zu schnell nachbaubar ist, um GPU-Beschleunigung zu rechtfertigen.</p>
      <p><strong>Richtiger Weg:</strong> Formel selbst nachbauen und Kandidaten durchtesten. Die Formel ist die Definition von <code>Java.lang.String.hashCode()</code> aus der Java-Doku:</p>
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
      <div class="callout warn"><div class="kicker">Kollisionen einplanen</div>32 Bit ⇒ ab ca. <code>2^16</code> Kandidaten wird ein Kollisionstreffer wahrscheinlich (Geburtstagsparadoxon, vgl. <a href="#" data-goto="theorie">Theorie → Hashfunktionen</a>). Jeden Treffer gegen den echten Kontext verifizieren. Reines Python ist für Millionen Kandidaten langsam — mit <code>multiprocessing</code> parallelisieren oder in C/Java nachbauen.</div>
      <p><strong>Meet-in-the-middle (Fortgeschritten):</strong> Für sehr lange Kandidaten kann man den Suchraum halbieren: Berechne für alle Präfixe und alle Suffixe die (linearen) Beiträge getrennt, speichere sie in einer Hash-Tabelle und suche, wo sie zusammen den Zielwert ergeben. Da <code>hashCode</code> linear ist (<code>h(ab) = h(a)*31^len(b) + h(b)</code>), kann man <code>h(a)*31^len(b)</code> gegen <code>target - h(b)</code> mappen. Voraussetzung: die Wortliste ist klein genug, dass beide Seiten passen. Das ist die klassische Angriffsform bei 32-Bit-Hashes mit bekannter Struktur.</p>` },

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
      <p><strong>Alternative: reines Python.</strong> Wenn hashcat den Argon2-Typ weiter streikt, kannst du KeePass-Hashes direkt in Python angreifen. Der kritische Teil ist das KDF — für AES-KDF reicht ein dünner PMC-Implementierung, für Argon2 nutzt du das <code>argon2-cffi</code>-Paket und baust die <code>-m 13400</code>-Payload-Manipulation selbst. Struktur:</p>
      <div class="codewrap"><pre><code># 1) keepass2john "Max Müller.kdbx" — selbst wenn hashcat scheitert, bekommst du den Hash
# 2) Baue die Übersetzung selbst (Skript-Logik):
#      - parse $keepass$... : KDF-Marker, Runden, Salt
#      - KDF anwenden (AES-KDF: HMAC/Key-Derivation oder Argon2)
#      - Prüf hash des Zielwerts
# 3) Für jeden Kandidaten: KDF + Compare — in einer Schleife</code></pre></div>
      <p>Das eigene Python-Vorgehen lohnt sich vor allem, wenn man den Debug-Zwang hat — sonst ist das aktuellste binary hashcat der schnellere Weg. <strong>Unabhängig davon:</strong> prüfe zuerst, ob <code>keepass2john</code> selbst schon den neueren KDBX-Typ hat. Neuere John-Versionen (jumbo ≥ 1.9) erkennen und extrahieren KDBX4 automatisch.</p>
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

    { id:"so-benchmark", title:"--benchmark / -b — Eigene Hardware messen", meta:"H/s für einen Modus", body:
      `<p><strong>Warum?</strong> Die Rechenleistung deines Geräts für einen bestimmten Hash-Typ bestimmt, ob ein Angriff in Stunden, Tagen oder Jahrzehnten endet. hashcat hat dafür den eingebauten Benchmark.</p>
      <div class="codewrap"><pre><code>hashcat -b --backend-ignore-opencl   # benchmarkt ALLE Modi
hashcat -b -m 1400 --backend-ignore-opencl   # nur SHA-256
hashcat -b -m 11600 --backend-ignore-opencl  # 7-Zip
hashcat -b -m 13400 --backend-ignore-opencl  # KeePass (AES-KDF)
hashcat --benchmark -m 23300 --backend-ignore-opencl  # iWork</code></pre></div>
      <p><strong>Was die Ausgabe zeigt:</strong> H/s (Hashes pro Sekunde) in H/s, kH/s, MH/s oder GH/s. Damit kannst du die Angriffsdauer überschlagen: <code>Sekunden = Kandidaten / H/s</code>.</p>
      <p><strong>Wichtig:</strong> <code>--backend-ignore-opencl</code> erzwingt die CUDA/HIP-Variante, falls OpenCL-Treiber fehlen (häufig in Docker/Headless-Setups). Ohne GPU läuft hashcat auf der CPU — deutlich langsamer.</p>` },
  ];

  var TASKS = [
    { id:"tk-numbers", title:"Numbers&lt;X&gt; (.odt/.ods) &amp; Poem.pages", meta:"Dateiendung lügt", body:
      `<p>Keine Kontextinfos vorhanden → allgemeine Best Practices. <strong>Wichtigster Schritt zuerst:</strong> <code>file</code> statt der Endung glauben — die <code>Numbers&lt;X&gt;</code>-Dateien sind trotz Namens echte <strong>LibreOffice/ODF</strong>-Dateien (siehe Basics → <code>libreoffice2john</code>), <code>Poem.pages</code> ist eine echte <strong>Apple-Pages</strong>-Datei (→ <code>iwork2john</code>). Danach: rockyou + <code>best64</code>, bei Erfolglosigkeit Hybrid/Maske.</p>` },
    { id:"tk-star", title:"Star.pdf — vollständige Masken-/Kombinationsstrategie", meta:"Policy bekannt", body:
      `<p>Policy: ≥2 Großbuchst., ≥2 Kleinbuchst., ≥4 Ziffern, ≥4 Sonderzeichen (<code>$ € !</code>, oft wiederholt), Mindestlänge 16, Muster <code>&lt;Jahr&gt;&lt;Stadt1&gt;&lt;Stadt2&gt;&lt;Sonderzeichen&gt;</code>.</p>
      <div class="codewrap"><pre><code># 1) Städteliste (10 größte dt. Städte) mit sich selbst kombinieren (2-Step --stdout)
hashcat --stdout -a1 staedte.txt staedte.txt &gt; staedte_combined.txt

# 2) Jahreszahlen (1900–2026) mit Städte-Kombis kreuzprodukt
hashcat --stdout -a1 jahre.txt staedte_combined.txt &gt; jahre_staedte.txt

# 3) Everything in einem -a6 Lauf mit eigener Klasse und increment
hashcat -m 10700 star.hashcat -a6 -1 '$€!' jahre_staedte.txt '?1?1?1?1?1?1' \
  --increment --increment-min 4 --increment-max 6 --show</code></pre></div>
      <p><strong>Der Trick:</strong> Das 2-Step <code>--stdout</code> baut schrittweise Kombinationen auf — erst Städte×Städte, dann Jahre×Städte. Der finale <code>-a6</code>-Lauf hängt dann die Sonderzeichen an. <code>--increment</code> durchsucht Längen 4–6 systematisch. Ergebnis: <code>2025HamburgBerlin!!!!</code></p>` },
    { id:"tk-mysheet", title:"MySheet.numbers — echtes Beispiel: Hint „Wir testen uns zu Tode“", meta:"nur Buchstaben, &gt;8 Zeichen", body:
      `<p>Hint der Aufgabe: <em>„Wir testen uns zu Tode“</em> + Passwort ist länger als 8 Zeichen. Der Lösungsraum aus dem ganzen Satz kombiniert wäre riesig — also erst die Kernwörter (<code>Test</code>, <code>Tod</code>, <code>wir</code>, …) mit sich selbst kreuzprodukten, bis Kombinationen &gt;8 Zeichen entstehen.</p>
      <div class="codewrap"><pre><code>iwork2john MySheet.numbers &gt; mysheet.hash
sed -E 's/^[^:]+://; s/:{4,}.*$//' mysheet.hash &gt; mysheet.hashcat
# Custom-Wortliste: alle Kombinationen aus dem Hint-Satz + größere Wortlisten
# (KI-generiert, siehe Ressourcen → Prompts), Ergebnis: mysheet_candidates.txt
hashcat -a0 mysheet.hashcat mysheet_candidates.txt</code></pre></div>
      <p><strong>Ergebnis:</strong> <code>TestTest</code> — die naheliegendste Kombination aus dem Hint war die richtige. Lehre: bei einem wörtlichen Hint zuerst die simpelsten Wortkombinationen testen, bevor man auf große generische Listen ausweicht.</p>` },
    { id:"tk-passwords", title:"Passwords.pages — echtes Beispiel: Hint „#j *** j *** 1“", meta:"Hint gibt Struktur vor", body:
      `<p>Der Dateiname ist ein Köder — aber hier gab die Aufgabe zusätzlich einen echten Hint: <code>#j *** j *** 1</code>. Das legt die Struktur fest: beginnt mit <code>#</code>, ein 4-Buchstaben-Wort das mit <code>j</code> anfängt, endet mit <code>1</code>.</p>
      <div class="codewrap"><pre><code>iwork2john Passwords.pages &gt; passwords.hash
sed -E 's/^[^:]+://; s/:{4}.*$//' passwords.hash &gt; passwords.hashcat
# Custom-Wortliste: alle 4-Buchstaben-Vornamen die mit j anfangen -> jwords.txt
hashcat -m 23300 passwords.hashcat -a0 jwords.txt -j '$1' -j '^#'</code></pre></div>
      <p>Siehe <a href="#" data-goto="basics">Basics → <code>-j</code> Inline-Regeln</a> für die Erklärung der beiden Regeln. <strong>Ergebnis:</strong> <code>#janejudy1</code>.</p>` },
    { id:"tk-kdbx-osint", title:"Max Müller.kdbx — echtes Beispiel: KDBX4 zu neu für Standard-Tools", meta:"eigenes Python-Skript nötig", body:
      `<p>Profilbeschreibung (Max Müller.md) auswerten: Vornamen im Umfeld (hier <code>Emma</code>, <code>Jonas</code>, <code>Laura</code>) als Basis einer Kombinations-Wortliste — alle Reihenfolgen, groß/klein, mit/ohne Leerzeichen.</p>
      <div class="callout tip"><div class="kicker">Warum kein Standardtool?</div>KDBX Version 4 (Argon2-KDF) war zum Zeitpunkt des Labs zu neu für die verfügbare hashcat/john-Version im Setup — kein <code>keepass2john</code>-Support für dieses Format. Lösung: eigenes Python-Skript, das die Wortliste durchprobiert und das KDBX4-Hashing (Argon2) selbst nachbildet.</p></div>
      <div class="codewrap"><pre><code># Wortliste: alle Kombinationen aus Emma/Jonas/Laura (Groß/Klein, mit/ohne Leerzeichen)
python3 kdbx4crack.py</code></pre></div>
      <p><strong>Ergebnis:</strong> <code>LauraEmmaJonas</code>. <strong>Verifikation:</strong> Nach dem Crack immer prüfen, ob die KDBX sich mit dem gefundenen Passwort tatsächlich öffnet — Argon2-Kollisionen sind zwar extrem unwahrscheinlich, aber ein echter Öffnungstest ist der einzige sichere Beweis.</p>` },
    { id:"tk-java", title:"JavaHashcodes.txt — echtes Beispiel: eigenes Crack-Skript", meta:"kein hashcat-Modus, siehe Sonderheiten", body:
      `<p>Kein hashcat-Modus für <code>String.hashCode()</code> (siehe <a href="#" data-goto="sonder">Sonderheiten → Java String.hashCode()</a> für die Formel). Lösungsweg: pro Zeichenlänge brute-forcen (a-z/A-Z) und die Meet-in-the-Middle-Eigenschaft nutzen, um den Suchraum zu halbieren.</p>
      <div class="codewrap"><pre><code>python3 java_crack.py   # input: JavaHashcodes.txt, Ergebnis-Mapping Hashcode -&gt; Klartext</code></pre></div>
      <p>Beispiel-Treffer aus dem Lab: <code>2147483647 → aAgaAXp</code>, <code>999999999 → rbgbafo</code>, <code>-2147483648 → aAgaAXq</code> — jede Zeile im Output ist ein eigener Hashcode/Klartext-Fund, mehrere davon einreichen.</p>` },
    { id:"tk-openssl", title:"personal_information.*.encrypted — echtes Beispiel: KDF-Skript statt hashcat", meta:"50 False Positives mit hashcat", body:
      `<p>hashcat-Weg über <code>openssl2john</code> lieferte <strong>50 Treffer</strong> gegen die Kandidatenliste — nicht verwertbar (siehe <a href="#" data-goto="sonder">Sonderheiten → OpenSSL Padding-False-Positives</a>). Lösung: eigenes Python-Skript mit <code>EVP_BytesToKey</code>/SHA-1 (OpenSSL-Standard-KDF), das das Ergebnis inhaltlich prüft statt nur aufs Padding zu vertrauen.</p>
      <div class="codewrap"><pre><code>python3 openssl_crack.py personal_information.aes256cbc_sha1.encrypted personal_information.aes256cbc_sha1.password_candidates.txt</code></pre></div>
      <p><strong>Ergebnis:</strong> Kandidat 12243, Passwort <code>sainsburys</code> → entschlüsselter Klartext: <code>Geboren 1976.</code></p>` },
  ];

  var HASH_VS_KDF = [
    { id:"hk-unterschied", title:"Hash-Funktion vs. KDF — der Unterschied", meta:"was du wissen musst", body:
      `<p>Zwei Begriffe, die im Kontext Passwort-Cracking ständig vermischt werden — der Unterschied ist <strong>der</strong> zentrale Punkt fürs Verständnis:</p>
      <ul>
        <li><strong>Hash-Funktion (<code>H(M)=h</code>):</strong> Eine Funktion, die beliebig lange Eingaben auf eine feste Ausgabelänge abbildet. Schnell, deterministisch, kollisionsarm. <strong>Aber:</strong> Sie ist <em>für sich genommen nicht dafür gedacht, Passwörter zu sichern</em>, weil sie zu schnell berechenbar ist.</li>
        <li><strong>KDF (Key Derivation Function):</strong> Eine spezialisierte Funktion, die genau das „Key-Stretching" einbaut — sie macht die Berechnung <em>absichtlich teuer</em> (viele Iterationen, viel Speicher), damit ein Angreifer pro Sekunde nur wenige Kandidaten testen kann.</li>
      </ul>
      <p><strong>Am Beispiel:</strong></p>
      <div class="codewrap"><pre><code># Langsam (für Passwort-Cracking IRRELEVANT, weil zu schnell):
#   H = SHA-256(M)              →  Milliarden Versuche/Sekunde

# Schnell für normalen Einsatz, aber zu schnell für das Cracken:
#   H = SHA-256(M + Salt)       →  Milliarden Versuche/Sekunde

# Teuer durch Key-Stretching — die KDF:
#   DK = PBKDF2(HMAC-SHA256, Passwort, Salt, 600.000 Iterationen)   → tausende/Sek
#   DK = scrypt(Passwort, Salt, N=2^14, r=8, p=1)                   → hunderte/Sek
#   DK = Argon2id(Passwort, Salt, m=64 MiB, t=3, p=1)               → Dutzende/Sek
#   DK = bcrypt(Passwort, Salt, cost=12)                            → hunderte/Sek</code></pre></div>
      <p><strong>Warum iterieren KDFs und nicht nur eine Runde?</strong> Eine Runde PBKDF2-HMAC-SHA256 ≈ 1 × SHA-256. Mit 600k Iterationen multipliziert sich die Zeit pro Kandidat — der Angreifer verliert entsprechend einen Faktor 600k. Genau das macht den Unterschied zwischen „sofort geknackt" und „deutlich teurer".</p>
      <p><strong>Was du zusätzlich über KDFs wissen musst:</strong></p>
      <ul>
        <li><strong>PBKDF2:</strong> baut auf einer Basis-PRF (meist HMAC), Parameter: <code>c</code> = Iterationen, <code>dkLen</code> = gewünschte Schlüssellänge. Empfehlung (OWASP): ≥ 600.000 Iterationen.</li>
        <li><strong>bcrypt:</strong> Blowfish-basiert, hat einen harten Speicher- und CPU-Kosten-Faktor (<code>cost</code>, logarithmisch) — 2^cost Operationen.</li>
        <li><strong>scrypt:</strong> speicherintensiv (parametrisierbar über <code>N</code>), macht FPGAs/ASICs weniger attraktiv.</li>
        <li><strong>Argon2:</strong> Gewinner des Password Hashing Competition. Speicherhart (<code>m</code>), iterativ (<code>t</code>), parallel (<code>p</code>). Varianten Argon2d (GPU-resistent), Argon2i (side-channel-resistent), Argon2id (beides). Siehe <a href="#" data-goto="theorie">Theorie</a>.</li>
      </ul>
      <p><strong>Praxisbezug zum Cracking:</strong> Ein FAST Hash (MD5, SHA-1, SHA-256, NTLM) gegen ein KDF (bcrypt, Argon2, PBKDF2) zu rechnen bedeutet einen Unterschied von mehreren Größenordnungen in der H/s-Zahl. Genau deshalb sind die <code>-m</code>-Modi für 7z, iWork oder KDBX so viel langsamer als <code>-m 0</code>/<code>-m 100</code> — das sind keine reinen Hash-Funktionen, sondern Datei-Verschlüsselungs-KDFs.</p>
      <p><strong>Merken für die Prüfung:</strong> Hash-Funktion = schnell + für Passwort-Hashing ungeeignet. KDF = absichtlich teuer + zweckgebunden für Passwort-Hashing/Key-Derivation. Bei den Datei-Formaten im Lab (PDF-AES, iWork, 7z, KeePass) steckt fast immer ein KDF (PBKDF/AES-KDF/Argon2) drin — deshalb sind diese Modi langsamer als reine Hashing-Angriffe.</p>` },
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
    { id:"th-hashfn", title:"Hashfunktionen — und wann sie ungeeignet sind", meta:"H(M)=h, KDF-Überblick", body:
      `<ul>
        <li>Eine Hashfunktion <code>H</code> bildet beliebig lange Nachrichten <code>M</code> auf einen Wert fester Länge ab: <code>h = H(M)</code>. Eine Bitänderung in <code>M</code> soll <code>h</code> mit hoher Wahrscheinlichkeit ändern (Lawineneffekt).</li>
        <li>Kollisionen sind bei jeder Hashfunktion unvermeidbar; kryptografische Hashfunktionen machen das Finden einer Kollision in der Praxis unmöglich — eine „normale" Hashfunktion (wie <code>String.hashCode()</code>) bietet diesen Schutz nicht.</li>
        <li><strong>Wichtig fürs Verständnis:</strong> MD5, SHA-256, SHA-512, RIPE-MD sind für <em>Passwort-Hashing</em> ungeeignet, weil sie zu schnell berechenbar sind und kein eingebautes Key-Stretching haben. Als <em>Dokument-Integritätsprüfung</em> (Datei unverändert?) sind sie dagegen völlig normal.</li>
        <li>Spezialisierte KDFs: <strong>PBKDF2</strong> (Ethereum-Wallets), <strong>bcrypt</strong> (Blowfish-basiert, OpenBSD), <strong>scrypt</strong> (u. a. Smartphone-Passwort-Hashing), <strong>Argon2</strong> (z. B. LUKS2), <strong>yescrypt</strong> (moderne Linux-Distros). Alle sind parametrisierbar (Laufzeit/Speicher), um Angriffe zu verlangsamen.</li>
      </ul>
      <p>Ausführlicher Vergleich siehe <a href="#" data-goto="rest">Der Rest → Hash-Funktionen vs. KDFs</a>.</p>` },
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
  renderAccordion("acc-hc-benchmark", HC_BENCHMARK);
  renderAccordion("acc-sonder", SONDER);
  renderAccordion("acc-tasks", TASKS);
  renderAccordion("acc-hash-vs-kdf", HASH_VS_KDF);
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
      var snippet = m.text.replace(/\s+/g, " ").trim().slice(0, 140);
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