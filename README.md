# Versteckt - HackMyVM (Medium)
 
![Versteckt.png](Versteckt.png)

## Übersicht

*   **VM:** Versteckt
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Versteckt)
*   **Schwierigkeit:** Medium
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 11. Oktober 2022
*   **Original-Writeup:** https://alientec1908.github.io/Versteckt_HackMyVM_Medium/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel der "Versteckt"-Challenge war die Erlangung von User- und Root-Rechten. Der Weg begann mit der Enumeration eines Webservers (Port 80), auf dem eine `/robots.txt` den Hinweis `S3CR3TZ0N3` (NATO-Alphabet für "S3CR3TZ0N3") enthielt. Dieses Verzeichnis enthielt eine `audio.wav`, deren Morsecode-Inhalt auf ein weiteres Verzeichnis `/m0r3inf0/` verwies. Aus dem HTML-Inhalt dieser Seite wurde mittels `cewl` eine Wortliste generiert, die für einen SSH-Brute-Force-Angriff (Port 22334) auf den Benutzer `marcus` verwendet wurde. Das Passwort `Falcon` wurde gefunden. Als `marcus` wurde MariaDB-Zugriff mit demselben Passwort erlangt. In der Datenbank `versteckt` wurden in den Tabellen `secret` und `secret2` Base64-kodierte Teile eines Passworts für den Benutzer `Benjamin` gefunden. Nach dem Zusammenfügen und Dekodieren (`kr4k4t04th3b3sTpl4c3`) gelang der SSH-Login als `Benjamin`. Die User-Flag wurde in dessen Home-Verzeichnis gefunden. Die Privilegieneskalation zu Root erfolgte durch Ausnutzung eines SUID-Root-Binaries `/usr/bin/chsn`. Dieses rief den `cat`-Befehl ohne absoluten Pfad auf. Durch PATH-Manipulation (Erstellen einer eigenen `cat`-Datei, die `bash` startete) wurde eine Root-Shell erlangt.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `gobuster`
*   `nikto`
*   `nc` (netcat)
*   `curl`
*   `wget`
*   Online Morse Decoder
*   `cewl`
*   `hydra`
*   `ssh`
*   `mysql` (MariaDB Client)
*   `base64`
*   `python3` (für Shell-Stabilisierung)
*   `sudo` (versucht)
*   `find`
*   `passwd` (zur Passwortänderung)
*   `chsn` (Custom Binary)
*   `echo`
*   `chmod`
*   `touch`
*   `export`
*   `cat`
*   `tail`
*   Standard Linux-Befehle (`ls`, `cd`, `id`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Versteckt" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web Enumeration (Clue Hunting):**
    *   IP-Findung mit `arp-scan` (`192.168.2.139`).
    *   `nmap`-Scan identifizierte offene Ports: 80 (HTTP - Apache 2.4.51, Directory Listing aktiv) und 22334 (SSH - OpenSSH 8.4p1).
    *   `gobuster` und `nikto` auf Port 80. `/robots.txt` enthielt "Sierra Three Charlie Romeo Three Tango Zulu Zero November Three", was zu `/s3cr3tz0n3/` dekodierte.
    *   In `/s3cr3tz0n3/` wurde `audio.wav` gefunden. Morsecode-Dekodierung ergab `/m0r3inf0/`.
    *   `cewl` wurde auf `http://192.168.2.139/s3cr3tz0n3/m0r3inf0/` angewendet, um eine Wortliste (`text.txt`) zu generieren.

2.  **Initial Access (SSH als `marcus` und `benjamin`):**
    *   `hydra -l marcus -P text.txt -f 192.168.2.139 -s 22334 ssh` fand das Passwort `Falcon` für `marcus`.
    *   SSH-Login als `marcus:Falcon`.
    *   Als `marcus` wurde MariaDB-Zugriff mit demselben Passwort (`Falcon`) erlangt.
    *   In der Datenbank `versteckt` wurden in den Tabellen `secret` (ID 11: `a3I0azR0MDR0`) und `secret2` (ID 11: `aDNiM3NUcGw0YzMK`) Base64-kodierte Passwortteile gefunden.
    *   Zusammenfügen und Dekodieren (`echo "a3I0azR0MDR0aDNiM3NUcGw0YzMK" | base64 -d`) ergab das Passwort `kr4k4t04th3b3sTpl4c3`.
    *   SSH-Login als `benjamin` mit dem Passwort `kr4k4t04th3b3sTpl4c3`. (Passwort wurde später zu `benni19` geändert).
    *   User-Flag `HMV{y0uR3gR34T}` in `/home/benjamin/user.txt` gelesen.

3.  **Privilege Escalation (von `benjamin` zu `root` via SUID Binary `chsn` und PATH Hijacking):**
    *   `sudo -l` für `benjamin` zeigte keine Sudo-Rechte.
    *   `find / -type f -perm -4000 ...` identifizierte ein SUID-Root und SGID-`benjamin` Binary `/usr/bin/chsn` (`-rwsrwx---`).
    *   Ausführen von `chsn` zeigte, dass es versuchte, `/tmp/proc.txt` mit `cat` (ohne absoluten Pfad) auszugeben.
    *   PATH-Manipulation:
        1.  `echo bash > /home/benjamin/cat`
        2.  `chmod +x /home/benjamin/cat`
        3.  `touch /tmp/proc.txt`
        4.  `export PATH=/home/benjamin/:$PATH`
    *   Ausführung von `chsn` als `benjamin`. Das SUID-Binary fand und führte nun die manipulierte `cat`-Datei (welche `bash` enthielt) mit Root-Rechten aus.
    *   Erlangung einer Root-Shell.
    *   Root-Flag `HMV{y0uR3D3fin1t3lytH3b3S7}` in `/root/root.txt` gelesen.

## Wichtige Schwachstellen und Konzepte

*   **Hinweise in `robots.txt` (NATO-Alphabet):** Führte zu einem versteckten Verzeichnis.
*   **Steganographie (Morsecode in Audio):** Enthüllte ein weiteres verstecktes Verzeichnis.
*   **Passwort-Brute-Force (SSH):** Erfolgreich mit einer kontextbasierten Wortliste (`cewl`).
*   **Passwort-Wiederverwendung:** SSH-Passwort funktionierte auch für MariaDB.
*   **Credentials in Datenbank (Base64-kodiert und aufgeteilt):** Rekonstruktion eines Passworts aus Datenbankeinträgen.
*   **SUID-Binary-Exploitation (`chsn`):** Ein SUID-Root-Programm rief einen Befehl (`cat`) ohne absoluten Pfad auf, was PATH-Manipulation zur Ausführung beliebigen Codes als Root ermöglichte.
*   **PATH Hijacking:** Modifizieren der `PATH`-Umgebungsvariable, um ein bösartiges Skript anstelle des legitimen Befehls auszuführen.
*   **Directory Listing auf Webserver:** Aktiviertes Directory Listing erleichterte die Navigation.
*   **SSH auf nicht standardmäßigem Port:** Erschwerte die Entdeckung geringfügig.

## Flags

*   **User Flag (`/home/benjamin/user.txt`):** `HMV{y0uR3gR34T}`
*   **Root Flag (`/root/root.txt`):** `HMV{y0uR3D3fin1t3lytH3b3S7}`

## Tags

`HackMyVM`, `Versteckt`, `Medium`, `robots.txt`, `Morse Code`, `Steganography`, `cewl`, `Hydra`, `SSH`, `MariaDB`, `Base64`, `SUID Exploitation`, `PATH Hijacking`, `Privilege Escalation`, `Linux`, `Web`
