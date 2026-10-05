"""Render the audit and its evidence index as a standalone, printable HTML report."""
import html
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'docs' / 'Security-2026-10-05'
findings = [
    ('S01', 'Hoog', 'JavaScript via login-doorverwijzing',
     'Een aanvaller kon een loginlink met een javascript:-next meegeven. Na succesvolle login voerde de browser die code uit in de sitecontext. Vereist dat het slachtoffer de link gebruikt en inlogt; ook beheerders konden doelwit zijn.',
     'In lokale Chrome aangetoond op commit 29db7a6 met een onschadelijke JavaScript-marker en een gesimuleerde verificatieresponse. Geen productieaccount aangevallen.',
     'next wordt server-side beperkt tot lokale paden; controles op backslashes, controletekens en percent-encoding; veilige JSON-inbedding.', 'browser-security.json'),
    ('S02', 'Hoog', 'Opgeslagen JavaScript in beheerknoppen',
     'Een manager kon via een veilingtitel de JavaScript-string in een onclick-handler doorbreken. Uitvoering volgde wanneer een beheerder op verwijderen klikte. Dit kon de grens tussen manager en owner doorbreken. Een vergelijkbaar invoegpatroon bestond voor manager-e-mailadressen.',
     'Uitvoering van de titel-marker in echte lokale Chrome bevestigd; na de wijziging bleef de marker onuitgevoerd. E-mailcontext aanvullend met template-regressietests gecontroleerd.',
     'Dynamische tekst staat nu in automatisch ge-escapete data-attributen, buiten de JavaScript-broncode.', 'browser-security.json'),
    ('S03', 'Hoog', 'Afbeeldingsproxy: interne doelen en actieve inhoud',
     'Een ingelogde beheerder kon de proxy naar een intern HTTPS-adres laten verwijzen. Redirects en DNS-antwoorden werden niet begrensd. De proxy gaf tevens het aangeleverde Content-Type door, inclusief HTML op de eigen origin. Voor gewone deelnemers was de beginhost beperkt, maar redirects werden niet opnieuw gevalideerd.',
     'Oude route accepteerde een loopbackdoel en gaf HTML met status 200 terug in een netwerkmock. Dit bewijst de ontbrekende grenscontrole, niet toegang tot een daadwerkelijk intern productiesysteem. Private DNS, gemengde antwoorden en redirects zijn lokaal getest.',
     'Alleen HTTPS/443 en publieke IP-adressen; iedere redirect opnieuw controleren; verbinding vastzetten op gevalideerd IP met TLS-hostnaamcontrole; maximaal 5 MiB; raster-signaturen; nosniff en sandbox-CSP. Openbaar Tosch-logo via de nieuwe downloader succesvol opgehaald.', 'baseline-evidence.json'),
    ('S04', 'Hoog', 'Racecondities in inlogcodes en pogingentellers',
     'Gelijktijdige verzoeken omzeilden eenmalig codegebruik en de limieten op aanvragen en foutieve pogingen. Voor succesvol hergebruik is een geldige code nodig; verloren pogingentellers verzwakten de bescherming tegen raden.',
     'Op de oude code met geforceerde interleaving: 8 correcte verzoeken gaven 8 successen; 8 verkeerde pogingen registreerden slechts 1 poging; 8 codeaanvragen kwamen door de limiet van 3. Alles met synthetische data in aparte PostgreSQL.',
     'Gedeelde transactielock per e-mailadres, rij-lock, atomair verbruik en tellen. Nieuwe codes worden als HMAC opgeslagen. Nieuwe test: slechts 1 succes, maximaal 5 verkeerde pogingen, maximaal 3 codes. Oude codes verlopen normaal binnen 10 minuten.', 'database-tests.txt'),
    ('S05', 'Middel', 'HTML-injectie in andere e-mailtemplates',
     'De gemelde feedbacktekst was al ge-escapet. Namen in inlogmails en namen/titels in afloopmails waren dat niet: ongewenste opmaak of phishinginhoud was mogelijk. Dit is geen bewijs van scriptuitvoering in een mailclient.',
     'Template-tests met HTML in naam en titel; uitgaande e-mail was gemockt.',
     'Alle betreffende tekstwaarden worden nu HTML-ge-escapet; interne mailproviderfouten worden niet meer aan gebruikers teruggegeven.', 'security-tests.txt'),
    ('S06', 'Middel', 'Onvoldoende begrenzing van browserverzoeken en misbruik',
     'Schrijfroutes hadden geen expliciete Origin-controle en accepteerden JSON via browser-simple contenttypes. SameSite=Lax was een bestaande beperking, maar bood geen complete bescherming tegen verzoeken vanaf een andere site onder hetzelfde hoofddomein. Feedback en codeaanvragen over veel adressen waren onvoldoende begrensd.',
     'Offline route-tests voor vreemde en sibling origins, contenttypes, ongeldige JSON en omvang. Echte PostgreSQL-tests voor gelijktijdige feedback en aanvragen over meerdere e-mailadressen.',
     'Origin/Fetch-Metadata-controle, application/json, maximaal 64 KiB en veldlimieten. Database-limieten: login 60/IP per vast venster van 10 minuten plus 3/adres per 10 minuten; feedback 5/gebruiker en 20/IP per vast venster. Een venstergrens kan kortstondig een dubbele burst toelaten.', 'database-tests.txt'),
    ('S07', 'Middel', 'Sessies, caching en invoergrenzen',
     'Cookies misten expliciet Secure; dynamische responses kregen geen expliciet private/no-store. HSTS bestond al. Bedragen, datum en documentstructuren hadden onvolledige validatie. De winnaarweergave vergeleek zichtbare namen, waardoor gelijke namen een onjuiste eigen-winnaarmelding konden geven.',
     'Regressies controleren cookieflags, tokenintegriteit/leeftijd, cacheheaders, bedragen, domeintoegang en verschillende accounts met dezelfde naam. Geen aangetoond incident van cachelek of cookiediefstal.',
     'Secure op HTTPS/Vercel, private/no-store, beperkte invoer, centprecisie en identiteit op e-mailadres intern. API blijft e-mail/IP van bieders verbergen. Beheerverwijderingen gebruiken dezelfde veilinglock als bieden.', 'security-tests.txt'),
    ('S08', 'Laag / niet bereikbaar aangetoond', 'Kwetsbare ongebruikte multipart-dependency',
     'pip-audit vond 3 unieke advisories voor python-multipart 0.0.29, dubbel gerapporteerd via aliases: CVE-2026-53538, CVE-2026-53539 en CVE-2026-53540. De applicatie gebruikt geen multipart/form-parser; een bereikbaar exploitpad is niet aangetoond.',
     'Dependency-audit op requirements en hun opgeloste transitieve dependencies; dit is geen volledige inventaris van het Vercel-runtime-image.',
     'Ongebruikte dependency verwijderd. Herhaalde audit rapporteert geen bekende kwetsbaarheden in de resterende opgeloste dependencyset.', 'dependencies-after.json'),
]
open_items = [
    ('Hoog — databaseprivileges', 'De productieverbinding heeft CREATEDB, CREATEROLE en BYPASSRLS, en kan schema’s/tabellen maken. Geen superuser. Dit vergroot de schade bij compromittering van de applicatie of credentials. Maak een aparte runtime-rol met alleen noodzakelijke tabel- en sequentierechten; gebruik een aparte migratierol. De huidige app voert schema-initialisatie uit, dus dit vereist een gerichte migratie plus wijziging van de Vercel-secret. Rechten van de bestaande mogelijk gedeelde rol zijn niet gewijzigd.'),
    ('Middel — CSP', 'script-src bevat nog unsafe-inline vanwege bestaande inline handlers. De concrete injectiepaden zijn gerepareerd, maar de CSP beschermt onvoldoende tegen een volgende scriptinjectie. Verplaats handlers naar externe scripts en gebruik nonces/hashes voor resterende scripts.'),
    ('Middel — sessie-intrekking en monitoring', 'Sessies zijn ondertekende cookies met 30 dagen sliding geldigheid. Rollen worden live gecontroleerd, maar er is geen individuele centrale sessie-intrekking. Voeg sessieregistratie/revocation en monitoring toe; een globale secretswissel logt iedereen uit en is tijdens deze audit niet uitgevoerd.'),
    ('Ontwerpkeuze — inschrijving en feedback', 'Iedereen met een geverifieerd e-mailadres kan deelnemer worden; domeinbeperkingen gelden per veiling. Het feedbackbord is toegankelijk voor ingelogde deelnemers. Als dit uitsluitend voor medewerkers bedoeld is, moet een globale toelatingslijst worden toegevoegd. De known-response bij codeaanvraag onthult bovendien of een adres al bekend is.'),
    ('Dekking — vervolgonderzoek', 'Geen volledige Vercel-toegangslogs, cloudaccount/IAM-inventaris, back-uphersteltest, gedistribueerde DoS-test of volledige supply-chain-analyse uitgevoerd. Bandit houdt 9 meldingen over: 8 lage meldingen over foutafhandeling en 1 middelhoge URL-open-melding voor de vaste SMTP2GO-API-URL (handmatig beoordeeld, geen gebruikersgestuurde URL). Dit is geen veiligheidsgarantie.'),
]

def esc(value): return html.escape(str(value))
live_path = OUT / 'live-after.json'
live = json.loads(live_path.read_text()) if live_path.exists() else None
live_version = next((x.get('version') for x in live['checks'] if x['path']=='/'), None) if live else None
status = 'Productiecontrole bevestigt ' + live_version if live_version == 'v1.10.1' else 'Reparaties lokaal getest; productiecontrole nog niet vastgelegd'
parts = ['<!doctype html><html lang="nl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Securityaudit Tosch Veiling — 5 oktober 2026</title>',
'''<style>body{font:16px/1.6 system-ui,sans-serif;max-width:1050px;margin:40px auto;padding:0 24px;color:#202630}h1,h2,h3{line-height:1.25}h1{border-bottom:5px solid #ff6f00;padding-bottom:20px}article{border:1px solid #ddd;border-radius:10px;padding:20px;margin:20px 0}dt{font-weight:700;margin-top:12px}dd{margin-left:0}a{color:#07569c}.status{background:#fff1df;padding:18px;border-radius:8px}table{border-collapse:collapse;width:100%}td,th{text-align:left;padding:9px;border-bottom:1px solid #ddd}code{overflow-wrap:anywhere} @media print{body{margin:0;font-size:11px}article{break-inside:avoid}a{color:inherit}}</style>''',
'<h1>Securityaudit Tosch Veiling</h1><p>5 oktober 2026 · veiling.tosch.nl · baseline v1.10.0 / commit 29db7a6 · reparatie v1.10.1</p>',
f'<p class="status"><strong>{esc(status)}</strong>. Meerdere aantoonbare kwetsbaarheden gerepareerd. Te ruime databaseprivileges blijven een open actie met hoge prioriteit.</p>',
'<h2>Aanleiding en incidentcontrole</h2><p>De aangeleverde HTML-test in feedback is in de bestaande feedbackmail en het bord ge-escapet. De doelgerichte, alleen-lezen productiecontrole vond voor de melder een deelnemersaccount, feedback #8 met uitsluitend een b-tag, nul biedingen en één geregistreerde login; geen geregistreerde beheermutaties. Er zijn geen script-indicatoren in gebruikersnamen gevonden. Dit bewijst niet dat er nooit misbruik is geweest; volledige HTTP-toegangslogs zijn niet onderzocht. De melding is niet verwijderd en de afzender is niet benaderd.</p>',
'<h2>Methode en afbakening</h2><p>Broncode, 32 routes, autorisatie, templates/DOM-sinks, SQL-parameterisatie, sessies, inlogcodes, transacties, e-mail, afbeeldingsproxy, dependencies en Git-historie onderzocht. Live: 22 begrensde anonieme GET-controles, HTTP→HTTPS en TLS; bronbestanden/secrets niet publiek gevonden, beheer en API vereisen login. De productie-DB is uitsluitend met een gecontroleerde read-only transactie geraadpleegd voor gerichte incident- en rechtenmetadata. Aanvalsscenario’s zijn uitgevoerd op localhost met synthetische gegevens; geen echte testmails, productie-aanvalspayloads of belastingstest. Deployment kan de nieuwe limiettabel aanmaken.</p>',
'<p>Historische secretscan: 46 unieke tekstblobs, nul treffers op de gebruikte patronen. Dit sluit onbekende formats of niet-gescande bestanden niet uit. Lokale configuratie heeft een sessiesecret van minstens 32 tekens en vereist DB-TLS; de productie-DB-verbinding gebruikte TLS. Geen secretwaarden zijn in het rapport opgenomen.</p>',
'<h2>Bevindingen en reparaties</h2>']
for fid, severity, title, impact, evidence, fix, artifact in findings:
    parts.append(f'<article id="{fid}"><h3>{fid} · {esc(severity)} · {esc(title)}</h3><dl><dt>Impact en voorwaarden</dt><dd>{esc(impact)}</dd><dt>Bewijs</dt><dd>{esc(evidence)} <a href="{artifact}">Bewijsbestand</a></dd><dt>Reparatie</dt><dd>{esc(fix)}</dd></dl></article>')
parts.append('<h2>Open acties en beperkingen</h2>')
for title, body in open_items:
    parts.append(f'<h3>{esc(title)}</h3><p>{esc(body)}</p>')
parts.append('''<h2>Validatie</h2><table><tr><th>Controle</th><th>Resultaat</th></tr>
<tr><td>Offline security-regressies</td><td>22 geslaagd</td></tr><tr><td>Security met aparte PostgreSQL</td><td>10 geslaagd</td></tr>
<tr><td>Bestaande veilingtransacties en verlenging</td><td>12 geslaagd</td></tr><tr><td>JavaScript countdown</td><td>8 geslaagd</td></tr>
<tr><td>Chrome security voor/na</td><td>Login-redirect en opgeslagen titel getest</td></tr>
<tr><td>Chrome functioneel</td><td>Twee bieders, herhaald verlengen, tijdzones, mobiel, overzicht, winnaar en weigeren laat bod geslaagd</td></tr>
<tr><td>Dependency-audit na reparatie</td><td>0 bekende kwetsbaarheden in opgeloste requirements</td></tr></table>
<p>52 geautomatiseerde tests plus twee browserscenario-suites. Verouderingswaarschuwing voor de httpx-TestClient verandert de testuitslag niet. Testdatabase: aparte PostgreSQL op localhost:55439; testfixtures blokkeren .env en echte e-mail.</p>
<h2>Uitrol en terugval</h2><p>Versie 1.10.1 voegt veiling_request_limits toe; bestaande veilingen, biedingen en feedback worden niet verwijderd. HMAC-opslag geldt voor nieuw aangevraagde codes; bestaande codes verlopen binnen hun normale tien minuten. Open browsertabbladen moeten worden ververst om nieuwe JavaScript te laden. Bij terugval moet rekening worden gehouden met opgeslagen HMAC-codes: de oude versie kan deze niet verifiëren; laat betrokken gebruikers dan een nieuwe code aanvragen. De limiettabel kan bij terugval blijven staan.</p>
<h2>Reproduceren</h2><p><code>.venv/Scripts/python.exe tests/test_security.py</code><br><code>.venv/Scripts/python.exe tests/test_security_db.py</code><br><code>.venv/Scripts/python.exe tests/test_extension.py</code><br><code>node --test tests/countdown.test.mjs</code><br><code>node tests/security_browser.mjs</code><br><code>node tests/browser.mjs</code></p>
<p>Database- en browsertests die dezelfde testdatabase gebruiken na elkaar uitvoeren. De baseline-evidence-test gebruikt git show 29db7a6 en geforceerde thread-interleaving; geen productie-DSN gebruiken.</p>
<h2>Bronnen</h2><ul>
<li><a href="https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html">OWASP: contextafhankelijke output-escaping</a></li>
<li><a href="https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html">OWASP: SSRF, redirects en DNS</a></li>
<li><a href="https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html">OWASP: CSRF en Origin-controle</a></li>
<li><a href="https://vercel.com/docs/headers/request-headers">Vercel: doorgestuurde client-IP-headers</a></li>
<li><a href="https://github.com/Kludex/python-multipart/security/advisories">python-multipart: upstream security-advisories</a></li></ul><h2>Bewijsbestanden</h2><ul>''')
if live_version == 'v1.10.1':
    parts.insert(-1, '<h2>Controle na uitrol</h2><p>Productie toont v1.10.1. De herhaalde anonieme routecontrole gaf geen 5xx-responses; de loginpagina gebruikt private, no-store. Drie ongeldige POST-verzoeken zonder e-mailadres leverden de verwachte 400 (ongeldige invoer), 403 (vreemde Origin) en 415 (text/plain). Er is geen loginmail aangevraagd. De read-only DB-nacontrole bevestigt de nieuwe limiettabel, ongewijzigde incidentmetadata en de nog te ruime DB-rechten. De tijdelijke lokale PostgreSQL-testserver is na de tests gestopt.</p>')
for path in sorted(OUT.iterdir()):
    if path.suffix in ('.json','.txt'):
        parts.append(f'<li><a href="{esc(path.name)}">{esc(path.name)}</a></li>')
parts.append('</ul></html>')
(OUT/'rapport.html').write_text('\n'.join(parts),encoding='utf-8')
print(status)
