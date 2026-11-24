/* Test harness: UI-logica van app.js. Offline, met een minimale DOM-stub
   (stub-elements per selector gecachet, zodat buildMarkdown via de DOM-stub
   aanstuurbaar is: prioriteit-select op "auto" en advisories via setAdvisories).
   Dekking: prioriteitsafleiding, CNA-normalisatie (CVE JSON 5.x), patchregels,
   KEV/SSVC-misbruikstatus, impactafleiding uit CVSS-vector, productopsomming
   en buildMarkdown-output (titel, patch-/misluktregels, CVSS-tabel, gegroepeerde
   referenties), tijdnotatie (Europe/Amsterdam), mislukt-ophalen-onderscheiding,
   CVE-status, CVE-invoervalidatie, NVD-rate-limit (cache-bewuste indexering),
   fetchJson, de CVE-fetchcache (incl. "Vers ophalen"), de geschiedenis
   (dedup, plafond, herstel) en de voortgangsmelding/herkenningshint in
   generate() (via nagebootste fetch, incl. cachede runs) en de
   try/finally-knopsherstel bij een onverwachte fout daarin, plus de
   a11y-attributen (aria-live statusbalk, aria-pressed tabs incl. klik-
   gedrag, aria-labels, API-sleutelveld type="password" incl. de bijbehorende
   veldstijl-regressiecheck in style.css), de mini-renderer
   mdToHtml (koppen, lijsten, tabellen, inline-opmaak, autolink, escaping,
   codeblok) en de print-PDF-onderdelen (paginanummers en lopende kop via
   @page-margeboxen, koptekst-striping, iframe-opruiming via afterprint), de
   favicon en de cosmetica uit de schone run (geschiedenisherstel zonder
   CVE-gegevens wist oude kaarten, de _cached-vlag blijft buiten de
   opslag-JSON terwijl _descEdit bewaard blijft, en het cache-toggle-label
   heeft geen inline style meer), plus de EPSS-exploitkans (respons-
   parsing, gebundelde en gecachete ophaal, "niet in model"-ontlasting,
   regeltekst met Nederlandse komma en weglaten bij mislukte ritten), de
   distributeurtrackers (URL-vormen, skip/cap en het blok in de advisory) en
   de jsPDF-export (markdown-regelconverter, routeknop jsPDF/printdialoog
   incl. vink en ontbrekende CDN, CDN-script volgorde, de async-lading en de
   SRI-pin van het CDN-script, en het vink buiten het geschiednissnapshot),
   de gedeelde kop-helper pdfKoptekst (striping, afkapping op 90 tekens met
   ellipsis) en de layoutloop van exportPdfJsPdf tegen een namaak-jsPDF
   (paginering, lopende kop en paginanummer per pagina, weeskopbescherming,
   bestandsnaam), plus de eigen naam per geschiedenisregel (notatie met en
   zonder naam, spaties/afkapping/lege invoer, herstelmelding en de bedrading
   van het labelveld in HTML, CSS en app.js), plus de optionele
   stroomschema-afbidding (notatie, positie onder de adviezen, <img> in de
   preview, "bijschrift: url" in de tekstexport en het geschiednissnapshot)
   en de html2canvas-export "met opmaak" (terugval zonder CDN-bibliotheken
   en bij een mislukte tekening incl. finally-opruiming van de verborgen
   kopie, repen per A4-pagina en verborgen kopie van de preview tegen
   namaak-canvas en namaak-jsPDF, lopende kop en paginanummers,
   -opmaak-bestandsnaam, de CDN-tag met async/SRI, de knopbedrading in HTML
   en app.js, en de jsPDF-constructors die alleen bestaande opties
   meegeven), plus de afbreekbare KEV-/EPSS-achtergrondverzoeken
   (signaal-doorifte, AbortError zonder retry en zonder uitval, de
   gebundelde achtergrondherbouw in restoreState en de abort bij een nieuwe
   generatie), plus de stub-hygiëne rond de gedeelde preview-stub (de
   terugval-printdialoog bewijst via een opgenomen iframe-schrijfwerk dat
   hij de actuele preview-inhoud gebruikt en niet de restwaarde van een
   eerdere sectie), plus de printdialoog die wacht op nog ladende
   afbeeldingen (load en error laten allebei door, een cap van 3 s houdt
   de dialoog bereikbaar bij een plaatje dat nooit laadt, en dubbele
   load-events drukken precies één keer af), plus de weeskopbescherming op
   de repengrens van de raster-route (kopposities uit de verborgen kopie,
   doorschuiven bij een kop vlak boven de grens, geen beeldverlies, laatste
   reep onbeschermd), plus de drie consistentiepunten uit schone-run-punt 7
   (elk console-foutpad draagt het "Advisory Writer:"-prefix, de bedrading
   van het geschiedenislabelveld is afwezigheidsbestendig, en de modeldatum
   uit de EPSS-arrayrespons wordt bewaard), plus de harde timeout per
   fetchpoging (hangende verbinding geeft op na timeoutMs zonder retry,
   snelle responsen en timeoutMs 0 gedragen zich als voorheen) en de
   URL-schemabeveiliging van het stroomschemaveld (http(s), relatief en
   data:image toegestaan; javascript: en blob: laten de regel vallen).
   Run: node test/test-ui.js   (vanuit de projectmap) */
"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");

// ---- minimale browser-stub zodat app.js ladingsgewijs meedraait ----
const noop = () => {};
const stubEl = () => {
  const classLog = []; // bijhouden welke classList-operaties de app doet
  return {
  value: "", textContent: "", innerHTML: "", open: false, checked: false, style: {},
  classLog,
  classList: { add: (c) => classLog.push(["add", c]), remove: (c) => classLog.push(["remove", c]), contains: (c) => classLog.some(([op, x]) => op === "add" && x === c) },
  // setAttribute en addEventListener zijn geen noop meer: de a11y-test
  // controleert aria-pressed na een tabklik en heeft dus de gezette
  // attributen en de geregistreerde handlers nodig.
  attrs: {}, setAttribute(k, v) { this.attrs[k] = v; },
  listeners: {}, addEventListener(ev, fn) { (this.listeners[ev] ||= []).push(fn); },
  querySelector: () => stubEl(),
  // querySelectorAll bestaat ook: de raster-route leest de kopposities
  // (h1-h4) uit de verborgen kopie; de namaak-html2canvas van de tests
  // zet er zelf een op het kopie-element om kopposities te simuleren.
  querySelectorAll: () => [],
  // appendChild/remove en de canvas-methoden zijn er voor de html2canvas-
  // route: de verborgen kopie van de preview wordt toegevoegd (children
  // houdt bij) en de repen zijn canvas-elementen (getContext/toDataURL).
  // remove noteert nu ook: de html2canvas-tests controleren of de verborgen
  // kopie bij een mislukte tekening daadwerkelijk wordt opgeruimd (finally).
  children: [], appendChild(c) { this.children.push(c); }, removed: false, remove() { this.removed = true; },
  getContext: () => ({ drawImage: noop }), toDataURL: () => "data:reep",
  }; };
// In-memory opslag-stubs: LocalStorage (veldgeheugen, staatsherstel,
// geschiedenis) en sessionStorage (KEV- en CVE-cache) zijn nu wél aanwezig,
// zodat cache- en geschiedenistests echte lees-/schrijfbewerkingen krijgen.
// (De try/catch-robuustheid van app.js wordt niet getest; in de browser kan
// opslag ontbreken of blokkeren, en dan draait de app alsnog gewoon.)
const mkStorage = () => {
  const m = new Map();
  return {
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => { m.set(k, String(v)); },
    removeItem: (k) => { m.delete(k); },
    // clear bestaat in de echte browser ook; sectie 26 maakt de sessieopslag
    // expliciet leeg vóór de KEV-afbraaktesten (de echte localStorage- en
    // sessionStorage-API's kennen allebei clear()).
    clear: () => { m.clear(); },
  };
};
// Stub per selector cachen: app.js bewaart de elementreferenties bij het
// laden; tests moeten dáár waarden kunnen zetten (bijv. prioriteit-select).
const elCache = new Map();
// De stub krijgt een id afgeleid van de cache-sleutel (#advisory-title ->
// advisory-title), want de app gebruikt el.id: saveField schrijft het
// veldgeheugen op data[el.id], en zonder id belandde alles daar op de
// sleutel "undefined" (de veldgeheugencheck vond dan nooit "advisory-title").
const cachedStub = (key) => {
  if (!elCache.has(key)) { const el = stubEl(); el.id = key.replace(/^#/, ""); elCache.set(key, el); }
  return elCache.get(key);
};
const sandbox = {
  document: {
    querySelector: (sel) => cachedStub(sel),
    getElementById: (id) => cachedStub("#" + id),
    // createElement geeft een iframe een contentWindow: de printdialoog-
    // terugval van de html2canvas-tests schrijft naar en print op het
    // iframe-document (alles genotuleerd of noop, geen echte afdruk).
    createElement: (tag) => {
      const el = stubEl();
      if (tag === "iframe") {
        el.contentWindow = {
          document: { open: noop, write: noop, close: noop },
          addEventListener: noop, removeEventListener: noop, focus: noop, print: noop,
        };
      }
      return el;
    },
    body: cachedStub("#body"),
  },
  localStorage: mkStorage(),
  sessionStorage: mkStorage(),
  location: { search: "", origin: "http://localhost:8080", pathname: "/" },
  URLSearchParams,
  navigator: {},
  fetch: async () => { throw new Error("geen netwerk in test"); },
  confirm: () => false,
  Blob: class {},
  setTimeout, clearTimeout, console,
};
const src = fs.readFileSync(path.join(__dirname, "..", "app.js"), "utf8");
const context = vm.createContext(sandbox);
// NB: globalThis i.p.v. this — app.js staat in strict mode, daar is `this`
// op topniveau van een script undefined. setKevMap is een testhaak om de
// KEV-feed (module-variabele kevMap) kunstmatig te vullen.
vm.runInContext(
  src + "\n;globalThis.__api = { maxSeverity, cveStatus, kevInfo, kevStatusText," +
  " parseSsvc, impactFromCvss, patchLine, extractProducts, extractCwes," +
  " discardedCveTokens, parseCveList, cleanCveToken, nvdStapMs, fetchJson, fetchCveProgram, benoemProducten, nowNl," +
  " buildMarkdown, groepeerReferenties, fetchCve, clearCveCache, netIndexen," +
  " historyPush, historyRead, historyRestore, historyDelete, historyClearAll, historyRename," +
  " geschiedenisOptieTekst, generate, mdToHtml," +
  " epssUitRespons, laadEpss, clearEpssCache, epssInfo, epssRegelTekst, distributeurRegels, loadKev," +
  " pdfRegels, pdfRoute, pdfKoptekst, exportPdfJsPdf, captureFields," +
  " stroomRegelTekst, html2canvasKlaar, exportPdfMetOpmaak, exportPdfPrinten," +
  " setKevMap: (m) => { kevMap = m; }," +
  " kevState: () => ({ map: kevMap ? kevMap.size : null, failed: kevFailed })," +
  " resetKevState: () => { kevMap = null; kevFailed = false; try { sessionStorage.removeItem(KEV_CACHE_KEY); } catch { /* leeg */ } }," +
  " setAdvisories: (a) => { advisories = a; }," +
  " getAdvisories: () => advisories," +
  " setLastMarkdown: (s) => { lastMarkdown = s; } };",
  context
);
const {
  maxSeverity, cveStatus, kevInfo, kevStatusText, parseSsvc, impactFromCvss,
  patchLine, extractProducts, extractCwes, discardedCveTokens, parseCveList, cleanCveToken, nvdStapMs,
  fetchJson, fetchCveProgram, benoemProducten, nowNl, buildMarkdown,
  groepeerReferenties, fetchCve, clearCveCache, netIndexen,
  historyPush, historyRead, historyRestore, historyDelete, historyClearAll, historyRename,
  geschiedenisOptieTekst, generate, mdToHtml,
  epssUitRespons, laadEpss, clearEpssCache, epssInfo, epssRegelTekst, distributeurRegels, loadKev,
  pdfRegels, pdfRoute, pdfKoptekst, exportPdfJsPdf, captureFields,
  stroomRegelTekst, html2canvasKlaar, exportPdfMetOpmaak, exportPdfPrinten,
  setKevMap, kevState, resetKevState, setAdvisories, getAdvisories, setLastMarkdown,
} = sandbox.__api;

let pass = 0, fail = 0;
function check(name, actual, expected) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}  ->  ${JSON.stringify(actual)}${ok ? "" : "  (verwacht: " + JSON.stringify(expected) + ")"}`);
  ok ? pass++ : fail++;
}
const m = (score, sev) => ({
  metrics: { cvssMetricV31: [{ type: "Primary", cvssData: { baseScore: score, baseSeverity: sev, vectorString: "V" } }] },
});
// CVE's met echte vectorstringen (voor de impactafleiding)
const rce = { id: "CVE-1", metrics: { cvssMetricV31: [{ type: "Primary", cvssData: { baseScore: 9.8, baseSeverity: "CRITICAL", vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" } }] } };
const lokaal = { id: "CVE-2", metrics: { cvssMetricV31: [{ type: "Primary", cvssData: { baseScore: 7.8, baseSeverity: "HIGH", vectorString: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" } }] } };
const geenVector = { id: "CVE-3", metrics: { cvssMetricV31: [{ type: "Primary", cvssData: { baseScore: 5, baseSeverity: "MEDIUM" } }] } };

// ---------- 1. maxSeverity: zwaarste over meerdere CVE's ----------
check("maxSeverity: eerste LAAG, tweede KRITIEK -> KRITIEK",
  maxSeverity([m(1, "LOW"), m(9.3, "CRITICAL")]), "CRITICAL");
check("maxSeverity: volgorde maakt niet uit",
  maxSeverity([m(9.3, "CRITICAL"), m(5, "MEDIUM"), m(7, "HIGH")]), "CRITICAL");
check("maxSeverity: lege lijst -> UNKNOWN", maxSeverity([]), "UNKNOWN");
check("maxSeverity: CVE zonder metrics genegeerd",
  maxSeverity([{}, m(4, "MEDIUM")]), "MEDIUM");

// ---------- 2. CVE Program API: normalisatie CVE JSON 5.x ----------
check("fetchCveProgram accepteert product én oud name-veld",
  /product:\s*block\.product\s*\|\|\s*block\.name/.test(src), true);
check("fetchCveProgram leest publicatiedatum uit cveMetadata",
  /cveMetadata\?\.datePublished/.test(src), true);
check("fetchCveProgram kiest cweId uit problemTypes",
  /d\.cweId\s*\|\|/.test(src), true);

// extractCwes: kaal CWE-nummer (NVD) én lange CNA-omschrijving
check("extractCwes: NVD-vorm 'CWE-394'",
  extractCwes({ weaknesses: [{ description: [{ value: "CWE-394" }] }] }), ["CWE-394"]);
check("extractCwes: CNA-vorm met lange omschrijving",
  extractCwes({ weaknesses: [{ description: [{ value: "CWE-59 Improper Link Resolution Before File Access" }] }] }), ["CWE-59"]);
check("extractCwes: NVD-CWE-noinfo valt weg",
  extractCwes({ weaknesses: [{ description: [{ value: "NVD-CWE-noinfo" }] }] }), []);

// extractProducts werkt op de genormaliseerde (NVD-)vorm
check("extractProducts vindt genormaliseerd product",
  extractProducts({ affected: [{ affectedData: [{ vendor: "F5", product: "nginx", versions: [{ status: "affected", lessThan: "1.31.9" }] }] }] }),
  ["F5 nginx < 1.31.9"]);

// ---------- 3. patchregel per CVE (product van het eigen CVE) ----------
const patchCve = (id, product, lessThan) => ({
  id, affected: [{ affectedData: [{ vendor: "v", product, versions: [{ status: "affected", lessThan }] }] }],
});
check("patchLine gebruikt eigen product, niet dat van het eerste CVE",
  patchLine(patchCve("CVE-2026-1", "nginx", "1.31.9"), "OpenSSH"),
  "CVE-2026-1: patch beschikbaar (nginx 1.31.9) \u2014 zie referenties.");
check("patchLine: lessThan '*' is geen patchversie",
  patchLine(patchCve("CVE-2026-2", "nginx", "*"), "nginx"), null);
check("patchLine: zonder eigen productnaam valt terug op titelproduct",
  patchLine(patchCve("CVE-2026-3", "*", "2.0"), "OpenSSH"),
  "CVE-2026-3: patch beschikbaar (OpenSSH 2.0) \u2014 zie referenties.");

// ---------- 4. KEV/SSVC-misbruikstatus ----------
check("kevInfo: cisaExploitAdd heeft voorrang en bevat actiefrist",
  kevInfo({ id: "CVE-1", cisaExploitAdd: "2026-11-09", cisaActionDue: "2026-11-12" }),
  { actief: true, sinds: "2026-11-09", actiefrist: "2026-11-12", bron: "CISA KEV" });
// NB: datumnotatie via toLocaleDateString kan per ICU-build/tijdzone iets
// verschillen, daarom op structuur getest en niet op de exacte maandnaam.
check("kevStatusText: opnamedatum én actiefrist in de tekst",
  /^Er is actief misbruik gemeld in de CISA KEV-catalogus \(CISA KEV, sinds \d+ \S+ 2026, actiefrist \d+ \S+ 2026\)\.$/
    .test(kevStatusText({ id: "CVE-1", cisaExploitAdd: "2026-11-09", cisaActionDue: "2026-11-12" })), true);

const ssvcCve = (exploitatie) => ({
  id: "CVE-S",
  metrics: { ssvcV203: [{ source: "CISA", ssvcData: { options: [{ exploitation: exploitatie }, { automatable: "no" }, { technicalImpact: "total" }] } }] },
});
check("parseSsvc leest de drie SSVC-opties uit de NVD-respons",
  parseSsvc(ssvcCve("active")), { exploitatie: "active", automatable: "no", technicalImpact: "total" });
check("kevInfo: SSVC 'active' -> actief, bron SSVC",
  kevInfo(ssvcCve("active")), { actief: true, sinds: null, actiefrist: null, bron: "SSVC (CISA)" });
check("kevInfo: SSVC 'poc' -> apart te melden als proof of concept",
  kevInfo(ssvcCve("poc")), { actief: false, poc: true, bron: "SSVC (CISA)" });
check("kevStatusText: PoC-tekst is geen melding van actief misbruik",
  /proof of concept/.test(kevStatusText(ssvcCve("poc"))), true);
check("kevInfo: SSVC 'none' -> geen actief misbruik",
  kevInfo(ssvcCve("none")), { actief: false, poc: false, bron: "SSVC (CISA)" });
check("kevInfo: geen enkele bron -> null (regel valt weg)",
  kevInfo({ id: "CVE-X" }), null);
check("kevStatusText zonder enige bron -> null",
  kevStatusText({ id: "CVE-X" }), null);

// KEV-feed als terugval (alleen aangesproken als de API niets levert)
setKevMap(new Map([["CVE-9", { cveID: "CVE-9", dateAdded: "2026-10-01" }]]));
check("kevInfo: terugval op de KEV-feed (opnamedatum uit feed)",
  kevInfo({ id: "CVE-9" }), { actief: true, sinds: "2026-10-01", actiefrist: null, bron: "CISA KEV" });
check("kevStatusText: feed geladen, CVE erin -> 'sinds <datum>'",
  /^Er is actief misbruik gemeld in de CISA KEV-catalogus \(CISA KEV, sinds \d+ \S+ 2026\)\.$/
    .test(kevStatusText({ id: "CVE-9" })), true);
check("kevInfo: feed geladen, CVE er niet in -> expliciet geen misbruik",
  kevInfo({ id: "CVE-99" }), { actief: false, poc: false, bron: "CISA KEV" });
setKevMap(null); // terug naar 'feed niet geladen' voor de resterende tests

// ---------- 5. impactafleiding uit de CVSS-vector ----------
check("impact: AV:N/PR:N/UI:N -> Remote Code Execution zonder rechten/interactie",
  /unauthenticated remote code execution/.test(impactFromCvss([rce], "nginx")), true);
check("impact: lokale privescaler AV:L/PR:L -> 'lokaal' en 'lage rechten'",
  [impactFromCvss([lokaal], "nginx").includes("lokaal op het systeem"),
   impactFromCvss([lokaal], "nginx").includes("met lage rechten")], [true, true]);
check("impact: geen vector -> neutrale tekst met productnaam",
  impactFromCvss([geenVector], "nginx").includes("overname van de getroffen nginx-dienst"), true);
check("impact: gebruikt de zwaarste CVE, niet de eerste",
  /unauthenticated remote code execution/.test(impactFromCvss([lokaal, rce], "nginx")), true);

// ---------- 6. productopsomming en tijdnotatie ----------
check("benoemProducten: lijstjes in looptekst", [
  benoemProducten(["OpenSSH"]),
  benoemProducten(["nginx", "OpenSSL"]),
  benoemProducten(["a", "b", "c"]),
  benoemProducten(["a", "b", "c", "d"]),
  benoemProducten([]),
], ["OpenSSH", "nginx en OpenSSL", "a, b en c", "a, b, c e.a.", null]);
// Titel/aankondiging noemen nu álle producten (buildMarkdown gebruikt
// productLijst = benoemProducten(...), niet langer alleen het eerste product).
check("buildMarkdown gebruikt de productopsomming in titel en aankondiging",
  [/\$\{kwets\} in \$\{productLijst\}/, /"zitten"\} in \$\{productLijst\}/].every((re) => re.test(src)), true);
// nowNl: expliciete tijdzone-omzetting (Intl), niet de systeemtijdzone met
// een "(Europe/Amsterdam)"-label erbij. Format: DD-MM-YYYY HH:MM (Europe/Amsterdam)
check("nowNl: vast formaat DD-MM-YYYY HH:MM (Europe/Amsterdam)",
  /^\d{2}-\d{2}-\d{4} \d{2}:\d{2} \(Europe\/Amsterdam\)$/.test(nowNl()), true);
check("nowNl: gebruikt Intl met expliciete tijdzone",
  /timeZone:\s*"Europe\/Amsterdam"/.test(src), true);

// ---------- 6b. buildMarkdown: productopsomming en mislukte CVE's ----------
// Prioriteit op "automatisch" zetten (stub-waarde is leeg, en een lege
// prioriteit zou de titel onterecht "Belangrijke" maken).
cachedStub("#prioriteit-select").value = "auto";
const cvePatch = (id, product, lessThan) => ({
  id,
  descriptions: [{ lang: "en", value: `beschrijving van ${id}` }],
  metrics: { cvssMetricV31: [{ type: "Primary", cvssData: { baseScore: 9.8, baseSeverity: "CRITICAL", vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" } }] },
  affected: [{ affectedData: [{ vendor: "v", product, versions: lessThan ? [{ status: "affected", lessThan }] : [] }] }],
  references: [{ url: `https://example.com/${id}` }],
});
const gefaald = { id: "CVE-2026-99998", _fetchFailed: true };

setAdvisories([cvePatch("CVE-2026-1", "nginx", "1.31.9"), cvePatch("CVE-2026-2", "OpenSSL", "3.2.1"), gefaald]);
const md1 = buildMarkdown();
check("titel noemt álle producten (nginx en OpenSSL)",
  md1.includes("# Kritieke kwetsbaarheden in nginx en OpenSSL"), true);
check("patchregels per eigen product", [md1.includes("CVE-2026-1: patch beschikbaar (nginx 1.31.9)"), md1.includes("CVE-2026-2: patch beschikbaar (OpenSSL 3.2.1)")], [true, true]);
check("mislukte CVE: eigen 'gegevens niet opgehaald'-adviesregel",
  md1.includes("CVE-2026-99998: gegevens konden niet worden opgehaald"), true);
check("mislukte CVE: eigen tekst in Technische Details",
  md1.includes("**CVE-2026-99998:** de gegevens konden niet worden opgehaald"), true);
check("mislukte CVE: 'geen gegevens' in de CVSS-tabel",
  md1.includes("| CVE-2026-99998 | *geen gegevens* | *geen gegevens* |"), true);
check("mislukte CVE valt NIET onder 'controleer bij de leverancier' (geen patch-oordeel)",
  md1.includes("CVE-2026-99998: controleer bij de leverancier"), false);

setAdvisories([cvePatch("CVE-2026-1", "nginx", "1.31.9"), cvePatch("CVE-2026-2", "OpenSSL", "3.2.1"), cvePatch("CVE-2026-3", "Tomcat", null)]);
const md2 = buildMarkdown();
check("drie producten: 'a, b en c' in de titel",
  md2.includes("# Kritieke kwetsbaarheden in nginx, OpenSSL en Tomcat"), true);
check("wél opgehaalde CVE zonder patchversie: wél 'controleer bij de leverancier'",
  md2.includes("CVE-2026-3: controleer bij de leverancier/distributeur"), true);
check("referenties gegroepeerd per CVE bij meerdere CVE's (elke groep met kopje)",
  [md2.includes("**CVE-2026-1:**"), md2.includes("**CVE-2026-2:**"), md2.includes("**CVE-2026-3:**")], [true, true, true]);
// enkele CVE: platte lijst zonder kopje
setAdvisories([cvePatch("CVE-2026-1", "nginx", "1.31.9")]);
const mdSingle = buildMarkdown();
// De technischedetailsregel bevat óók "**CVE-2026-1:**", dus includes is
// hier geen geldige test op "geen referentiekopje": er wordt geteld. Bij
// één CVE mag de notatie maar één keer voorkomen (de technischedetailsregel,
// de referentielijst is plat zonder kopje); bij meerdere CVE's twee keer.
check("referenties plat (geen CVE-kopje) bij één enkele CVE",
  [mdSingle.includes("- https://example.com/CVE-2026-1"),
   (mdSingle.match(/\*\*CVE-2026-1:\*\*/g) || []).length], [true, 1]);
setAdvisories([]); // weer schone lei voor de overige tests

// ---------- 7. mislukt ophalen is geen 'geen patch' ----------
check("kevStatusText: CVE zonder opgehaalde gegevens -> geen misbruikregel",
  kevStatusText({ id: "CVE-2026-99998", _fetchFailed: true }), null);
check("kevStatusText: mislukt gaat vóór zelfs aanwezige KEV-velden (geen schijnzekerheid)",
  kevStatusText({ id: "CVE-X", _fetchFailed: true, cisaExploitAdd: "2026-01-01" }), null);
check("buildMarkdown: mislukte CVE krijgt eigen 'gegevens niet opgehaald'-melding",
  /gegevens konden niet worden opgehaald/.test(src), true);
check("buildMarkdown: 'mislukt'-patchlijn alleen voor wél opgehaalde CVE's",
  /advisories\.filter\(\(c\) => !c\._fetchFailed && !fixedVersion\(c\)\)/.test(src), true);
check("generate: mislukte CVE blijft als stub in de advisory",
  /_fetchFailed: true/.test(src), true);

// ---------- 8. CVE-verwerkingsstatus ----------
check("cveStatus: rejected -> Afgewezen", cveStatus({ vulnStatus: "Rejected" }).label, "Afgewezen");
check("cveStatus: received -> Nog niet geanalyseerd", cveStatus({ _state: "RECEIVED" }).label, "Nog niet geanalyseerd");
check("cveStatus: analyzed -> null", cveStatus({ vulnStatus: "Analyzed" }), null);

// ---------- 9. CVE-invoervalidatie ----------
// NB: een CVE-serienummer is volgens de CVE-specificatie minimaal vier
// cijfers, en parseCveList aanvaardt "CVE-2026-1" (één cijfer) daarom niet.
// De fixtures hieronder gebruiken realistische viercijferige serienummers;
// echte typos zoals "2026-1" blijven juist wél als ongeldig gerapporteerd.
check("discardedCveTokens: typos komen terug, geldige niet",
  discardedCveTokens("CVE-2026-123158\n2026-99999\nCVE2026-1\n"),
  ["2026-99999", "CVE2026-1"]);
check("discardedCveTokens: alles geldig -> leeg", discardedCveTokens("CVE-2026-1001, CVE-2026-1002"), []);

// 9. Punt 5: geen ruis van niet-CVE-woorden, wel geplakte leestekens
// accepteren en duplicaten samenvoegen.
check("cleanCveToken: leestekens aan de rand gaan eraf, hoofdletters erop",
  cleanCveToken("  -CVE-2026-123158.  "), "CVE-2026-123158");
check("parseCveList: geplakt 'CVE-2026-1001.' en lijststreepje '- CVE-2026-1002' worden herkend",
  parseCveList("CVE-2026-1001.\n- CVE-2026-1002"), ["CVE-2026-1001", "CVE-2026-1002"]);
check("parseCveList: duplicaten (ook in andere kas) worden samengevoegd",
  parseCveList("CVE-2026-1001, cve-2026-1001, CVE-2026-1002"), ["CVE-2026-1001", "CVE-2026-1002"]);
check("discardedCveTokens: los woord zonder cijfers ('en') is geen ruis",
  discardedCveTokens("CVE-2026-1001 en CVE-2026-1002"), []);
check("discardedCveTokens: '(OpenSSH)' wordt niet gemeld, '2026-9' wel",
  discardedCveTokens("CVE-2026-1001 (OpenSSH) 2026-9"), ["2026-9"]);
check("discardedCveTokens: 'CVE-2026-1001.' is na opschonen geldig -> geen melding",
  discardedCveTokens("CVE-2026-1001."), []);
check("discardedCveTokens: dubbele typo's worden één keer gemeld",
  discardedCveTokens("2026-1 2026-1"), ["2026-1"]);

// ---------- 9b. referenties: groeperen, plafond en dedupe ----------
const refCve = (id, n) => ({
  id, references: Array.from({ length: n }, (_, i) => ({ url: `https://ref/${id}/${i}` })),
});
check("groepeerReferenties: max 4 per CVE",
  groepeerReferenties([refCve("CVE-A", 6)]).map((g) => g.refs.length), [4]);
check("groepeerReferenties: totaalplafond 10 over meerdere CVE's",
  groepeerReferenties([refCve("CVE-A", 5), refCve("CVE-B", 5), refCve("CVE-C", 5)])
    .reduce((n, g) => n + g.refs.length, 0), 10);
check("groepeerReferenties: dubbele URL's over CVE's blijven één keer over",
  groepeerReferenties([
    { id: "CVE-A", references: [{ url: "https://x/1" }, { url: "https://x/2" }] },
    { id: "CVE-B", references: [{ url: "https://x/2" }, { url: "https://x/3" }] },
  ]).flatMap((g) => g.refs.map((r) => r.url)),
  ["https://x/1", "https://x/2", "https://x/3"]);
check("groepeerReferenties: mislukte CVE overgeslagen",
  groepeerReferenties([refCve("CVE-A", 2), { id: "CVE-B", _fetchFailed: true }]).map((g) => g.id), ["CVE-A"]);

// ---------- 10. NVD-rate-limit ----------
check("nvdStapMs: 3 CVE's zonder sleutel -> 1200", nvdStapMs(3, false), 1200);
check("nvdStapMs: 8 CVE's zonder sleutel -> 6500", nvdStapMs(8, false), 6500);
check("nvdStapMs: met API-sleutel altijd 1200", nvdStapMs(8, true), 1200);

// ---------- 11. fetchJson en de volledige fallback-route ----------
(async () => {
  const origFetch = sandbox.fetch;

  // 429: één poging, geen zinloze retry binnen hetzelfde 30s-venster
  let attempts = 0;
  // URL-filter: alleen de eigen https://x-verzoeken tellen. Een eventueel
  // nog nazwevend achtergrondverzoek (andere URL) mag de teller niet
  // verhogen van de ene poging die deze check afdwingt naar de twee.
  sandbox.fetch = async (u) => { if (String(u) === "https://x") attempts++; return { ok: false, status: 429 }; };
  const r429 = await fetchJson("https://x", { tries: 3, baseDelay: 5 }).then(
    () => ["geen fout", attempts], (e) => [e.message, attempts]
  );
  check("fetchJson 429: één poging + API-sleutelmelding",
    [r429[1], /API-sleutel/.test(r429[0])], [1, true]);

  // 503: retry/backoff blijft intact
  attempts = 0;
  sandbox.fetch = async (u) => { if (String(u) === "https://x") attempts++; return { ok: false, status: 503 }; };
  await fetchJson("https://x", { tries: 3, baseDelay: 5 }).catch(() => {});
  check("fetchJson 503: drie pogingen (retry/backoff intact)", attempts, 3);

  // Nagemaakte CVE JSON 5.x-respons door de volledige fallback-route:
  // publicatiedatum, CWE en product moeten er alle drie uit komen.
  sandbox.fetch = async () => ({
    ok: true,
    json: async () => ({
      dataType: "CVE_RECORD", dataVersion: "5.1",
      cveMetadata: { state: "PUBLISHED", datePublished: "2026-11-05T15:46:26.488Z" },
      containers: {
        cna: {
          descriptions: [{ lang: "en", value: "sshd password bypass" }],
          problemTypes: [{ descriptions: [{ cweId: "CWE-394", description: "CWE-394 Unexpected Status Code or Return Value" }] }],
          affected: [{ vendor: "OpenBSD", product: "OpenSSH", versions: [{ status: "affected", lessThan: "10.6p2", version: "0" }] }],
          metrics: [{ cvssV3_1: { baseScore: 9.3, baseSeverity: "CRITICAL", vectorString: "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" } }],
          references: [{ url: "https://sshhole.com" }],
        },
      },
    }),
  });
  const cna = await fetchCveProgram("CVE-2026-123158");
  check("fallback: publicatiedatum uit cveMetadata.datePublished",
    cna.published, "2026-11-05T15:46:26.488Z");
  check("fallback: CWE uit problemTypes.cweId", extractCwes(cna), ["CWE-394"]);
  check("fallback: product en patchversie uit affected",
    [extractProducts(cna), patchLine(cna, null)],
    [["OpenBSD OpenSSH < 10.6p2"], "CVE-2026-123158: patch beschikbaar (OpenSSH 10.6p2) \u2014 zie referenties."]);

  // ---------- 12. CVE-fetchcache (sessionStorage) ----------
  clearCveCache();
  let nFetch = 0;
  sandbox.fetch = async () => {
    nFetch++;
    return { ok: true, json: async () => ({ vulnerabilities: [{ cve: { id: "CVE-2026-77", descriptions: [{ lang: "en", value: "cached" }] } }] }) };
  };
  await fetchCve("CVE-2026-77");
  const hit = await fetchCve("CVE-2026-77");
  check("cache: tweede keer geen netwerkgebruik, wél _cached-vlag",
    [nFetch, hit._cached, hit.descriptions[0].value], [1, true, "cached"]);
  // vink "Vers ophalen" -> cache overgeslagen, resultaat wél opnieuw gecachet
  cachedStub("#no-cache").checked = true;
  await fetchCve("CVE-2026-77");
  check("cache: 'Vers ophalen' slaat de cache over", nFetch, 2);
  cachedStub("#no-cache").checked = false;
  const hit2 = await fetchCve("CVE-2026-77");
  check("cache: na 'Vers ophalen' weer een hit (geen extra netwerkgebruik)", [nFetch, hit2._cached], [2, true]);

  sandbox.fetch = origFetch;

  // ---------- 12b. alleen netwerkcalls worden vertraagd (fix 2) ----------
  // CVE-2026-77 staat in de cache (sectie 12); de vijf andere niet.
  const zes = ["CVE-2026-77", "CVE-2026-81", "CVE-2026-82", "CVE-2026-83", "CVE-2026-84", "CVE-2026-85"];
  const metCache = netIndexen(zes, true);
  check("cache: cachede CVE krijgt geen vertraging-index",
    [metCache.idx.has("CVE-2026-77"), metCache.count], [false, 5]);
  check("cache: netwerk-CVE's krijgen oplopende index (0, 1, ...)",
    [metCache.idx.get("CVE-2026-81"), metCache.idx.get("CVE-2026-85")], [0, 4]);
  // De stapgrootte schaalt mee met het aantal NETWERKophaalacties: één van
  // de zes is cached, dus nog vijf netwerkcalls en géén opschaling naar 6,5 s
  // (oud gedrag: zes CVE's in totaal zou wél opschalen).
  check("stapgrootte op netwerkcalls: 5 van 6 netwerk blijft 1,2 s",
    nvdStapMs(metCache.count, false), 1200);
  const zonderCache = netIndexen(zes, false); // vink "Vers ophalen"
  check("'Vers ophalen': alles telt mee, wél opschaling",
    [zonderCache.count, nvdStapMs(zonderCache.count, false)], [6, 6500]);

  // ---------- 13. geschiedenis van advisory's ----------
  setAdvisories([cvePatch("CVE-2026-1", "nginx", "1.31.9")]);
  setLastMarkdown("tekst-1");
  historyPush();
  historyPush(); // zelfde markdown -> geen dubbele regel
  check("geschiedenis: dubbele regels voorkomen",
    [historyRead().length, historyRead()[0].markdown], [1, "tekst-1"]);
  setLastMarkdown("tekst-2");
  historyPush();
  check("geschiedenis: nieuwste regel bovenaan", [historyRead().length, historyRead()[0].markdown], [2, "tekst-2"]);
  for (let i = 3; i <= 12; i++) { setLastMarkdown(`tekst-${i}`); historyPush(); }
  check("geschiedenis: plafond van 8 regels", historyRead().length, 8);
  const histKey = historyRead()[0].key;
  setAdvisories([]);
  historyRestore(histKey);
  check("geschiedenis: herstel zet advisory-gegevens terug", getAdvisories().map((c) => c.id), ["CVE-2026-1"]);

  // ---------- 13b. geschiedenis: veldsnapshots en wissen (fix 2) ----------
  // Veldwaarden vastleggen bij het pushen: de briefvelden van dat moment,
  // zonder browservoorkeuren (API-sleutel) en zonder het CVE-veld.
  cachedStub("#advisory-title").value = "Testtitel";
  cachedStub("#advisory-ref").value = "ADV-2026-001";
  cachedStub("#nvd-apikey").value = "geheim";
  cachedStub("#cve-input").value = "CVE-2026-1";
  setAdvisories([cvePatch("CVE-2026-1", "nginx", "1.31.9")]);
  setLastMarkdown("tekst-velden");
  historyPush();
  const velden = historyRead()[0].fields;
  check("geschiedenis: veldsnapshot bevat de briefvelden van dat moment",
    [velden["advisory-title"], velden["advisory-ref"], velden["prioriteit-select"]],
    ["Testtitel", "ADV-2026-001", "auto"]);
  check("geschiedenis: API-sleutel en CVE-veld zitten níet in het snapshot",
    ["nvd-apikey" in velden, "cve-input" in velden], [false, false]);
  // Herstellen zet ook de velden terug (en schrijft ze naar het veldgeheugen)
  cachedStub("#advisory-title").value = "Wijziging erna";
  cachedStub("#advisory-ref").value = "ADV-9";
  historyRestore(historyRead()[0].key);
  check("geschiedenis: herstel zet de briefvelden terug",
    [cachedStub("#advisory-title").value, cachedStub("#advisory-ref").value],
    ["Testtitel", "ADV-2026-001"]);
  check("geschiedenis: herstel schrijft veldwaarden ook naar het veldgeheugen",
    JSON.parse(sandbox.localStorage.getItem("advisory-writer:velden-v1"))["advisory-title"], "Testtitel");
  // Oud item zonder veldsnapshot: alleen de tekst herstellen, geen crash
  const lijst = historyRead();
  lijst.unshift({ key: "oud-item", label: "01-01", cves: ["CVE-2026-1"], markdown: "m", advisories: [cvePatch("CVE-2026-1", "nginx", "1.31.9")] });
  sandbox.localStorage.setItem("advisory-writer:history-v1", JSON.stringify(lijst));
  cachedStub("#advisory-title").value = "Nog nieuw";
  historyRestore("oud-item");
  check("geschiedenis: oud item zonder snapshot crasht niet en laat velden intact",
    [cachedStub("#advisory-title").value, getAdvisories().map((c) => c.id)], ["Nog nieuw", ["CVE-2026-1"]]);
  // Eén item wissen en de hele lijst legen
  const voorWissen = historyRead().length;
  historyDelete("oud-item");
  check("geschiedenis: Wis item verwijdert alleen het gekozen item",
    [historyRead().length, historyRead().some((e) => e.key === "oud-item")], [voorWissen - 1, false]);
  historyClearAll();
  check("geschiedenis: Wis alles legt de lijst leeg", historyRead().length, 0);
  // Gemaakte dropdownkeuze blijft staan als er intussen een nieuw item bij komt
  setLastMarkdown("tekst-a");
  historyPush();
  const keyA = historyRead()[0].key;
  cachedStub("#history-select").value = keyA;
  setLastMarkdown("tekst-b");
  historyPush(); // nieuwe regel -> dropdown wordt herbouwd
  check("geschiedenis: gemaakte keuze blijft staan na een nieuwe push",
    cachedStub("#history-select").value, keyA);
  setAdvisories([]);

  // ---------- 14. voortgangsmelding en herkenningshint (fix 3 en 4) ----------
  // Alle setStatus-schrijfsignalen bijhouden: de statushost is een stub,
  // dus de textContent wordt als getter/setter opnieuw gedefinieerd.
  const statusWrites = [];
  Object.defineProperty(cachedStub("#status"), "textContent", {
    get: () => (statusWrites.length ? statusWrites[statusWrites.length - 1] : ""),
    set: (v) => { statusWrites.push(v); },
    configurable: true,
  });

  // Fix 4: bij een volledig ongeldige lijst toont de vroege return meteen
  // wát er niet werd herkend, in plaats van alleen de standaardtekst.
  cachedStub("#cve-input").value = "2026-99999";
  await generate();
  const hintMsg = statusWrites[statusWrites.length - 1];
  check("hint: alles ongeldig -> standaardtekst èn herkenningsinfo",
    [hintMsg.includes("Voer minstens één geldig CVE-nummer in"), hintMsg.includes("Niet als CVE herkend: 2026-99999")],
    [true, true]);

  // Fix 3: echte voortgang. Twee CVE's, trage NVD-respons: er moet één
  // startmelding zijn plus één update per VOLTOOIDE ophaalactie (oud gedrag:
  // alle meldingen draaiden synchroon op t=0, alleen het laatste nummer was
  // zichtbaar). Stap van 1,2 s maakt deze test merkbaar maar niet traag.
  let nvdCalls = 0;
  sandbox.fetch = async (url) => {
    if (url.includes("services.nvd")) {
      nvdCalls++;
      const id = decodeURIComponent(url.split("cveId=")[1]);
      return { ok: true, json: async () => ({ vulnerabilities: [{ cve: { id, descriptions: [{ lang: "en", value: "d" }] } }] }) };
    }
    return { ok: true, text: async () => "", json: async () => ({}) };
  };
  clearCveCache();
  statusWrites.length = 0;
  // Let op: viercijferige serienummers — de valideer-regel CVE-\d{4}-\d{4,}
  // wijst driedigits-IDs af, en generate() keert dan vroeg terug vóórdat er
  // ook maar één voortgangsmelding is geschreven.
  cachedStub("#cve-input").value = "CVE-2026-2001, CVE-2026-2002";
  await generate();
  // Let op: loadDisclaimer() schrijft ook een statusmelding vóór de startmelding,
  // dus zoeken in plaats van index 0.
  check("voortgang: startmelding met aantal op te halen",
    statusWrites.find((w) => w.startsWith("Ophalen van")), "Ophalen van 2 CVE's (2 op te halen)...");
  check("voortgang: één update per voltooide CVE",
    statusWrites.filter((w) => /voltooid/.test(w)).map((w) => w.match(/(\d)\/2 voltooid/)[1]), ["1", "2"]);
  check("voortgang: eindmelding 'Klaar' sluit af",
    statusWrites[statusWrites.length - 1].startsWith("Klaar. 2 CVE(s) verwerkt"), true);

  // Tweede run: alles staat in de cache — de startmelding zegt dat expliciet
  // en er gaan geen NVD-calls meer weg (cache-bewuste melding, fix 1+3).
  statusWrites.length = 0;
  const nvdCallsVooraf = nvdCalls;
  await generate();
  check("voortgang: volledig cachede run meldt de cache-verdeling",
    statusWrites.find((w) => w.startsWith("Ophalen van")), "Ophalen van 2 CVE's (0 op te halen, 2 uit cache)...");
  check("voortgang: cachede run doet géén nieuwe NVD-calls",
    nvdCalls, nvdCallsVooraf);

  // Punt 4 schone run: try/finally rond de ophaal- en renderfase. Een
  // onverwachte fout (hier afgedwongen via een gooiende createElement in
  // renderCveCards) mocht de genereerknop niet eeuwig op disabled laten
  // staan, en de statusbalk moest van "Ophalen..." naar een foutmelding.
  {
    const origCreate = sandbox.document.createElement;
    sandbox.document.createElement = () => { throw new Error("renderfout"); };
    // Het afgedwongen foutpad logt zichzelf in de app via console.error; die
    // run-ruis is bewezen gedrag en geen foutval, dus de vm-console gaat
    // tijdelijk op stil (de tests zelf loggen via de buitenste console).
    const origConsole14 = sandbox.console;
    sandbox.console = { log: noop, warn: noop, error: noop };
    cachedStub("#cve-input").value = "CVE-2026-3001"; // vier cijfers, idem
    let gegooid = false;
    try { await generate(); } catch { gegooid = true; } // mag niet meer doorlekken
    sandbox.console = origConsole14;
    check("try/finally: onverwachte fout herstelt genereerknop en meldt netjes",
      [gegooid, cachedStub("#fetch-btn").disabled,
       statusWrites[statusWrites.length - 1].includes("onverwachte fout")],
      [false, false, true]);
    sandbox.document.createElement = origCreate;
  }

  // --- 15. A11y en API-sleutelveld (fixen 6 en 7) -------------------------
  // Statische checks: de vaste aria-attributen in index.html en app.js.
  const htmlSrc = fs.readFileSync(path.join(__dirname, "..", "index.html"), "utf8");
  const cssSrc = fs.readFileSync(path.join(__dirname, "..", "style.css"), "utf8");
  check("a11y: statusbalk is aria-live-region",
    /<p id="status"[^>]+aria-live="polite"/.test(htmlSrc), true);
  check("a11y: tabs starten met aria-pressed",
    /id="tab-preview"[^>]+aria-pressed="true"/.test(htmlSrc) &&
    /id="tab-raw"[^>]+aria-pressed="false"/.test(htmlSrc), true);
  check("a11y: raw-textarea heeft eigen aria-label",
    /id="advisory-raw"[^>]+aria-label=/.test(htmlSrc), true);
  check("a11y: API-sleutelveld is wachtwoordveld (fix 7)",
    /type="password" id="nvd-apikey" autocomplete="off"/.test(htmlSrc), true);
  // Regressie van fix 7: het wachtwoordveld moet meedraaien in dezelfde
  // veldselectoren als de andere inputs, anders verliest het zijn donkere
  // thema-stijl en rendert het als wit browser-standaardveld.
  check("stijl: wachtwoordveld valt onder de gewone veldstijl (fix 7-regressie)",
    /input\[type="text"\],\s*input\[type="password"\],\s*textarea,\s*select\s*\{/.test(cssSrc), true);
  check("a11y: beschrijving-veld op de kaart heeft aria-label",
    /textarea class="desc-edit"[^>]+aria-label=/.test(src), true);

  // Gedrag: een tabklik moet aria-pressed meebewegen (niet alleen de class).
  cachedStub("#tab-raw").listeners.click.forEach((f) => f());
  check("a11y: klik Markdown-tab zet aria-pressed om",
    [cachedStub("#tab-raw").attrs["aria-pressed"], cachedStub("#tab-preview").attrs["aria-pressed"]], ["true", "false"]);
  cachedStub("#tab-preview").listeners.click.forEach((f) => f());
  check("a11y: klik Rendered-tab herstelt aria-pressed",
    [cachedStub("#tab-raw").attrs["aria-pressed"], cachedStub("#tab-preview").attrs["aria-pressed"]], ["false", "true"]);

  // --- 16. mdToHtml: de mini-renderer (was het enige ongeteste onderdeel) --
  check("mdToHtml: kopniveaus h1 t/m h4",
    [mdToHtml("# A").includes("<h1>A</h1>"), mdToHtml("## B").includes("<h2>B</h2>"),
     mdToHtml("#### D").includes("<h4>D</h4>")], [true, true, true]);
  check("mdToHtml: ongenummerde lijst",
    mdToHtml("- a\n- b"), "<ul>\n<li>a</li>\n<li>b</li>\n</ul>");
  check("mdToHtml: tabel met kopregel, separatorrij overgeslagen",
    mdToHtml("| A | B |\n| --- | --- |\n| 1 | 2 |\n\nx")
      .includes("<table>\n<tr><th>A</th><th>B</th></tr>\n<tr><td>1</td><td>2</td></tr>\n</table>"), true);
  check("mdToHtml: inline-opmaak vet, schuin, code en koppeling",
    mdToHtml("**vet** *schuin* `code` [klik](https://x.nl/a)"),
    "<p><strong>vet</strong> <em>schuin</em> <code>code</code> <a href=\"https://x.nl/a\" target=\"_blank\" rel=\"noopener\">klik</a></p>");
  check("mdToHtml: kale URL wordt klikbaar (autolink)",
    mdToHtml("Zie https://example.com/a voor meer").includes('href="https://example.com/a"'), true);
  // Autolink mocht de afsluitende punt (of het sluitende haakje) van de zin
  // niet meer in de href slepen: de punctuatie valt buiten de ankertag.
  check("mdToHtml: afsluitende punt blijft buiten de link (autolink)",
    mdToHtml("Zie https://example.com/a.").includes(">https://example.com/a</a>."), true);
  check("mdToHtml: sluitende haak na de URL blijft buiten de link",
    mdToHtml("(bron: https://example.com/a)").includes(">https://example.com/a</a>)"), true);
  check("mdToHtml: <br> in celtekst blijft een echte regelbreking (CVSS-tabel)",
    mdToHtml("| A |\n| --- |\n| **9.8 (Kritiek)** <br>Vector: `V` |").includes("<br>Vector: <code>V</code>"), true);
  check("mdToHtml: HTML in brontekst wordt escaped (geen ruwe tags, XSS-veilig)",
    [mdToHtml("<script>alert(1)</script>").includes("&lt;script&gt;"),
     mdToHtml("<b>x</b>").includes("<b>")], [true, false]);
  check("mdToHtml: codeblok met triple backticks",
    [mdToHtml("```\nvector\n```").includes("<pre><code>"),
     mdToHtml("```\nvector\n```").includes("</code></pre>")], [true, true]);
  check("mdToHtml: blockquote, horizontale lijn en alinea-samenvoeging",
    [mdToHtml("> citaat").includes("<blockquote>citaat</blockquote>"),
     mdToHtml("---").includes("<hr>"),
     mdToHtml("regel een\nregel twee").includes("<p>regel een regel twee</p>")], [true, true, true]);

  // --- 17. print-PDF: paginanummers, lopende kop en favicon (fix 9) --------
  check("pdf: paginanummers via @page-margebox (counter(page) / counter(pages))",
    /@bottom-center\s*\{[^}]*counter\(page\)[^}]*counter\(pages\)/.test(src), true);
  check("pdf: lopende kop op elke pagina met advisorynummer/titel",
    /@top-center \{ content: "\$\{koptekst\}"/.test(src), true);
  // De kopstriping en -afkapping leven in één gedeelde helper (pdfKoptekst),
  // zodat de PDF-routes nooit uit elkaar kunnen lopen. De teller is drie: de
  // helper wordt in jsPDF-tekstexport, printdialoog én html2canvas-raster
  // aangeroepen (de raster-route kwam later bij deze check; de oude eis van
  // twee liet die route buiten beschouwing).
  check("pdf: koptekst-striping via de gedeelde pdfKoptekst-helper (alle drie de routes)",
    /\["'\\\\<>\\n\\r\]\/g/.test(src) && /function pdfKoptekst\(\)/.test(src) &&
    (src.match(/const koptekst = pdfKoptekst\(\);/g) || []).length === 3, true);
  // Opruimen van het print-iframe luistert naar afterprint in plaats van een
  // vaste timeout: print() is in Firefox/Safari niet blokkerend, dus bij een
  // vaste 1 s kon het iframe tijdens de open dialoog verdwijnen.
  check("pdf: iframe-opruiming via afterprint-event (geen vaste 1 s meer)",
    /addEventListener\("afterprint", cleanup\)/.test(src) && !/setTimeout\(\(\) => iframe\.remove\(\), 1000\)/.test(src), true);
  check("pdf: opruimen is dubbelingsbestendig en heeft een vangnet-timeout",
    [/if \(verwijderd\) return;/.test(src), /setTimeout\(cleanup, 120000\)/.test(src)], [true, true]);
  check("favicon: inline SVG-favicon in index.html (geen extra verzoek)",
    /rel="icon"[^>]*data:image\/svg\+xml/.test(htmlSrc), true);

  // --- 18. cosmetica uit de schone run (punten 2, 3 en 4) ----------------
  // Punt 2: een geschiedenisitem zónder CVE-gegevens moest de kaarten van
  // de vorige advisory van het scherm halen (oud gedrag: ze bleven staan).
  const lijstLeeg = historyRead();
  lijstLeeg.unshift({ key: "leeg-item", label: "02-02", cves: [], markdown: "m-leeg", fields: {}, advisories: [] });
  sandbox.localStorage.setItem("advisory-writer:history-v1", JSON.stringify(lijstLeeg));
  cachedStub("#cve-cards").innerHTML = "oude kaarten";
  cachedStub("#data-panel").classLog.length = 0;
  historyRestore("leeg-item");
  check("geschiedenis: herstel zonder CVE-gegevens wist oude kaarten en verbergt het paneel",
    [cachedStub("#cve-cards").innerHTML,
     cachedStub("#data-panel").classLog.some(([op, c]) => op === "add" && c === "hidden")],
    ["", true]);
  // Punt 3: de _cached-vlag zegt buiten de genereerbeurt niets en hoeft niet
  // mee in de opslag; _descEdit (handmatige beschrijving) wél.
  setAdvisories([{ id: "CVE-2026-1", _descEdit: "handmatige tekst", _cached: true }]);
  setLastMarkdown("opslag-check");
  historyPush();
  const opgeslagen = historyRead()[0].advisories[0];
  check("opslag: _cached-vlag blijft buiten de opslag-JSON",
    Object.prototype.hasOwnProperty.call(opgeslagen, "_cached"), false);
  check("opslag: _descEdit blijft wél bewaard (handmatige beschrijving)",
    opgeslagen._descEdit, "handmatige tekst");
  // Punt 4: het cache-toggle-label heeft geen inline style meer in de HTML,
  // de halfvette tekst komt nu uit een CSS-klasse.
  check("cache-toggle: inline style uit HTML, halfvet nu via .cache-toggle .hint in CSS",
    [!htmlSrc.includes("style=\"font-weight:600\""), /\.cache-toggle \.hint\s*\{[^}]*font-weight:\s*600/.test(cssSrc)],
    [true, true]);

  // --- 19. EPSS: exploitkans van FIRST (uitbreidingsronde) ----------------
  // De live-API (geverifieerd 22-11-2026) levert een array van objecten:
  // data: [{ cve, epss, percentile, date }]. De objectvorm uit sommige
  // documentatie blijft als tweede tak ondersteund.
  check("EPSS: array-respons (live API-vorm) correct omgezet",
    epssUitRespons({ data: [
      { cve: "CVE-2026-1", epss: "0.97", percentile: "0.995", date: "2026-11-21" },
      { cve: "CVE-2026-2", epss: "0.01", date: "2026-11-21" }, // zonder percentiel
    ] }),
    { "CVE-2026-1": { score: 0.97, percentile: 0.995, date: "2026-11-21" },
      "CVE-2026-2": { score: 0.01, percentile: null, date: "2026-11-21" } });
  check("EPSS: object-respons (documentatievorm) werkt ook",
    epssUitRespons({ data: { "CVE-2026-1": "0.97" }, percentile: { "CVE-2026-1": "0.995" } }),
    { "CVE-2026-1": { score: 0.97, percentile: 0.995, date: null } });
  check("EPSS: niet-numerieke score overgeslagen, lege respons netjes leeg",
    [Object.keys(epssUitRespons({ data: [{ cve: "CVE-1", epss: "geen getal" }] })).length,
     Object.keys(epssUitRespons({})).length], [0, 0]);

  // Schone start: cache en een eventuele storestatus uit eerdere secties
  // terugzetten, zodat de teller hier vanaf nul begint.
  clearEpssCache();
  let epssCalls = 0;
  let epssUrl = "";
  const origFetch19 = sandbox.fetch;
  sandbox.fetch = async (url) => {
    if (String(url).includes("api.first.org")) {
      epssCalls++;
      epssUrl = String(url);
      return { ok: true, json: async () => ({ data: [
        { cve: "CVE-2026-1", epss: "0.97", percentile: "0.995", date: "2026-11-21" },
        { cve: "CVE-2026-2", epss: "0.01", date: "2026-11-21" },
        { cve: "CVE-2026-5", epss: "0.5", percentile: "0.9" }, // zonder datum
      ] }) };
    }
    throw new Error("geen netwerk in test");
  };
  await laadEpss(["CVE-2026-1", "CVE-2026-2"]);
  await laadEpss(["CVE-2026-1"]); // beide bekend: geen nieuw verzoek nodig
  check("EPSS: één gebundeld verzoek (comma-gescheiden), daarna uit de 24-u-cache",
    [epssCalls, epssUrl.includes("cve=CVE-2026-1,CVE-2026-2")], [1, true]);
  check("EPSS: cache staat in sessionStorage (overleeft een herladen)",
    JSON.parse(sandbox.sessionStorage.getItem("advisory-writer:epss-v1")).scores["CVE-2026-1"].score, 0.97);
  await laadEpss(["CVE-2026-3"]); // niet in het model: komt als { score: null } in de cache
  await laadEpss(["CVE-2026-3"]); // bekend-onbekend: géén tweede verzoek
  check("EPSS: 'niet in model' wordt onthouden en niet opnieuw opgevraagd", epssCalls, 2);
  check("EPSS: regeltekst met Nederlandse komma en percentiel (en zonder percentiel)",
    [epssRegelTekst({ id: "CVE-2026-1" }).includes("EPSS-inschatting: 0,97 (99,5e percentiel)"),
     epssRegelTekst({ id: "CVE-2026-2" }).includes("EPSS-inschatting: 0,01 \u2014")], [true, true]);
  check("EPSS: onbekend of niet-in-model CVE levert geen regel op",
    [epssRegelTekst({ id: "CVE-2026-3" }), epssRegelTekst({ id: "CVE-2026-4" })], [null, null]);
  // De modeldatum mee tonen: de cache is maximaal 24 uur oud, dus de getoonde
  // run is nagenoeg altijd de meest recente; zonder datum in de respons valt
  // het stukje weg (exacte tekstcheck, dus zonder lokaal-afhankelijke datum).
  await laadEpss(["CVE-2026-5"]);
  check("EPSS: modeldatum uit de respons staat in de regel",
    epssRegelTekst({ id: "CVE-2026-1" }).includes("(FIRST EPSS, model "), true);
  check("EPSS: respons zonder modeldatum levert geen losse modelvermelding",
    epssRegelTekst({ id: "CVE-2026-5" }),
    "EPSS-inschatting: 0,5 (90e percentiel) \u2014 kans op misbruik in de komende 30 dagen (FIRST EPSS).");
  check("EPSS: mislukt CVE doet geen kansclaim",
    epssRegelTekst({ id: "CVE-2026-1", _fetchFailed: true }), null);
  setAdvisories([cvePatch("CVE-2026-1", "nginx", "1.31.9")]);
  check("buildMarkdown: EPSS-regel in Technische Details",
    buildMarkdown().includes("EPSS-inschatting: 0,97 (99,5e percentiel)"), true);
  check("EPSS: badge op de CVE-kaart met drempelkleuren (broncode-check)",
    /class="badge \$\{epss\.score >= 0\.5 \? "high"/.test(src), true);
  check("EPSS: statusmelding bij niet beschikbaar (broncode-check)",
    /EPSS niet beschikbaar \(api\.first\.org\)/.test(src), true);
  clearEpssCache();
  sandbox.fetch = async () => { throw new Error("geen netwerk in test"); };
  await laadEpss(["CVE-2026-1"]); // faalt: epssFailed aan, geen tweede poging meer
  await laadEpss(["CVE-2026-1"]);
  check("EPSS: bij een storing valt de regel weg en wordt niet opnieuw geprobeerd",
    epssInfo({ id: "CVE-2026-1" }), null);
  sandbox.fetch = origFetch19;

  // --- 20. Distributeurtrackers (uitbreidingsronde) ---------------------
  // URL-vormen live geverifieerd 22-11-2026: Debian en Ubuntu houden het
  // CVE-nummer zoals het is, Red Hat gebruikt kleine letters, SUSE vraagt
  // om een afsluitende slash. Een distributeur die een CVE niet volgt, geeft
  // zelf een 404: dat is het antwoord van de tracker, geen kapotte link.
  check("distributeurlinks: zes controlelinks in de geverifieerde URL-vormen",
    distributeurRegels([{ id: "CVE-2026-123158" }]),
    ["- CVE-2026-123158: Debian https://security-tracker.debian.org/tracker/CVE-2026-123158 \u00b7 Ubuntu https://ubuntu.com/security/CVE-2026-123158 \u00b7 Red Hat https://access.redhat.com/security/cve/cve-2026-123158 \u00b7 SUSE https://www.suse.com/security/cve/CVE-2026-123158/ \u00b7 Fedora https://cve.fedoraproject.org/#/cve/CVE-2026-123158 \u00b7 Amazon Linux https://alas.aws.amazon.com/cve/html/CVE-2026-123158.html"]);
  // De twee nieuwsten van de uitbreidingsronde apart bewaakt: juist hun
  // vormen wijken het meest af van de vier bestaande (hash-route van de
  // Fedora-CVE-website resp. .html-achtervoegsel bij ALAS). In de grote
  // streng hierboven zou een typefout anders makkelijk meekomen.
  check("distributeurlinks: Fedora-hash-route en Amazon-.html-vorm in elke regel",
    [distributeurRegels([{ id: "CVE-1" }])[0].includes("https://cve.fedoraproject.org/#/cve/CVE-1"),
     distributeurRegels([{ id: "CVE-1" }])[0].includes("https://alas.aws.amazon.com/cve/html/CVE-1.html")],
    [true, true]);
  check("distributeurlinks: mislukte CVE overgeslagen, maximum van drie regels",
    distributeurRegels([{ id: "CVE-1" }, { id: "CVE-F", _fetchFailed: true },
      { id: "CVE-2" }, { id: "CVE-3" }, { id: "CVE-4" }]).map((r) => r.split(":")[0]),
    ["- CVE-1", "- CVE-2", "- CVE-3"]);
  // advisories staat nog op het nginx-CVE uit sectie 19: het blok moet mee.
  check("buildMarkdown: distributeurtrackers-blok na de referenties",
    [buildMarkdown().includes("**Distributeurtrackers (controleer de pakketstatus per distributie):**"),
     buildMarkdown().includes("https://www.suse.com/security/cve/CVE-2026-1/")], [true, true]);
  setAdvisories([{ id: "CVE-9", _fetchFailed: true }]);
  check("distributeurlinks: blok vervalt bij uitsluitend mislukte CVE's",
    buildMarkdown().includes("Distributeurtrackers"), false);
  setAdvisories([]);

  // --- 21. jsPDF: PDF-download met printdialoog als terugval ---------------
  // pdfRegels is de pure converter markdown -> regels met rol (h1 t/m h4,
  // bul, tabel, tekst); jsPDF zelf heeft in de testomgeving geen window en
  // drukt dus niets, maar de conversie en de routeknop zijn volledig testbaar.
  check("pdfRegels: kop, bul, tabel en koppeling kaalgemaakt, scheidsrij overgeslagen",
    pdfRegels("# Titel\n\n- **vet** item\n| A | B |\n| --- | --- |\n| 1 | [klik](https://x) |\n"),
    [
      { tekst: "Titel", stijl: "h1" },
      { tekst: "vet item", stijl: "bul" },
      { tekst: "A   |   B", stijl: "tabel" },
      { tekst: "1   |   klik (https://x)", stijl: "tabel" },
    ]);
  check("pdfRegels: inline-opmaak kaal, hr overgeslagen, blockquote als tekst",
    [pdfRegels("**dik** tekst en `code`")[0],
     pdfRegels("> citaat\n---").map((r) => r.tekst)],
    [{ tekst: "dik tekst en code", stijl: "tekst" }, ["citaat"]]);
  // Routeknop: jsPDF alleen als de CDN-bibliotheek er is én het vink uit staat.
  check("pdfRoute: zonder geladen jsPDF altijd de printdialoog",
    pdfRoute(), "printen");
  sandbox.window = { jspdf: { jsPDF: class {} } };
  check("pdfRoute: jsPDF geladen -> echte PDF-download",
    pdfRoute(), "jspdf");
  cachedStub("#pdf-print").checked = true;
  check("pdfRoute: vink 'PDF via printdialoog' heeft voorrang",
    pdfRoute(), "printen");
  delete sandbox.window;
  cachedStub("#pdf-print").checked = false;
  check("jsPDF: CDN-script in index.html vóór app.js en vink in de knoppenrij",
    [htmlSrc.includes("jspdf.umd.min.js") &&
     htmlSrc.indexOf("jspdf.umd.min.js") < htmlSrc.indexOf('src="app.js"'),
     /id="pdf-print"/.test(htmlSrc) && htmlSrc.includes("PDF via printdialoog")],
    [true, true]);
  // Startgedrag en toeleveringsketen: de CDN mag de app niet kunnen blokkeren
  // en de script is gepind. async is veilig omdat pdfRoute() pas op klikmoment
  // naar window.jspdf kijkt; zonder async wacht app.js op de CDN en is een
  // trage of geblokkeerde CDN een lege, onbedienbare pagina.
  const jspdfTag = htmlSrc.match(/<script[^>]*jspdf[^>]*>/)[0];
  check("jsPDF: CDN-script is async geladen (app wacht er niet op)",
    /\basync\b/.test(jspdfTag), true);
  check("jsPDF: CDN-script is SRI-gepind (integrity sha512 + crossorigin)",
    [/integrity="sha512-[A-Za-z0-9+/=]{60,}"/.test(jspdfTag),
     /crossorigin="anonymous"/.test(jspdfTag)], [true, true]);
  check("jsPDF: export kiest de route en valt terug op de printdialoog",
    [/pdfRoute\(\) === "jspdf"/.test(src) && /exportPdfJsPdf\(\)/.test(src) &&
     /exportPdfPrinten\(\)/.test(src),
     /jsPDF-export mislukt; printdialoog als terugval/.test(src)],
    [true, true]);
  // De voorkeur is een browservoorkeur: hij wordt onthouden (MEMORIZED_FIELDS),
  // maar reist niet mee in het geschiedenis-snapshot (net als de API-sleutel).
  check("geschiedenis: 'PDF via printdialoog' blijft buiten het veldsnapshot",
    Object.prototype.hasOwnProperty.call(captureFields(), "pdf-print"), false);

  // --- 22. pdfKoptekst en de layoutloop van exportPdfJsPdf ----------------
  // De helper is puur en dus direct testbaar; de layoutloop draait tegen een
  // namaak-jsPDF die elke doc-aanroep noteert (punt 3 van de schone run: de
  // loop zelf draaide nog nooit in de tests). De namaak wrapt niet (één regel
  // per tekst) en telt tekenposities per pagina mee.
  cachedStub("#advisory-ref").value = "";
  cachedStub("#advisory-title").value = ""; // restwaarde uit eerdere secties wissen
  check("pdfKoptekst: zonder invulling de kaale standaard 'advisory'", pdfKoptekst(), "advisory");
  cachedStub("#advisory-ref").value = "ADV-<1>";
  check("pdfKoptekst: striping van \" ' \\ < > (CSS-content-string en PDF-kop)", pdfKoptekst(), "ADV-1");
  cachedStub("#advisory-ref").value = "A".repeat(120);
  const kopLang = pdfKoptekst();
  check("pdfKoptekst: afgekapt op 90 tekens + ellipsis (91 totaal, past binnen 174 mm)",
    [kopLang.length, kopLang.endsWith("\u2026")], [91, true]);
  cachedStub("#advisory-ref").value = "";

  let laatsteDoc = null;
  class FakeJsPdf {
    constructor() { this.pages = [[]]; this._i = 0; laatsteDoc = this; }
    setFont() {}
    setFontSize() {}
    setTextColor() {}
    splitTextToSize(t) { return [t]; } // één regel per tekst: voorspelbaar y-drukwerk
    text(t, x, y) { this.pages[this._i].push({ t, x, y }); }
    addPage() { this.pages.push([]); this._i = this.pages.length - 1; }
    getNumberOfPages() { return this.pages.length; }
    setPage(i) { this._i = i - 1; }
    save(naam) { this._naam = naam; }
  }
  sandbox.window = { jspdf: { jsPDF: FakeJsPdf } };
  cachedStub("#advisory-ref").value = "ADV-2026-001";
  // 44 bullettes (elk 5,6 mm: 4,5 lijn + 1,1 ruimte) laten de y op 266,4 mm
  // eindigen: de kop (11,5 pt) past dan zélf nog nét op pagina 1 (tot 277 mm),
  // maar de eerste regel ervonder niet meer. Zonder weeskopbescherming zou
  // de kop dan als eenzame laatste regel onder pagina 1 staan; met de
  // bescherming schuift hij met de tekst mee naar pagina 2.
  const buls = Array.from({ length: 44 }, (_, i) => `- bol ${i + 1}`).join("\n");
  setLastMarkdown(`${buls}\n\n## Kop twee\n\nna de kop\n`);
  exportPdfJsPdf();
  const pg = laatsteDoc.pages;
  check("jsPDF-loop: paginering bij overloop (44 bul + kop + tekst over twee pagina's)",
    pg.length, 2);
  check("jsPDF-loop: lopende kop en paginanummer op elke pagina",
    pg.map((p) => [p.some((d) => d.t === "ADV-2026-001"),
      p.some((d) => d.t === "1 / 2" || d.t === "2 / 2")]),
    [[true, true], [true, true]]);
  check("jsPDF-loop: weeskopbescherming — de kop staat volledig op pagina 2, niet eenzaam onderaan pagina 1",
    [pg[0].some((d) => d.t === "Kop twee"), pg[1].some((d) => d.t === "Kop twee")], [false, true]);
  check("jsPDF-loop: bestandsnaam volgt het advisorynummer", laatsteDoc._naam, "ADV-2026-001.pdf");
  delete sandbox.window;
  cachedStub("#advisory-ref").value = "";

  // --- 23. Geschiedenis: eigen naam per regel (uitbreidingsronde) ----------
  // De dropdown liet alleen een tijdstempel + advisorynummer zien; een eigen
  // naam ("Testomgeving maart") maakt terugvinden makkelijker. De notatie is
  // een aparte functie (geschiedenisOptieTekst), want de DOM-stub bewaart
  // geen kindopties en kan de dropdown dus niet uitlezen.
  setAdvisories([cvePatch("CVE-2026-1", "nginx", "1.31.9")]);
  setLastMarkdown("label-tekst");
  historyPush();
  const labelItem = historyRead()[0];
  check("eigen naam: nieuwe regels zijn standaard naamloos, notatie blijft oud",
    [labelItem.naam, geschiedenisOptieTekst(labelItem)],
    [undefined, `${labelItem.label} \u2014 CVE-2026-1`]);
  check("eigen naam: notatie zet de naam vóór de tijdstempel (tijd blijft staan)",
    geschiedenisOptieTekst({ label: "22 nov 13:34", cves: ["CVE-1"], naam: "Testomgeving maart" }),
    "Testomgeving maart \u00b7 22 nov 13:34 \u2014 CVE-1");
  check("eigen naam: handmatige markering blijft achter de tijdstempel",
    geschiedenisOptieTekst({ label: "L", cves: ["CVE-1"], naam: "X", manual: true }),
    "X \u00b7 L \u2014 CVE-1 (handmatig)");
  const hernoemd = historyRename(labelItem.key, "  Testomgeving   maart  ");
  check("eigen naam: spaties gecolapst en in de geschiedenis-JSON gezet",
    [hernoemd, historyRead()[0].naam], ["Testomgeving maart", "Testomgeving maart"]);
  check("eigen naam: dropdownregel toont naam en tijdstempel",
    geschiedenisOptieTekst(historyRead()[0]),
    `Testomgeving maart \u00b7 ${labelItem.label} \u2014 CVE-2026-1`);
  check("eigen naam: afgekapt op 60 tekens (maxlength van het veld)",
    historyRename(labelItem.key, "A".repeat(80)).length, 60);
  check("eigen naam: lege invoer maakt de regel weer naamloos",
    [historyRename(labelItem.key, "   "), historyRead()[0].naam], ["", undefined]);
  check("eigen naam: onbekende sleutel (intussen gewist) levert null op",
    historyRename("er-gaat-iets-weg", "x"), null);
  historyRename(labelItem.key, "Herstelnaam");
  statusWrites.length = 0;
  historyRestore(labelItem.key);
  check("eigen naam: de herstelmelding noemt de naam vóór het tijdstempel",
    statusWrites[statusWrites.length - 1].includes("(Herstelnaam, "), true);
  setAdvisories([]);
  // Bedrading en vormgeving: veld in de HTML (met label en maxlength), eigen
  // breedte in de CSS, en de koppeling aan de selectie in app.js.
  check("eigen naam: labelveld in index.html met aria-label, maxlength en disabled",
    [/id="hist-label"[^>]*maxlength="60"/.test(htmlSrc),
     /aria-label="Eigen naam voor de geselecteerde geschiedenisregel"/.test(htmlSrc),
     /id="hist-label"[^>]*disabled/.test(htmlSrc)], [true, true, true]);
  check("eigen naam: eigen breedte en gedempte staat in style.css",
    [/\.hist-label-input\s*\{[^}]*min-width:\s*12rem/.test(cssSrc),
     /\.hist-label-input:disabled/.test(cssSrc)], [true, true]);
  check("eigen naam: veld is gekoppeld aan de selectie (change + sync in renderHistory)",
    /histLabelInput\.addEventListener\("change"/.test(src) &&
    /histLabelInput\.value = geselecteerd && geselecteerd\.naam/.test(src) &&
    /histLabelInput\.disabled = !list\.length/.test(src), true);

  // --- 24. Stroomschema-afbidding (uitbreidingsronde) ---------------------
  // Optioneel afbeeldingsveld onder de Handelingsperspectieven: een kaal
  // URL'tje krijgt markdown-notatie, een volledig blok blijft zoals het is,
  // en de preview toont een echte <img> (de renderer kende geen
  // afbeeldingssyntaxis en zou er "!<a>" van hebben gemaakt).
  setAdvisories([cvePatch("CVE-2026-1", "nginx", "1.31.9")]);
  check("stroomschema: leeg veld laat de output ongewijzigd",
    [buildMarkdown().includes("Stroomschema"), buildMarkdown().includes("## Technische Details")],
    [false, true]);
  cachedStub("#stroomschema").value = "https://x.nl/stroom.png";
  const mdStroom = buildMarkdown();
  check("stroomschema: kale URL krijgt afbeeldingsnotatie tussen adviezen en Technische Details",
    [mdStroom.includes("![Stroomschema](https://x.nl/stroom.png)"),
     mdStroom.indexOf("## Handelingsperspectieven & Adviezen") < mdStroom.indexOf("![Stroomschema]("),
     mdStroom.indexOf("![Stroomschema](") < mdStroom.indexOf("## Technische Details")],
    [true, true, true]);
  cachedStub("#stroomschema").value = "![Proces](https://x.nl/p.png)";
  check("stroomschema: volledige notatie blijft onveranderd",
    buildMarkdown().includes("![Proces](https://x.nl/p.png)"), true);
  const imgHtml = mdToHtml("![Stroomschema](https://x.nl/a.png)");
  check("stroomschema: preview toont <img> met alt en geen los uitroepteken",
    [imgHtml.includes('<img src="https://x.nl/a.png" alt="Stroomschema">'), imgHtml.includes("!<a")],
    [true, false]);
  check("stroomschema: markdown-koppeling blijft een ankertekst (regressie)",
    mdToHtml("[klik](https://x.nl/a)").includes('<a href="https://x.nl/a" target="_blank" rel="noopener">klik</a>'), true);
  check("stroomschema: tekstexport-route zet 'bijschrift: url' als regel",
    pdfRegels("![Stroomschema](https://x.nl/a.png)")[0],
    { tekst: "Stroomschema: https://x.nl/a.png", stijl: "tekst" });
  check("stroomschema: veld reist mee in het geschiednissnapshot",
    captureFields().stroomschema, "![Proces](https://x.nl/p.png)");
  check("stroomschema: veld met label in index.html",
    /for="stroomschema"/.test(htmlSrc) && /id="stroomschema"/.test(htmlSrc), true);
  check("stroomschema: max-width in preview-CSS en print-CSS",
    [/\.preview img\s*\{[^}]*max-width:\s*100%/.test(cssSrc),
     /img \{ max-width: 100%; \}/.test(src)], [true, true]);
  check("stroomschema: buildMarkdown bouwt de regel voorwaardelijk in",
    /const stroomRegel = stroomRegelTekst\(\)/.test(src) && /stroomRegel \?/.test(src), true);
  cachedStub("#stroomschema").value = "";
  setAdvisories([]);

  // --- 25. html2canvas: PDF "met opmaak" (tweede externe bron) ------------
  // De layoutloop van exportPdfMetOpmaak (verborgen kopie van de preview,
  // repen per A4-pagina, kop/paginanummer, bestandsnaam) draait tegen een
  // namaak-canvas en de namaak-jsPDF uit sectie 22; de echte CDN en het
  // echte tekenwerk blijven buiten de test. Beide terugvallen (CDN ontbreekt,
  // tekenen faalt) moeten op de printdialoog uitkomen.
  // addImage noteert ook de hoogte in mm: de raster-tests controleren op
  // die hoogtes of de repen echt per A4-pagina snijden en of de
  // weeskopbescherming een reep verkort.
  FakeJsPdf.prototype.addImage = function (url, fmt, x, y, breedte, hoog) { this.pages[this._i].push({ img: url, hoog }); };
  check("html2canvasKlaar: false zonder window.html2canvas", html2canvasKlaar(), false);
  setLastMarkdown("h2c-tekst");
  statusWrites.length = 0;
  // Stub-hygiëne (punt 4 van de schone run): de gecachete stub-cache kent
  // één #advisory-preview die eerdere secties met inhoud hebben achtergelaten
  // (sectie 14 liet er generate()-uitvoer in staan). De terugval mocht niet
  // van die restwaarde leven: een expliciet gezette inhoud vóór de aanroep
  // plus een opgenomen iframe-schrijfwerk maakt de check inhoudsonafhankelijk.
  const oorsprCreateH2c = sandbox.document.createElement;
  let iframeH2c = null;
  const geschrevenH2c = [];
  sandbox.document.createElement = (tag) => {
    const el = oorsprCreateH2c(tag);
    if (tag === "iframe") { iframeH2c = el; el.contentWindow.document.write = (s) => geschrevenH2c.push(String(s)); }
    return el;
  };
  cachedStub("#advisory-preview").innerHTML = "<p>ACTUELE-PREVIEW</p>";
  await exportPdfMetOpmaak(); // nog geen namaak-window: terugvalpad
  check("html2canvas: zonder CDN-bibliotheken meldt de knop de terugval én opent de printdialoog",
    [statusWrites.some((w) => w.includes("html2canvas en/of jsPDF niet geladen")),
     statusWrites[statusWrites.length - 1].includes("Printdialoog geopend")], [true, true]);
  check("html2canvas: de terugval-printdialoog gebruikt de actuele preview-inhoud (geen stub-restwaarde)",
    [iframeH2c !== null, geschrevenH2c.some((s) => s.includes("<p>ACTUELE-PREVIEW</p>"))], [true, true]);
  sandbox.document.createElement = oorsprCreateH2c; // wrapper van de fallbackcheck eraf
  let h2cElement = null;
  sandbox.window = {
    html2canvas: async (el) => { h2cElement = el; return { width: 1316, height: 2632 }; },
    jspdf: { jsPDF: FakeJsPdf },
  };
  cachedStub("#advisory-ref").value = "ADV-2026-001";
  cachedStub("#advisory-preview").innerHTML = "<p>PROEFPREVIEW</p>";
  statusWrites.length = 0;
  await exportPdfMetOpmaak();
  check("html2canvas: verborgen kopie op vaste breedte met preview-klasse en -inhoud",
    [String(h2cElement.style.cssText).includes("658px"),
     h2cElement.children[0].className, h2cElement.children[0].innerHTML],
    [true, "preview", "<p>PROEFPREVIEW</p>"]);
  const pgH = laatsteDoc.pages;
  check("html2canvas: raster per A4-pagina (twee repen JPEG op twee pagina's)",
    [pgH.length, pgH.map((p) => p.some((d) => d.img === "data:reep"))], [2, [true, true]]);
  check("html2canvas: lopende kop en paginanummer op elke pagina",
    pgH.map((p) => [p.some((d) => d.t === "ADV-2026-001"),
      p.some((d) => d.t === "1 / 2" || d.t === "2 / 2")]),
    [[true, true], [true, true]]);
  check("html2canvas: bestandsnaam -opmaak.pdf en downloadmelding met rasterhinweis",
    [laatsteDoc._naam, statusWrites[statusWrites.length - 1].includes("PDF met opmaak gedownload")],
    ["ADV-2026-001-opmaak.pdf", true]);
  let h2cFailEl = null;
  sandbox.window.html2canvas = async (el) => { h2cFailEl = el; throw new Error("tekenen mislukt"); };
  statusWrites.length = 0;
  // Verwachte console-error van het terugvalpad (mislukte tekening): vm-
  // console tijdelijk afzetten; de testoutput zelf loopt via de buitenste console.
  const origConsole25 = sandbox.console;
  sandbox.console = { log: noop, warn: noop, error: noop };
  await exportPdfMetOpmaak();
  sandbox.console = origConsole25;
  check("html2canvas: mislukte tekening meldt de terugval en opent de printdialoog",
    [statusWrites.some((w) => w.includes("html2canvas-export mislukt; printdialoog als terugval")),
     statusWrites[statusWrites.length - 1].includes("Printdialoog geopend")], [true, true]);
  check("html2canvas: ook bij een mislukte tekening ruimt de finally de verborgen kopie op",
    h2cFailEl && h2cFailEl.removed, true);
  delete sandbox.window;
  // De knop gaat tijdens het tekenen op slot: dubbelklikken gaf anders twee
  // downloads naast elkaar. De namaak-canvas laat het tekenwerk 5 ms duren.
  sandbox.window = {
    html2canvas: async () => { await new Promise((r) => setTimeout(r, 5)); return { width: 1316, height: 1000 }; },
    jspdf: { jsPDF: FakeJsPdf },
  };
  const knopH = cachedStub("#pdf-opmaak");
  const runH = knopH.listeners.click[0]();
  const tijdens = knopH.disabled;
  await runH;
  check("html2canvas: knop staat tijdens de run op slot en herstelt daarna",
    [tijdens, knopH.disabled], [true, false]);
  delete sandbox.window;
  cachedStub("#advisory-ref").value = "";
  cachedStub("#advisory-preview").innerHTML = ""; // stub-hygiëne: gedeelde stub leeg achterlaten
  // Bedrading en toeleveringsketen: CDN-tag met async/SRI, knop in HTML en
  // app.js, en de knop wordt na genereren/herstel uit disabled gehaald.
  const h2cTag = htmlSrc.match(/<script[^>]*html2canvas[^>]*>/)[0];
  check("html2canvas: CDN-tag async en SRI-gepind (integrity sha512 + crossorigin)",
    [/\basync\b/.test(h2cTag), /integrity="sha512-[A-Za-z0-9+/=]{60,}"/.test(h2cTag),
     /crossorigin="anonymous"/.test(h2cTag)], [true, true, true]);
  check("html2canvas: knopbedrading in HTML en app.js (incl. inschakelen na generatie)",
    [/id="pdf-opmaak"/.test(htmlSrc),
     /if \(pdfOpmaakBtn\) pdfOpmaakBtn\.disabled = false/.test(src),
     /await exportPdfMetOpmaak\(\)/.test(src)], [true, true, true]);
  // jsPDF v4 kent géén optie "useFileSaveAs" (type-definitie 4.x: alleen
  // orientation/unit/format/compress/precision/filters/userUnit/encryption/
  // putOnlyUsedFonts/hotfixes/floatPrecision); een onbekende optie werd
  // stil genegeerd en suggeerde een niet-bestaande Firefox-fix. Deze check
  // bakt de beide constructors op hun kale opties.
  const ctorsJsPdf = src.match(/new jsPDF\(\{[^)]*\}\)/g) || [];
  check("jsPDF: beide constructors geven alleen bestaande opties mee (geen useFileSaveAs)",
    [ctorsJsPdf.length, ctorsJsPdf.every((c) => !c.includes("useFileSaveAs"))], [2, true]);

  // --- 25b. Weeskopbescherming op de repengrens (punt 6 schone run) ------
  // De raster-snijder kende de bescherming niet die de tekstexport en de
  // printdialoog al hadden: een kop vlak boven de repengrens kon eenzaam
  // onderaan een pagina eindigen. De namaak-html2canvas zet daarvoor een
  // querySelectorAll op het kopie-element; de koppositie komt uit de
  // offsetTop van de kopie zelf. Verwachtingen (canvas 1316×2632 px, breedte
  // 174 mm): mmPerPx = 174/1316, pxPerPagina = 1928, grens = 1928 px,
  // KOP_HOUD = 14 mm = 106 px. Een kop op offsetTop 1300 px (×2 = 2600 px)
  // valt dus 670 px vóór de grens en wordt NIET verzet; een kop op
  // offsetTop 960 px (×2 = 1920 px) valt 8 px vóór de grens en wél.
  const mmPerPxH2c = 174 / 1316;
  const op = (px) => px * mmPerPxH2c; // pixels → mm op papier
  const nabij = (a, b) => Math.abs(a - b) < 0.01;
  const hoogtesVan = (pg) => pg.map((p) => (p.find((d) => d.img) || {}).hoog);
  const mkKopCanvas = (kopOffsetTops, hoogtePx = 2632) => async (el) => {
    el.children[0].querySelectorAll = () => kopOffsetTops.map((t) => ({ offsetTop: t }));
    return { width: 1316, height: hoogtePx };
  };
  sandbox.window = { jspdf: { jsPDF: FakeJsPdf }, html2canvas: mkKopCanvas([1300]) }; // kop ver van de grens
  setLastMarkdown("kopproef-1");
  await exportPdfMetOpmaak();
  const hoogtesK = hoogtesVan(laatsteDoc.pages);
  check("raster: een kop ver van de repengrens blijft staan (volle eerste reep, rest als tweede)",
    [laatsteDoc.pages.length, nabij(hoogtesK[0], op(1928)), nabij(hoogtesK[1], op(704))], [2, true, true]);
  sandbox.window.html2canvas = mkKopCanvas([960]); // kop op 1920 px: 8 px vóór de grens van 1928
  setLastMarkdown("kopproef-2");
  await exportPdfMetOpmaak();
  const hoogtesL = hoogtesVan(laatsteDoc.pages);
  check("raster: een kop vlak boven de repengrens schuift door (eerste reep wordt korter)",
    [laatsteDoc.pages.length, nabij(hoogtesL[0], op(1919)), nabij(hoogtesL[1], op(713))], [2, true, true]);
  check("raster: de verkorte reep geeft geen beeldverlies (som van repen = canvashoogte)",
    nabij(hoogtesL.reduce((a, h) => a + h, 0), op(2632)), true);
  sandbox.window.html2canvas = mkKopCanvas([150, 160, 1500], 1000); // koppen vlak bij elkaar, canvas past op één pagina
  setLastMarkdown("kopproef-3");
  await exportPdfMetOpmaak();
  const hoogtesN = hoogtesVan(laatsteDoc.pages);
  check("raster: de laatste reep krijgt geen kopbescherming (één reep, geen eindeloos snijden)",
    [laatsteDoc.pages.length, nabij(hoogtesN[0], op(1000))], [1, true]);
  delete sandbox.window;

  // --- 26. Afbreekbare achtergrondverzoeken (KEV/EPSS bij herstel) ---------
  // Punt 3 van de schone run: een nieuwe generatie kapt de KEV-/EPSS-
  // verzoeken die restoreState op de achtergrond start af (AbortController),
  // zodat een trage lopende call niet alsnog over het nieuwe resultaat heen
  // renderde. Afbreken is géén uitval: kevFailed/epssFailed blijven uit en
  // de volgende beurt probeert het gewoon. De controller-zelf is DOM-
  // gedrag (in de sandbox afwezig, dus daar draait de route zonder signaal);
  // de signaal-doorifte, de AbortError-behandeling en de bedrading worden
  // hier dynamisch en statisch gecheckt.
  let seenSignal = null;
  sandbox.fetch = async (url, opts) => { seenSignal = opts && opts.signal; return { ok: true, json: async () => ({ ok: 1 }) }; };
  await fetchJson("https://x/y", { tries: 1, signal: "SIGNAALTJE" });
  check("afbreken: fetchJson geeft het signaal door aan fetch", seenSignal, "SIGNAALTJE");
  let abortPogingen = 0;
  sandbox.fetch = async () => { abortPogingen++; const e = new Error("afgebroken"); e.name = "AbortError"; throw e; };
  let abortGegooid = false;
  try { await fetchJson("https://x/y", { tries: 3, baseDelay: 1 }); }
  catch (e) { abortGegooid = e.name === "AbortError"; }
  check("afbreken: AbortError is een bewuste afbreking en wordt niet opnieuw geprobeerd",
    [abortPogingen, abortGegooid], [1, true]);
  resetKevState();
  let kevPogingen = 0;
  // NB: sessieopslag expliciet leegmaken: eerdere secties (de generate-
  // runs) kunnen de KEV-feed al in sessionStorage hebben gezet, en die
  // cache doet loadKev de fetch overslaan - dan telt kevPogingen één te
  // laag. resetKevState zelf laat de sessiecaches bewust intact (het is
  // ook de testhaak voor de terugvalroutes), dus de wis is hier expliciet.
  sandbox.sessionStorage.clear();
  sandbox.fetch = async () => { kevPogingen++; const e = new Error("afgebroken"); e.name = "AbortError"; throw e; };
  await loadKev({});
  check("afbreken: een afgebroken KEV-verzoek blijft géén uitval (map leeg, failed uit)",
    kevState(), { map: null, failed: false });
  resetKevState(); // alleen de in-memory vlaggen wissen, de sessie-cache staat leeg
  // NB: ook deze tweede stub verhoogt kevPogingen. De eerdere versie van deze
  // stub vergat de increment, waardoor de teller op één bleef terwijl het
  // gedrag (nieuw verzoek na een afbreking) juist wél klopte: de check
  // faalde op de telling, niet op de retry.
  sandbox.fetch = async () => { kevPogingen++; return { ok: true, json: async () => ({ vulnerabilities: [{ cveID: "CVE-2026-KEV", dateAdded: "2026-01-01" }] }) }; };
  await loadKev();
  check("afbreken: na een afbreking probeert de volgende KEV-beurt wél en laadt de feed",
    [kevPogingen, kevState().map, !!kevInfo({ id: "CVE-2026-KEV" })], [2, 1, true]);
  clearEpssCache();
  sandbox.fetch = async () => { const e = new Error("afgebroken"); e.name = "AbortError"; throw e; };
  await laadEpss(["CVE-2026-7"]);
  const epssNaAfbraak = epssInfo({ id: "CVE-2026-7" });
  sandbox.fetch = async () => ({ ok: true, json: async () => ({ data: [{ cve: "CVE-2026-7", epss: "0.42", percentile: "0.9", date: "2026-11-21" }] }) });
  await laadEpss(["CVE-2026-7"]);
  check("afbreken: een afgebroken EPSS-beurt is geen uitval en de volgende laadt wél",
    [epssNaAfbraak, epssInfo({ id: "CVE-2026-7" }).score], [null, 0.42]);
  check("afbreken: beide loaders keren bij AbortError terug zónder uitval te markeren",
    (src.match(/if \(e\.name === "AbortError"\) return;/g) || []).length, 2);
  check("afbreken: restoreState bundelt KEV/EPSS in één herbouw met eigen controller",
    [/achtergrondRun = controller/.test(src), /Promise\.all\(laden\)/.test(src),
     /if \(nogGeldig\(\)\)/.test(src)], [true, true, true]);
  check("afbreken: een nieuwe generatie kapt de achtergrondrun af",
    [/if \(achtergrondRun\) \{/.test(src), /achtergrondRun\.abort\(\)/.test(src)], [true, true]);

  // --- 27. Printdialoog wacht op nog ladende afbeeldingen -----------------
  // Punt 5 van de schone run: een stroomschema-afbeelding vanaf een trage
  // URL was bij het afdrukken nog niet geladen en gaf een lege vlek in de
  // print. De app loopt na het load-event expliciet de documentafbeeldingen
  // na: printen pas als elk beeld laadt of faalt, met een cap van 3 s zodat
  // een onbereikbaar plaatje de dialoog niet oneindig ophoudt. Het load-
  // event kan bovendien de about:blank-slag vangen, dus printen gebeurt
  // maximaal één keer per exportbeurt. De iframe-stub levert hiervoor een
  // document.images en print-notulerende contentWindow; de 250-ms-
  // stylingvertraging van de app is in de wachttijden meegerekend.
  const oorsprPrint = sandbox.document.createElement;
  const mkPrintEnv = (images) => {
    const prints = [];
    const el = {
      style: {}, attrs: {}, setAttribute(k, v) { this.attrs[k] = v; },
      listeners: {}, addEventListener(ev, fn) { (this.listeners[ev] ||= []).push(fn); },
      removed: false, remove() { this.removed = true; },
      contentWindow: {
        document: { open: noop, write: noop, close: noop, images },
        prints, focus: noop, print() { prints.push("print"); },
        addEventListener: noop, removeEventListener: noop,
      },
    };
    sandbox.document.createElement = () => el;
    return el;
  };
  setLastMarkdown("printtest");
  const imgTrage = { complete: false, listeners: {}, addEventListener(ev, fn) { (this.listeners[ev] ||= []).push(fn); } };
  const elTrage = mkPrintEnv([imgTrage]);
  exportPdfPrinten();
  elTrage.onload();
  await new Promise((r) => setTimeout(r, 320)); // 250 ms printvertraging was geweest
  const printsVoorLoad = elTrage.contentWindow.prints.length;
  imgTrage.listeners.load.forEach((fn) => fn());
  await new Promise((r) => setTimeout(r, 320));
  check("print: de printdialoog wacht een nog ladende afbeelding af en print daarna",
    [printsVoorLoad, elTrage.contentWindow.prints.length], [0, 1]);
  const elCompleet = mkPrintEnv([{ complete: true }]);
  exportPdfPrinten();
  elCompleet.onload();
  await new Promise((r) => setTimeout(r, 320));
  check("print: complete afbeeldingen laten de printdialoog direct door (alleen de stylingvertraging)",
    elCompleet.contentWindow.prints.length, 1);
  const elDubbel = mkPrintEnv([{ complete: true }]);
  exportPdfPrinten();
  elDubbel.onload(); elDubbel.onload(); // about:blank-slag én documentload
  await new Promise((r) => setTimeout(r, 320));
  check("print: dubbel load-event drukt precies één keer af",
    elDubbel.contentWindow.prints.length, 1);
  const imgKapotte = { complete: false, listeners: {}, addEventListener(ev, fn) { (this.listeners[ev] ||= []).push(fn); } };
  const elKapot = mkPrintEnv([imgKapotte]);
  exportPdfPrinten();
  elKapot.onload();
  imgKapotte.listeners.error.forEach((fn) => fn()); // gebroken plaatje: tóch door
  await new Promise((r) => setTimeout(r, 320));
  check("print: een gebroken afbeelding (error) houdt de printdialoog niet vast",
    elKapot.contentWindow.prints.length, 1);
  const elNooit = mkPrintEnv([{ complete: false, addEventListener: noop }]);
  exportPdfPrinten();
  elNooit.onload(); // geen enkel load-/error-event: de cap van 3 s moet redden
  await new Promise((r) => setTimeout(r, 3600));
  check("print: een afbeelding die nooit laadt, houdt de printdialoog niet langer dan de cap van 3 s",
    elNooit.contentWindow.prints.length, 1);
  sandbox.document.createElement = oorsprPrint; // stub-fabriek terugzetten
  setLastMarkdown("");

  // -------------------------------------------------------------------------
  // 28. PUNT 7: kleine consistentie-afwerkingen
  // ---------------------------------------------------------------------
  // Drie losse puntjes uit de schone-run-analyse, elk vastgezet zodat ze
  // niet terugsluipen: (a) elke console-fout in app.js draagt het "Advisory
  // Writer:"-prefix dat alle andere meldingen ook dragen, (b) de bedrading
  // van het geschiedenislabelveld is afwezigheidsbestendig als alle andere
  // knoppen, en (c) de modeldatum uit de EPSS-respons wordt in beide
  // responsvormen opgenomen (in de arraytak was het veld gedestructureerd
  // en genegeerd, terwijl de objecttak het wél zette).

  console.log("\n--- 28. kleine consistentie-afwerkingen ---");

  {
    // (a) elke console-oproep in app.js begint met het app-prefix. De teller
    // is expliciet: drie foutpaden (genereren, jsPDF, html2canvas) en die
    // drie moeten stuk voor stuk het prefix dragen.
    const foutLogs = src.match(/console\.error\("[^"]*"/g) || [];
    check("console: elk foutpad draagt het Advisory Writer-prefix", [
      foutLogs.length,
      foutLogs.every((m) => m.startsWith('console.error("Advisory Writer:')),
    ], [3, true]);

    // (b) het labelveld mag ontbreken zonder dat de init van de app kraakt.
    check("histLabel: ontbreekt het veld, dan kraakt de bedrading niet", [
      src.includes("if (histLabelInput) {"),
    ], [true]);

    // (c) EPSS-arraytak: de modeldatum uit de respons belandt in de cache,
    //     zodat de regel in Technische Details haar kan tonen.
    check("EPSS-arraytak: modeldatum uit de respons wordt bewaard", [
      src.includes("date: e.date || null"),
    ], [true]);
  }

  // --- 29. Harde timeout op uitgaande calls + URL-schema stroomschema ----- 
  // Twee kleine robuustheidsuitbreidingen. (a) fetchJson heeft nu een harde
  // bovengrens per poging: een hangende verbinding (promise die nooit uit
  // Holt) mocht de genereerbeurt anders oneindig laten wachten. De timeout
  // is noRetry: een poging van dertig seconden zonder respons wordt niet
  // binnen enkele seconden plotseling wel beantwoord. (b) Het
  // stroomschemaveld aanvaardt alleen http(s), een relatieve URL en
  // data:image; "javascript:..." of "blob:" is vrijwel altijd een plakfout
  // en laat de beeldregel vallen in plaats van een kapot beeld in pre-
  // view, print en export te slepen.
  {
    const origFetch29 = sandbox.fetch;

    // (a) hangende verbinding: de fetch-promise holt nooit uit
    let pogingen29 = 0;
    sandbox.fetch = async () => { pogingen29++; return new Promise(() => {}); };
    const rT = await fetchJson("https://hangt", { tries: 3, baseDelay: 1, timeoutMs: 50 })
      .then(() => ["geen fout", pogingen29], (e) => [e.message, pogingen29]);
    check("timeout: een hangende verbinding geeft op na timeoutMs (noRetry, één poging)",
      [/timeout/.test(rT[0]), rT[1]], [true, 1]);

    // (b) snelle respons: normaal resultaat, de wekker-timer doet niet mee
    sandbox.fetch = async () => ({ ok: true, json: async () => ({ snel: 1 }) });
    const rS = await fetchJson("https://snel", { tries: 1, baseDelay: 1, timeoutMs: 5000 });
    check("timeout: een snelle respons levert gewoon het resultaat op",
      rS.snel, 1);

    // (c) timeoutMs 0 schakelt de grens uit (gedrag als voor de uitbreiding)
    const rN = await fetchJson("https://nul", { tries: 1, baseDelay: 1, timeoutMs: 0 })
      .then(() => "ok", () => "fout");
    check("timeout: timeoutMs 0 laat de grens geheel buiten spel",
      rN, "ok");

    // (d) de standaard van dertig seconden staat als constante in de bron,
    //     zodat KEV-feed (meerdere MB) en NVD eronder passen
    check("timeout: standaard van 30 s als constante in app.js",
      /const FETCH_TIMEOUT_MS = 30000;/.test(src), true);

    sandbox.fetch = origFetch29;

    // (e) stroomschema: toegestane en geweigerde schema's
    const stroomTest = (v) => { cachedStub("#stroomschema").value = v; return stroomRegelTekst(); };
    check("stroomschema: http(s), relatief en data:image toegestaan",
      [stroomTest("https://x.nl/stroom.png"), stroomTest("stroom.png"),
       stroomTest("/img/plaatje.png"), stroomTest("data:image/png;base64,AAAA")],
      ["![Stroomschema](https://x.nl/stroom.png)", "![Stroomschema](stroom.png)",
       "![Stroomschema](/img/plaatje.png)", "![Stroomschema](data:image/png;base64,AAAA)"]);
    check("stroomschema: verrassende schema's laten de beeldregel vallen",
      [stroomTest("javascript:alert(1)"), stroomTest("blob:https://x.nl/abc"),
       stroomTest("ftp://x.nl/a.png"), stroomTest("![Proces](blob:https://x.nl/abc)")],
      ["", "", "", ""]);
    cachedStub("#stroomschema").value = ""; // stub-hygiene
  }

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})();
