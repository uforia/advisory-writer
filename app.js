/* ============================================================
   Advisory Writer — automates security advisories.
   Template follows de voorbeeldstructuur (CERT-stijl):
     Versie → aanhef → aankondiging → Impact →
     Handelingsperspectieven & Adviezen → Technische Details →
     afsluiting → geadresseerden → Disclaimer
   Data sources (CORS-enabled, no API key needed):
     - NVD API 2.0 : https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=...
       (optionele API-sleutel verhoogt de limiet; retry/backoff ingebouwd;
       per beurt gebundeld opgehaald via parameter cveIds, max 20 nummers
       per chunk, met terugval per nummer voor wat de bundelrespons niet
       teruggeeft of als de hele bundelcall faalt; een mislukte bundelcall
       logt een console-waarschuwing met het app-prefix)
     - CVE Program API (fallback): https://cveawg.mitre.org/api/cve/...
   KEV/SSVC (actief misbruik) komt primair uit de NVD-respons zelf
   (velden cisaExploitAdd/cisaActionDue en metrics.ssvcV*); de KEV-feed is
   terugval en wordt alleen opgehaald als die velden ontbreken. De
   KEV-terugval en de EPSS-call lopen parallel (Promise.all na de
   CVE-fase): de traagste van de twee bepaalt de duur van de fase, niet
   de som van beide:
   https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
   EPSS (exploitkans) komt van de FIRST EPSS-API
   (https://api.first.org/data/v1/epss?cve=...): één gebundeld verzoek per
   beurt, 24 uur per browser gecachet; de badge op de kaart en de regel in
   Technische Details vallen netjes weg als de API onbereikbaar is of het
   CVE-nummer niet in het model staat.
   Distributeurtrackers: de advisory sluit een vaste set controlelinks per
   CVE-nummer af (Debian, Ubuntu, Red Hat, SUSE, Fedora, Amazon Linux en
   Alpine), aangevuld met extra per-CVE-links uit de NVD-referenties van het
   eigen nummer (Rocky Linux, Arch Linux); zie distributeurRegels().
   Stroomschema: een optionele afbeelding-URL (bijv. een eigen beslisboom of
   procesplaatje) kan als beeld onder de Handelingsperspectieven & Adviezen
   worden gezet; zie stroomRegelTekst(). Een geweigerd URL-schema laat de
   beeldregel niet meer woordloos vallen: de statusbalk meldt de weigering
   (helper stroomWaarschuwing, toonmoment toonStroomStatus) bij live-herbouw
   én in de afsluitende melding van genereren.
   PDF-export: jsPDF (CDN) maakt een echte PDF-download met paginanummers en
   lopende kop; zonder die bibliotheek (offline of geblokkeerd) of met het
   vink "PDF via printdialoog" blijft de browserprintdialoog de route. De
   knop "PDF met opmaak" fotografeert de preview met html2canvas (CDN) en
   plakt die als raster op een PDF; ontbreekt die bibliotheek of faalt het
   tekenen, dan valt ook die knop terug op de printdialoog. Beide PDF-routes
   wachten eerst op ladende afbeeldingen (gedeelde wachtOpPlaatjes-helper),
   zodat de raster-route zijn kopposities op de juiste hoogtes meet. Beide
   CDN-scripts laden async en zijn SRI-gepind. De printdialoog zelf krijgt
   een upgrade via paged.js (optie 3): de pagedjs-polyfill (jsDelivr,
   sha256-SRI) wordt in het print-iframe geladen en paginéért het document
   echt (margeboxen in elke browser, breukbescherming op regelgeometrie);
   is de CDN er niet of te traag, dan print de dialoog kaal zoals altijd.
   Extra bediening: live-herbouw van de advisory bij veldwijzigingen,
   staatsherstel na herladen (LocalStorage), deellink via ?cve=...-parameter
   (op file:// valt die terug op het eigen adres, want daar is origin "null"),
   de taal van de CVE-beschrijvingen is kiesbaar via het veld "Beschrij-
   vingstaal" (auto volgt de browsertaal, NL/EN vast; alleen de opgehaalde
   beschrijving volgt de keuze; zie taalVoorkeur()/kiesBeschrijving()) en
   de bediening is volledig tweetalig via het veld "Interfacetaal"
   (woordenboek UI_TEKSTEN met T()/vertaalUi(); de advisory-brief blijft
   Nederlands; zie uiTaal()),
   CVE-fetchcache (sessionStorage), bewerkbare raw-markdown en een
   geschiedenis van de laatste advisory's, waarin elke regel een eigen naam
   kan krijgen via het labelveld naast de dropdown; de CVE-records gaan
   compact de opslag in (compactAdvisory: alleen wat bouwer en kaart nodig
   hebben, referenties gekapt op de getoonde zes). Na een beurt met een
   zachte uitval (mislukte nummers, KEV/EPSS-uitval of een geweigerd
   stroomschema) verschijnt bovendien de knop "Probeer opnieuw" onder de
   statusbalk: één klik draait een volledige generatie en heft de
   KEV/EPSS-afkoelperiode op (optie 7). De KEV-/EPSS-verzoeken
   die bij een herstel op de achtergrond lopen, zijn afbreekbaar: een nieuwe
   generatie kapt ze af in plaats van er dubbel op na te bouwen. Het
   knopslot tijdens genereren is gecentraliseerd: generate() schakelt vijf
   knoppen uit en de finally zet ze voor élke uitkomst weer aan (succes,
   onverwachte fout en vroegtijdige return bij volledige ophaalmislukking).
   Toegankelijkheid (A11y): de statusbalk is een aria-live-region (meldingen
   als "NVD-limiet bereikt" zijn zo ook voor schermlezers hoorbaar) en
   krijgt tijdens meldingsbursts tijdelijk aria-busy, zodat een schermlezer
   alleen de definitieve melding voorleest; de tab-knoppen zijn
   toggle-knoppen met aria-pressed, het API-sleutelveld is type="password"
   en de bewerkbare tekstvakken hebben een label.
   Meertaligheid (optie 2, volledig): twee onafhankelijke keuzes. Het veld
   "Beschrijvingstaal" (#taal-select) bepaalt uit welke NVD-exemplaren de
   CVE-beschrijvingen worden gekozen (taalVoorkeur/kiesBeschrijving). Het
   veld "Interfacetaal" (#ui-taal) vertaalt de bediening: statieveel via
   data-i18n-attributen (vertaalUi), statusmeldingen, kaart- en
   geschiedenisteksten via woordenboek UI_TEKSTEN met T(); "auto" volgt de
   browsertaal en zonder browsertaal blijft de app Nederlands. De advisory-
   brief zelf blijft Nederlands: de brief is product, niet bediening.
   ============================================================ */

"use strict";

// ---------- DOM ----------
const $ = (sel) => document.querySelector(sel);
const cveInput = $("#cve-input");
const titleInput = $("#advisory-title");
const refInput = $("#advisory-ref");
const dateInput = $("#pub-date");
const prioriteitSelect = $("#prioriteit-select");
// Taalkeuze voor de CVE-beschrijvingen (optie 2); zie taalVoorkeur().
const taalSelect = $("#taal-select");
// Taalkeuze van de interface (optie 2, volledig); zie uiTaal()/vertaalUi().
const uiTaalSelect = $("#ui-taal");
const aankondigerInput = $("#aankondiger");
const aankondigingDatumInput = $("#aankondiging-datum");
const bijnaamInput = $("#bijnaam");
const meldpuntInput = $("#meldpunt");
const aanhefInput = $("#aanhef");
const geadresseerdenInput = $("#geadresseerden");
const openingInput = $("#opening");
const impactInput = $("#impact");
const handelInput = $("#handelingsperspectieven");
const stroomInput = $("#stroomschema");
const versieInput = $("#advisory-versie");
const apiKeyInput = $("#nvd-apikey");
const noCacheInput = $("#no-cache");
const fetchBtn = $("#fetch-btn");
const copyBtn = $("#copy-btn");
const downloadBtn = $("#download-btn");
const pdfBtn = $("#pdf-btn");
const pdfOpmaakBtn = $("#pdf-opmaak");
const pdfPrintInput = $("#pdf-print");
const disclaimerStatusEl = $("#disclaimer-status");
const statusEl = $("#status");
const dataPanel = $("#data-panel");
const cveCards = $("#cve-cards");
const outputPanel = $("#output-panel");
const previewEl = $("#advisory-preview");
const rawEl = $("#advisory-raw");
const regenBtn = $("#regen-btn");
const historySelect = $("#history-select");
const histLabelInput = $("#hist-label");
const histDelBtn = $("#hist-del");
const histClearBtn = $("#hist-clear");
// Retry-knop na uitval (optie 7): staat in index.html verborgen en verschijnt
// alleen na een generatiebeurt met ten minste één zachte uitval.
const retryBtn = $("#retry-btn");

let advisories = [];   // fetched + normalised CVE data
let lastMarkdown = "";
let manualEdits = false; // raw-tekst handmatig gewijzigd: velden bouwen niet meer over
// AbortController van de KEV/EPSS-verzoeken die restoreState op de
// achtergrond start; een nieuwe generatie kapt ze af (zie generate()).
let achtergrondRun = null;

// ---------- Onthouden van ingevulde velden (LocalStorage) ----------
// Alle door de gebruiker ingevulde velden worden bij elke wijziging opgeslagen
// in LocalStorage en bij een volgend bezoek hersteld. Velden die de gebruiker
// nooit heeft aangeraakt, krijgen bij het openen hun automatische standaard
// (publicatiedatum = nu, voorbeeld-CVE). 'Velden wissen' wist het geheugen.

// ==================== MEERTALIGE UI (OPTIE 2, VOLLEDIG) ====================
// Twee talen, één woordenboek per taal. uiTaal() volgt hetzelfde patroon als
// taalVoorkeur(): vaste keuze boven auto, auto volgt de browsertaal; bij een
// onbekende of ontbrekende browsertaal blijft de interface in het Nederlands
// (de moedertaal van de app), want dan staat het veld op "auto" en is er
// verder niets te kiezen.
function uiTaal() {
  const v = (uiTaalSelect && uiTaalSelect.value) || "auto";
  if (v === "nl" || v === "en") return v;
  const nav = String((navigator && navigator.language) || "");
  if (!nav) return "nl"; // geen browsertaal bekend (oude browser, sandbox): moedertaal
  return nav.toLowerCase().replace("_", "-").startsWith("nl") ? "nl" : "en";
}

// T(sleutel, vervangers): tekst uit het woordenboek van de actieve
// interface-taal, met {placeholder}-vervanging. Ontbreekt een sleutel in de
// voorkeurstaal dan valt T terug op het Nederlands; ontbreekt hij ook daar,
// dan komt de sleutel zelf terug - een ontbrekende vertaling is dan zicht-
// baar in de interface in plaats van onzichtbaar.
function T(sleutel, vervangers) {
  const t = UI_TEKSTEN[uiTaal()] || UI_TEKSTEN.nl;
  let s = t[sleutel];
  if (s === undefined) s = UI_TEKSTEN.nl[sleutel];
  if (s === undefined) return sleutel;
  if (vervangers) {
    for (const k of Object.keys(vervangers)) s = s.split("{" + k + "}").join(String(vervangers[k]));
  }
  return s;
}

// Statieveel vertalen: elk element met data-i18n (tekst), data-i18n-html
// (tekst met markup, zoals de footer en de labels met hint-span),
// data-i18n-title, data-i18n-ph (placeholder) of data-i18n-aria (aria-label)
// krijgt de woordenboekversie van de actieve taal; <html lang> en de
// documenttitel volgen mee. Nieuw statieveel: geef het element het
// data-attribuut met een sleutel en voeg die sleutel in BEIDE talen aan
// UI_TEKSTEN toe; test 43(e) telt de attributen en faalt bij een eenzijdige
// toevoeging.
function vertaalUi() {
  const taal = uiTaal();
  if (typeof document === "undefined" || !document) return;
  if (document.documentElement) document.documentElement.lang = taal;
  document.title = T("paginatitel");
  const els = document.querySelectorAll
    ? document.querySelectorAll("[data-i18n],[data-i18n-html],[data-i18n-title],[data-i18n-ph],[data-i18n-aria]")
    : [];
  for (const el of els) {
    if (!el.getAttribute) continue;
    const kh = el.getAttribute("data-i18n-html");
    const k = kh != null ? kh : el.getAttribute("data-i18n");
    if (k != null) {
      if (kh != null) el.innerHTML = T(k);
      else el.textContent = T(k);
    }
    const kt = el.getAttribute("data-i18n-title");
    if (kt != null) el.setAttribute("title", T(kt));
    const kp = el.getAttribute("data-i18n-ph");
    if (kp != null) el.setAttribute("placeholder", T(kp));
    const ka = el.getAttribute("data-i18n-aria");
    if (ka != null) el.setAttribute("aria-label", T(ka));
  }
}

// Sleutels in deze dictionary zijn contract: index.html verwijst met
// data-i18n-sleutels naar de NL/EN-paren hieronder, en de runtime-strings
// van de statusbalk, de kaarten en de geschiedenis (T()-aanroepen in
// app.js) delen dezelfde lijst. De prioriteits- en taallopen van de
// selectlists worden wél meevertaald, maar de OPTIEWAARDEN ("Laag", ...) niet
// - die staan zo in de brief en in de CVSS-techniek van de kaarten.
const UI_TEKSTEN = {
  nl: {
    "paginatitel": "Advisory Writer — Security Advisories",
    "header.sub": "Genereer security advisories — vul alleen de CVE's in; de tekstvelden zijn optioneel.",
    "kop.invoer": "Invoer",
    "label.cve": "CVE's <span class=\"hint\">(een per regel of gescheiden door komma's)</span>",
    "label.titel": "Advisorytitel <span class=\"hint\">(optioneel, wordt automatisch gegenereerd)</span>",
    "ph.titel": "Kritieke kwetsbaarheden in nginx",
    "label.ref": "Advisorynummer <span class=\"hint\">(optioneel)</span>",
    "label.datum": "Publicatiedatum/tijd",
    "label.prioriteit": "Prioriteit <span class=\"hint\">(handmatig; auto = zwaarste CVSS over alle CVE's)</span>",
    "opt.pri.auto": "Automatisch (op basis van CVSS)",
    "opt.pri.laag": "Laag", "opt.pri.middel": "Middel", "opt.pri.hoog": "Hoog", "opt.pri.kritiek": "Kritiek",
    "label.taal": "Beschrijvingstaal <span class=\"hint\">(taal van de opgehaalde CVE-beschrijvingen; de brief zelf blijft Nederlands)</span>",
    "taal.title": "Welk beschrijvingsexemplaar van de CVE's op de kaarten en in Technische Details komt; bij ontbreken van de voorkeurstaal valt dit terug op Engels en dan op de eerste beschrijving",
    "opt.taal.auto": "Automatisch (browsertaal)",
    "opt.taal.nl": "Nederlands (waar beschikbaar)",
    "opt.taal.en": "Engels",
    "label.uitaal": "Interfacetaal <span class=\"hint\">(taal van de app; de advisory-brief blijft Nederlands)</span>",
    "uitaal.title": "Taal van bediening, statusmeldingen en CVE-kaarten; de advisory en de CVE-beschrijvingen volgen eigen keuzes",
    "opt.uitaal.auto": "Automatisch (browsertaal)",
    "opt.uitaal.nl": "Nederlands",
    "opt.uitaal.en": "English",
    "label.versie": "Advisoryversie <span class=\"hint\">(standaard 1.0; verhoog bij een herissue, bijv. 1.1)</span>",
    "label.apikey": "NVD API-sleutel <span class=\"hint\">(optioneel; verhoogt de NVD-limiet van 5 naar 50 req/30 s)</span>",
    "ph.apikey": "gratis aan te vragen op nvd.nist.gov (verplicht bij vele CVE's tegelijk)",
    "summary.textvelden": "Tekstvelden voor de brief <span class=\"hint\">(aanhef, aankondiging, impact, adviezen, geadresseerden)</span>",
    "label.aanhef": "Aanhef <span class=\"hint\">(optioneel, bijv. \"Beste NS-collega,\")</span>",
    "ph.aanhef": "Beste NS-collega,",
    "label.meldpunt": "Meldpunt <span class=\"hint\">(voor de centralisatie-alinea)</span>",
    "ph.meldpunt": "CERT via cert@cert.nl",
    "label.opening": "Opening <span class=\"hint\">(optionele alinea vóór de titel, bijv. \"Graag jullie zorgvuldige aandacht voor het onderstaande bericht.\")</span>",
    "ph.opening": "Graag jullie zorgvuldige aandacht voor het urgente onderstaande bericht.",
    "label.ankondiger": "Aangekondigd door <span class=\"hint\">(optioneel; anders vendor uit NVD)</span>",
    "ph.ankondiger": "Xint en F5/nginx",
    "label.ankonddatum": "Aankondigingsdatum <span class=\"hint\">(optioneel; anders publicatiedatum)</span>",
    "ph.ankonddatum": "18 november 2026",
    "label.bijnaam": "Bijnaam <span class=\"hint\">(optioneel, bijv. nginx2root)</span>",
    "ph.bijnaam": "sshhole",
    "label.impact": "Impact <span class=\"hint\">(vrije tekst; anders automatisch gegenereerde standaardimpact)</span>",
    "ph.impact": "Een succesvolle aanval kan leiden tot ...",
    "label.handel": "Eigen handelingsperspectieven <span class=\"hint\">één per regel; worden vóór de standaardadviezen geplaatst (bijv. interne systemen, AKS, RSMAN)</span>",
    "ph.handel": "Amazon Kubernetes Service: patch deze meteen.\nRSMAN\nBodyCam APIs",
    "label.stroom": "Stroomschema <span class=\"hint\">(optioneel; afbeelding-URL die onder de Handelingsperspectieven & Adviezen komt te staan, bijv. een eigen beslisboom of procesplaatje)</span>",
    "label.gead": "Geadresseerden <span class=\"hint\">(optioneel; wordt \"Deze mail is gestuurd aan: ...\")</span>",
    "ph.gead": "IT leads, IT managers, BISO's, TISO's, CTI en CSO",
    "vink.vers": "Vers ophalen (geen cache)",
    "vink.vers.title": "Opgeslagen CVE-gegevens (1 uur per browsersessie) overslaan en alles opnieuw bij NVD ophalen",
    "knop.ophalen": "Ophalen & genereren",
    "knop.kopieer": "Markdown kopiëren",
    "knop.download": ".md downloaden",
    "knop.pdf": "PDF exporteren",
    "knop.pdf.title": "Download de advisory als PDF-bestand (jsPDF); vink „PDF via printdialoog” aan voor de browserprintdialoog met alle HTML-opmaak",
    "knop.pdfopmaak": "PDF met opmaak",
    "knop.pdfopmaak.title": "Download de advisory als PDF met alle HTML-opmaak (tabelkaders, badges en het stroomschema-beeld): html2canvas fotografeert de preview als raster. Tekst is dan niet selecteerbaar; ontbreekt de CDN of faalt het tekenen, dan opent de printdialoog",
    "vink.print": "PDF via printdialoog",
    "vink.print.title": "Genereer de PDF via de browserprintdialoog in plaats van de ingebouwde jsPDF-download (bijv. om vooraf te kijken of de opmaak klopt)",
    "knop.deellink": "Deellink kopiëren",
    "knop.deellink.title": "Kopieer een link met de ingevulde CVE's (?cve=...); de ontvanger opent de app met directe generatie",
    "knop.wissen": "Velden wissen",
    "knop.wissen.title": "Wis alle ingevulde velden en herstel de standaardwaarden",
    "hint.geheugen": "Ingevulde velden worden automatisch onthouden in deze browser (LocalStorage) en bij een volgend bezoek hersteld; het laatste resultaat wordt na herladen teruggezet. Opgehaalde CVE-gegevens worden één uur per browsersessie gecachet (vink „Vers ophalen” aan om die te omzeilen). Met „Velden wissen” keer je terug naar de standaardwaarden.",
    "kop.cvegegevens": "CVE-gegevens <span class=\"hint\">(NVD API 2.0 — controleer en bewerk waar nodig; de beschrijving is bewerkbaar en de wijziging komt direct in de advisory)</span>",
    "kop.resultaat": "Resultaat",
    "tab.preview": "Rendered",
    "tab.markdown": "Markdown",
    "knop.regen": "Opnieuw genereren uit velden",
    "knop.regen.title": "Bouw de tekst opnieuw uit de ingevulde velden en verwerp handmatige bewerkingen",
    "label.gesch": "Geschiedenis:",
    "label.gesch.title": "De laatste 8 gegenereerde advisory's in deze browser; herstel bevat ook de briefvelden van dat moment",
    "opt.leeg": "(leeg)",
    "hist-label.ph": "eigen naam van deze regel",
    "hist-label.aria": "Eigen naam voor de geselecteerde geschiedenisregel",
    "hist-label.title": "Geef de geselecteerde geschiedenisregel een eigen naam (bijv. ‘Testomgeving maart’). Enter of klik ernaast bewaart; leeg laten maakt de regel weer naamloos.",
    "knop.histdel": "Wis item",
    "knop.histdel.title": "Verwijder het geselecteerde geschiedenisitem",
    "knop.histclear": "Wis alles",
    "knop.histclear.title": "Wis de volledige geschiedenislijst (het laatste resultaat voor staatsherstel blijft apart bewaard)",
    "raw.aria": "Advisorytekst in Markdown, handmatig bewerkbaar",
    "raw.title": "Handmatig bewerkbaar; veldwijzigingen bouwen de tekst daarna niet meer over (knop 'Opnieuw genereren uit velden')",
    "footer": "Databronnen: <a href=\"https://nvd.nist.gov/developers/vulnerabilities\" target=\"_blank\">NVD API 2.0</a> · <a href=\"https://cveproject.github.io/docs/api\" target=\"_blank\">CVE Program API</a> · <a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog\" target=\"_blank\">CISA KEV</a> (actief misbruik) · <a href=\"https://api.first.org/data/v1/epss\" target=\"_blank\">FIRST EPSS</a> (exploitkans). Raadpleeg voor productinformatie de distributeurtrackers (Debian, Ubuntu, Red Hat, SUSE, Fedora, Amazon Linux en Alpine; extra per-CVE-links zoals Rocky Linux en Arch Linux komen uit de NVD-referenties). PDF-export via <a href=\"https://github.com/parallax/jsPDF\" target=\"_blank\">jsPDF</a> en, voor de download met HTML-opmaak, <a href=\"https://html2canvas.hertzen.com/\" target=\"_blank\">html2canvas</a> (CDN's; de printdialoog blijft de terugval).",
    "knop.retry": "Probeer opnieuw",
    "knop.retry.title": "Haal alles opnieuw op: probeert uitgevallen bronnen en mislukte nummers opnieuw (geslaagde nummers komen uit de cache)",
    // ---- runtime: statusbalk, kaarten en geschiedenis ---------------------
    "reset.vraag": "Alle ingevulde velden wissen en terugkeren naar de standaardwaarden?",
    "disclaimer.geladen": "Disclaimer: geladen uit {bestand} ({aantal} tekens).",
    "disclaimer.standaard": "Disclaimer: ingebouwde standaardtekst. Plaats disclaimer.md in de projectmap voor eigen tekst (via http-server).",
    "status.afgewezen": "Afgewezen",
    "status.afgewezen.note": "Deze CVE is door de CNA afgewezen (rejected) — controleer of het juiste nummer is gebruikt.",
    "status.nogan": "Nog niet geanalyseerd",
    "status.nogan.note": "De NVD-analyse is nog niet gereed; de gegevens zijn (voorlopig) uitsluitend door de CNA aangeleverd.",
    "status.nvd-poging": "{id}: NVD niet bereikbaar/gevonden ({reden}) — CVE Program API proberen...",
    "stroom.geweigerd": "Stroomschema-URL geweigerd ({schema}) — alleen http(s), relatief of data:image toegestaan: {url}",
    "stroom.hersteld": "Stroomschema-URL weer geaccepteerd; het beeld staat weer in de advisory.",
    "status.opnieuw": "Advisory opnieuw gegenereerd uit de velden.",
    "hist.hersteld": "Advisory uit geschiedenis ({wie}{label}) hersteld, inclusief de veldwaarden van dat moment. Klik op „Ophalen & genereren” voor actuele gegevens.",
    "hist.leeg": "(leeg)",
    "hist.handmatig": "(handmatig)",
    "state.hersteld": "Laatste resultaat hersteld uit deze browser. Klik op „Ophalen & genereren” voor actuele data.",
    "kaart.geen-gegevens": "Geen gegevens",
    "kaart.mislukt": "Gegevens konden niet worden opgehaald (NVD en CVE Program API niet bereikbaar of onbekend nummer). Controleer het nummer en klik nogmaals op „Ophalen & genereren”.",
    "kaart.niet-beschikbaar": "Niet beschikbaar",
    "kaart.kev-onbekend": "KEV-status onbekend",
    "kaart.kev-actief": "KEV: actief misbruik",
    "kaart.sinds": "sinds",
    "kaart.poc": "Exploit (PoC) beschikbaar",
    "kaart.kev-geen": "KEV: geen actief misbruik",
    "kaart.desc-label": "Beschrijving van {id}, bewerkbaar",
    "kaart.desc-title": "Bewerkbaar: wijzigingen komen direct in de advisory",
    "kaart.publicatie": "Publicatie:",
    "kaart.producten": "Producten:",
    "kaart.geen-producten": "(geen productdata — controleer distributeur)",
    "kaart.cveprog": "NVD niet bereikbaar/gegevens onvolledig: data afkomstig van de CVE Program API (door de CNA aangeleverd).",
    "gen.ongeldig": "Voer minstens één geldig CVE-nummer in (formaat CVE-2026-123158).",
    "gen.niet-herkend": " Niet als CVE herkend: {lijst}.",
    "gen.onverwacht": "Genereren mislukt door een onverwachte fout: {reden}.",
    "gen.start.1": "Ophalen van {aantal} CVE ({net} op te halen{cache})...",
    "gen.start.n": "Ophalen van {aantal} CVE's ({net} op te halen{cache})...",
    "gen.cache-uit": ", {n} uit cache",
    "gen.voortgang": "Ophalen {id} — {i}/{n} voltooid...",
    "gen.mislukt": "Ophalen mislukt voor: {lijst}. Controleer de nummers en/of netwerktogang.",
    "gen.klaar-deel": "Klaar. {ok} CVE(s) verwerkt{cache}, {mis} mislukt ({lijst}); advisory voor zover mogelijk gegenereerd.",
    "gen.klaar": "Klaar. {ok} CVE(s) verwerkt{cache} en advisory gegenereerd.",
    "gen.cache-deel": ", {n} uit cache (vink \"Vers ophalen\" aan voor actuele data)",
    "gen.epss-uit": " EPSS niet beschikbaar (api.first.org).",
    "kopieer.gelukt": "Markdown gekopieerd naar klembord.",
    "kopieer.mislukt": "Kopiëren mislukt: klembord niet beschikbaar (de app vereist https of localhost).",
    "share.gelukt": "Deellink gekopieerd: {url}",
    "share.url": "Deellink: {url}",
    "hist.verwijderd": "Geschiedenisitem verwijderd.",
    "hist.gewist": "Geschiedenis gewist.",
    "hist.kies-eerst": "Kies eerst een geschiedenisregel: het labelveld geeft die regel een eigen naam.",
    "hist.niet-vinden": "Geschiedenisregel niet gevonden (intussen gewist?).",
    "hist.hernoemd": "Geschiedenisregel hernoemd naar “{naam}”.",
    "hist.naamloos": "Eigen naam verwijderd; de regel toont weer alleen het tijdstempel.",
    "pdf.jspdf-klaar": "PDF gedownload als PDF-bestand (jsPDF). Voor de printdialoog met alle opmaak: vink “PDF via printdialoog” aan.",
    "pdf.print-open-fout": "Printdialoog kon niet worden geopend; gebruik de browserprint (Ctrl/Cmd+P).",
    "pdf.print-geopend": "Printdialoog geopend — kies daar “Opslaan als PDF” / “Save as PDF”.",
    "pdf.h2c-ontbreekt": "html2canvas en/of jsPDF niet geladen (CDN traag of geblokkeerd); printdialoog als terugval.",
    "pdf.h2c-run": "PDF met opmaak samenstellen (preview fotograferen)...",
    "pdf.h2c-klaar": "PDF met opmaak gedownload (raster: tekst is niet selecteerbaar).",
    "pdf.h2c-fout": "html2canvas-export mislukt; printdialoog als terugval.",
  },
  en: {
    "paginatitel": "Advisory Writer — Security Advisories",
    "header.sub": "Generate security advisories — fill in only the CVE numbers; the text fields are optional.",
    "kop.invoer": "Input",
    "label.cve": "CVE numbers <span class=\"hint\">(one per line or comma-separated)</span>",
    "label.titel": "Advisory title <span class=\"hint\">(optional, generated automatically)</span>",
    "ph.titel": "Critical vulnerabilities in nginx",
    "label.ref": "Advisory number <span class=\"hint\">(optional)</span>",
    "label.datum": "Publication date/time",
    "label.prioriteit": "Priority <span class=\"hint\">(manual; auto = heaviest CVSS across all CVEs)</span>",
    "opt.pri.auto": "Automatic (based on CVSS)",
    "opt.pri.laag": "Low", "opt.pri.middel": "Medium", "opt.pri.hoog": "High", "opt.pri.kritiek": "Critical",
    "label.taal": "Description language <span class=\"hint\">(language of the fetched CVE descriptions; the letter itself stays Dutch)</span>",
    "taal.title": "Which description copy of the CVEs appears on the cards and in Technical Details; if the preferred language is missing it falls back to English and then to the first description",
    "opt.taal.auto": "Automatic (browser language)",
    "opt.taal.nl": "Dutch (where available)",
    "opt.taal.en": "English",
    "label.uitaal": "Interface language <span class=\"hint\">(language of the app; the advisory letter stays Dutch)</span>",
    "uitaal.title": "Language of the controls, status messages and CVE cards; the advisory and the CVE descriptions follow their own choices",
    "opt.uitaal.auto": "Automatic (browser language)",
    "opt.uitaal.nl": "Nederlands",
    "opt.uitaal.en": "English",
    "label.versie": "Advisory version <span class=\"hint\">(default 1.0; raise on a reissue, e.g. 1.1)</span>",
    "label.apikey": "NVD API key <span class=\"hint\">(optional; raises the NVD limit from 5 to 50 req/30 s)</span>",
    "ph.apikey": "free to request at nvd.nist.gov (required for many CVEs at once)",
    "summary.textvelden": "Letter text fields <span class=\"hint\">(salutation, announcement, impact, advice, addressees)</span>",
    "label.aanhef": "Salutation <span class=\"hint\">(optional, e.g. \"Dear colleague,\")</span>",
    "ph.aanhef": "Dear colleague,",
    "label.meldpunt": "Reporting point <span class=\"hint\">(for the centralisation paragraph)</span>",
    "ph.meldpunt": "CERT via cert@cert.nl",
    "label.opening": "Opening <span class=\"hint\">(optional paragraph before the title, e.g. \"Please give the message below your careful attention.\")</span>",
    "ph.opening": "Please give the urgent message below your careful attention.",
    "label.ankondiger": "Announced by <span class=\"hint\">(optional; otherwise vendor from NVD)</span>",
    "ph.ankondiger": "Xint and F5/nginx",
    "label.ankonddatum": "Announcement date <span class=\"hint\">(optional; otherwise publication date)</span>",
    "ph.ankonddatum": "18 November 2026",
    "label.bijnaam": "Nickname <span class=\"hint\">(optional, e.g. nginx2root)</span>",
    "ph.bijnaam": "sshhole",
    "label.impact": "Impact <span class=\"hint\">(free text; otherwise an auto-generated standard impact)</span>",
    "ph.impact": "A successful attack may lead to ...",
    "label.handel": "Own courses of action <span class=\"hint\">one per line; placed before the standard advice (e.g. internal systems, AKS, RSMAN)</span>",
    "ph.handel": "Amazon Kubernetes Service: patch this immediately.\nRSMAN\nBodyCam APIs",
    "label.stroom": "Flowchart <span class=\"hint\">(optional; image URL shown below the courses of action & advice, e.g. your own decision tree or process image)</span>",
    "label.gead": "Addressees <span class=\"hint\">(optional; becomes \"This mail was sent to: ...\")</span>",
    "ph.gead": "IT leads, IT managers, BISOs, TISOs, CTI and CSO",
    "vink.vers": "Fresh fetch (no cache)",
    "vink.vers.title": "Skip the stored CVE data (1 hour per browser session) and fetch everything from NVD again",
    "knop.ophalen": "Fetch & generate",
    "knop.kopieer": "Copy Markdown",
    "knop.download": "Download .md",
    "knop.pdf": "Export PDF",
    "knop.pdf.title": "Download the advisory as a PDF file (jsPDF); tick “PDF via print dialog” for the browser print dialog with all HTML formatting",
    "knop.pdfopmaak": "Formatted PDF",
    "knop.pdfopmaak.title": "Download the advisory as a PDF with all HTML formatting (table borders, badges and the flowchart image): html2canvas photographs the preview as a raster. Text is then not selectable; if the CDN is missing or drawing fails, the print dialog opens",
    "vink.print": "PDF via print dialog",
    "vink.print.title": "Generate the PDF via the browser print dialog instead of the built-in jsPDF download (e.g. to check the formatting first)",
    "knop.deellink": "Copy share link",
    "knop.deellink.title": "Copy a link with the filled-in CVEs (?cve=...); the recipient opens the app with immediate generation",
    "knop.wissen": "Clear fields",
    "knop.wissen.title": "Clear all filled-in fields and restore the defaults",
    "hint.geheugen": "Filled-in fields are remembered automatically in this browser (LocalStorage) and restored on the next visit; the last result is restored after reloading. Fetched CVE data is cached for one hour per browser session (tick “Fresh fetch” to bypass it). “Clear fields” returns you to the defaults.",
    "kop.cvegegevens": "CVE data <span class=\"hint\">(NVD API 2.0 — check and edit where needed; the description is editable and changes go straight into the advisory)</span>",
    "kop.resultaat": "Result",
    "tab.preview": "Rendered",
    "tab.markdown": "Markdown",
    "knop.regen": "Regenerate from fields",
    "knop.regen.title": "Rebuild the text from the filled-in fields and discard manual edits",
    "label.gesch": "History:",
    "label.gesch.title": "The last 8 generated advisories in this browser; restore also includes the letter fields of that moment",
    "opt.leeg": "(empty)",
    "hist-label.ph": "your own name for this entry",
    "hist-label.aria": "Own name for the selected history entry",
    "hist-label.title": "Give the selected history entry your own name (e.g. ‘Test environment March’). Enter or click away saves; leaving it empty makes the entry nameless again.",
    "knop.histdel": "Delete entry",
    "knop.histdel.title": "Delete the selected history entry",
    "knop.histclear": "Clear all",
    "knop.histclear.title": "Clear the entire history list (the last result for state restore is kept separately)",
    "raw.aria": "Advisory text in Markdown, manually editable",
    "raw.title": "Manually editable; field changes no longer rebuild the text afterwards (button 'Regenerate from fields')",
    "footer": "Data sources: <a href=\"https://nvd.nist.gov/developers/vulnerabilities\" target=\"_blank\">NVD API 2.0</a> · <a href=\"https://cveproject.github.io/docs/api\" target=\"_blank\">CVE Program API</a> · <a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog\" target=\"_blank\">CISA KEV</a> (active exploitation) · <a href=\"https://api.first.org/data/v1/epss\" target=\"_blank\">FIRST EPSS</a> (exploit probability). For product information consult the distributor trackers (Debian, Ubuntu, Red Hat, SUSE, Fedora, Amazon Linux and Alpine; additional per-CVE links such as Rocky Linux and Arch Linux come from the NVD references). PDF export via <a href=\"https://github.com/parallax/jsPDF\" target=\"_blank\">jsPDF</a> and, for the download with HTML formatting, <a href=\"https://html2canvas.hertzen.com/\" target=\"_blank\">html2canvas</a> (CDNs; the print dialog remains the fallback).",
    "knop.retry": "Try again",
    "knop.retry.title": "Fetch everything again: retries failed sources and failed numbers (successful numbers come from the cache)",
    // ---- runtime: statusbalk, kaarten en geschiedenis ---------------------
    "reset.vraag": "Clear all filled-in fields and return to the defaults?",
    "disclaimer.geladen": "Disclaimer: loaded from {bestand} ({aantal} characters).",
    "disclaimer.standaard": "Disclaimer: built-in standard text. Place disclaimer.md in the project folder for your own text (via http-server).",
    "status.afgewezen": "Rejected",
    "status.afgewezen.note": "This CVE was rejected by the CNA — check that the right number was used.",
    "status.nogan": "Not yet analysed",
    "status.nogan.note": "The NVD analysis is not ready yet; the data was (provisionally) supplied only by the CNA.",
    "status.nvd-poging": "{id}: NVD unreachable/not found ({reden}) — trying the CVE Program API...",
    "stroom.geweigerd": "Flowchart URL rejected ({schema}) — only http(s), relative or data:image allowed: {url}",
    "stroom.hersteld": "Flowchart URL accepted again; the image is back in the advisory.",
    "status.opnieuw": "Advisory regenerated from the fields.",
    "hist.hersteld": "Advisory restored from history ({wie}{label}), including the field values of that moment. Click “Fetch & generate” for current data.",
    "hist.leeg": "(empty)",
    "hist.handmatig": "(manual)",
    "state.hersteld": "Last result restored from this browser. Click “Fetch & generate” for current data.",
    "kaart.geen-gegevens": "No data",
    "kaart.mislukt": "Data could not be fetched (NVD and CVE Program API unreachable or unknown number). Check the number and click “Fetch & generate” again.",
    "kaart.niet-beschikbaar": "Not available",
    "kaart.kev-onbekend": "KEV status unknown",
    "kaart.kev-actief": "KEV: actively exploited",
    "kaart.sinds": "since",
    "kaart.poc": "Exploit (PoC) available",
    "kaart.kev-geen": "KEV: no active exploitation",
    "kaart.desc-label": "Description of {id}, editable",
    "kaart.desc-title": "Editable: changes go straight into the advisory",
    "kaart.publicatie": "Publication:",
    "kaart.producten": "Products:",
    "kaart.geen-producten": "(no product data — check distributor)",
    "kaart.cveprog": "NVD unreachable/data incomplete: data from the CVE Program API (supplied by the CNA).",
    "gen.ongeldig": "Enter at least one valid CVE number (format CVE-2026-123158).",
    "gen.niet-herkend": " Not recognised as CVE: {lijst}.",
    "gen.onverwacht": "Generation failed due to an unexpected error: {reden}.",
    "gen.start.1": "Fetching {aantal} CVE ({net} to fetch{cache})...",
    "gen.start.n": "Fetching {aantal} CVEs ({net} to fetch{cache})...",
    "gen.cache-uit": ", {n} from cache",
    "gen.voortgang": "Fetching {id} — {i}/{n} done...",
    "gen.mislukt": "Fetch failed for: {lijst}. Check the numbers and/or network access.",
    "gen.klaar-deel": "Done. {ok} CVE(s) processed{cache}, {mis} failed ({lijst}); advisory generated as far as possible.",
    "gen.klaar": "Done. {ok} CVE(s) processed{cache}, advisory generated.",
    "gen.cache-deel": ", {n} from cache (tick “Fresh fetch” for current data)",
    "gen.epss-uit": " EPSS unavailable (api.first.org).",
    "kopieer.gelukt": "Markdown copied to clipboard.",
    "kopieer.mislukt": "Copy failed: clipboard unavailable (the app requires https or localhost).",
    "share.gelukt": "Share link copied: {url}",
    "share.url": "Share link: {url}",
    "hist.verwijderd": "History entry deleted.",
    "hist.gewist": "History cleared.",
    "hist.kies-eerst": "Select a history entry first: the label field gives that entry a name.",
    "hist.niet-vinden": "History entry not found (deleted in the meantime?).",
    "hist.hernoemd": "History entry renamed to “{naam}”.",
    "hist.naamloos": "Own name removed; the entry shows only the timestamp again.",
    "pdf.jspdf-klaar": "PDF downloaded as a PDF file (jsPDF). For the print dialog with all formatting: tick “PDF via print dialog”.",
    "pdf.print-open-fout": "Print dialog could not be opened; use the browser print (Ctrl/Cmd+P).",
    "pdf.print-geopend": "Print dialog opened — choose “Save as PDF” there.",
    "pdf.h2c-ontbreekt": "html2canvas and/or jsPDF not loaded (CDN slow or blocked); print dialog as fallback.",
    "pdf.h2c-run": "Composing formatted PDF (photographing the preview)...",
    "pdf.h2c-klaar": "Formatted PDF downloaded (raster: text is not selectable).",
    "pdf.h2c-fout": "html2canvas export failed; print dialog as fallback.",
  },
};

const STORAGE_KEY = "advisory-writer:velden-v1";
const MEMORIZED_FIELDS = [
  "cve-input", "advisory-title", "advisory-ref", "pub-date", "prioriteit-select", "taal-select",
  "ui-taal",
  "aanhef", "meldpunt", "opening", "aankondiger", "aankondiging-datum", "bijnaam",
  "impact", "handelingsperspectieven", "stroomschema", "geadresseerden", "advisory-versie", "nvd-apikey",
  "no-cache", "pdf-print",
];
const DETAILS_KEY = "__optiesOpen";

// In-memory kopie van het veldgeheugen (fix 6): saveField deed voorheen per
// toetsaanslag een volledige lees-parseer-voeg-schrijf-cyclus. De cache houdt
// de data in het geheugen; per wijziging is alleen nog een setItem nodig en
// de JSON wordt één keer per paginalaad geparseerd. Write-through blijft:
// élke wijziging belandt nog direct in localStorage, de cache pakt alleen
// het herhaaldelijk herlezen en -parsen weg.
let veldenCache = null;
function veldenLezen() {
  if (veldenCache) return veldenCache;
  try { veldenCache = JSON.parse(localStorage.getItem(STORAGE_KEY)) || {}; }
  catch { veldenCache = {}; } // privémodus/blokkeercookie: werken zonder onthouden
  return veldenCache;
}

function veldenSchrijven() {
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(veldenLezen())); } catch { /* geen persistentie */ }
}

function saveField(el) {
  const data = veldenLezen();
  data[el.id] = el.type === "checkbox" ? el.checked : el.value; // checkbox: .checked, niet .value ("on")
  veldenSchrijven();
}

function restoreFields() {
  const data = veldenLezen();
  for (const id of MEMORIZED_FIELDS) {
    const el = document.getElementById(id);
    if (!el || !Object.prototype.hasOwnProperty.call(data, id)) continue;
    if (el.type === "checkbox") el.checked = !!data[id];
    else el.value = data[id];
  }
  const detailsEl = document.querySelector("details.options");
  if (detailsEl && data[DETAILS_KEY] === true) detailsEl.open = true;
}

function initFieldMemory() {
  restoreFields();
  for (const id of MEMORIZED_FIELDS) {
    const el = document.getElementById(id);
    if (!el) continue;
    el.addEventListener("input", () => { saveField(el); queueRefresh(); });
    el.addEventListener("change", () => { saveField(el); queueRefresh(); });
  }
  const detailsEl = document.querySelector("details.options");
  if (detailsEl) {
    detailsEl.addEventListener("toggle", () => {
      veldenLezen()[DETAILS_KEY] = detailsEl.open;
      veldenSchrijven();
    });
  }
  const resetBtn = $("#reset-btn");
  if (resetBtn) {
    resetBtn.addEventListener("click", () => {
      if (!confirm(T("reset.vraag"))) return;
      try { localStorage.removeItem(STORAGE_KEY); } catch { /* leeg al */ }
      veldenCache = null; // de in-memory kop moet meewissen (fix 6)
      clearCveCache(); // ook de CVE-fetchcache leeg: wissen = écht opnieuw
      clearEpssCache(); // idem voor de EPSS-cache
      location.reload();
    });
  }
}

// ---------- Disclaimer (extern bestand of ingebouwde standaard) ----------
// Plaats een bestand 'disclaimer.md' (of 'disclaimer.txt') in de projectmap;
// de inhoud wordt dan als disclaimertekst in de advisory gebruikt.
// Let op: laden via fetch() vereist server via http(s) (bijv. python3 -m http.server).

const DISCLAIMER_FILES = ["disclaimer.md", "disclaimer.txt"];
const DEFAULT_DISCLAIMER =
  "*Deze advisory is opgesteld op basis van openbare informatie (NVD en het CVE Program). " +
  "Aan de inhoud kunnen geen rechten worden ontleend. Controleer voor de op jouw omgeving " +
  "toegesnedene pakketversies de informatie van de betreffende leverancier of distributeur.*";

let disclaimerText = null; // null = ingebouwde standaard

async function loadDisclaimer() {
  for (const fname of DISCLAIMER_FILES) {
    try {
      const res = await fetch(`./${fname}`, { cache: "no-store" });
      if (res.ok) {
        const text = (await res.text()).trim();
        if (text) {
          disclaimerText = text;
          if (disclaimerStatusEl)
            disclaimerStatusEl.textContent = T("disclaimer.geladen", { bestand: "`" + fname + "`", aantal: text.length });
          return true;
        }
      }
    } catch (e) {
      // bestand niet beschikbaar of fetch geblokkeerd (file://) — probeer volgende
    }
  }
  disclaimerText = null;
  if (disclaimerStatusEl)
    disclaimerStatusEl.textContent = T("disclaimer.standaard");
  return false;
}

// ---------- CISA KEV (Known Exploited Vulnerabilities) en SSVC ----------
// De misbruikstatus komt primair uit de NVD-respons zelf: velden
// cisaExploitAdd/cisaActionDue (KEV-opname) en metrics.ssvcV* (SSVC van de
// CISA-ADP). De KEV-feed (meerdere MB) is terugval voor CVE's zonder die
// velden en wordt alleen dan opgehaald. Is de feed niet bereikbaar, dan valt
// de KEV-status netjes weg ("status onbekend") en werkt de rest door.

const KEV_FEED_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

let kevMap = null;    // cveID -> KEV-entry; null = nog niet geladen / niet beschikbaar
// Een uitval is géén sessielijm meer: na een afkoelperiode van KEV_RETRY_MS
// wordt de volgende keer wéér geprobeerd. Zonder die cooldown kon één
// hiccup bij CISA (of één harde timeout van 30 s) de KEV-regel de rest van
// het paginabezoek laten missen, ook bij genereren tien minuten later. De
// cooldown wordt lui gecontroleerd bij binnenkomst van loadKev: verlopen,
// dan wordt kevFailed gereset en volgt een gewone poging; de AbortError van
// een afgebroken verzoek telt nog steeds nooit als uitval.
let kevFailed = false;
let kevFailedAt = 0;
const KEV_RETRY_MS = 5 * 60 * 1000;

// De KEV-feed is meerdere MB; de (compacte) lijst wordt daarom één uur in
// sessionStorage gecachet, zodat een herladen pagina de feed niet opnieuw
// hoeft op te halen. Bij een volle of geblokkeerde cache valt alles terug
// op gedrag als voorheen (netjes, zonder foutmelding).
const KEV_CACHE_KEY = "advisory-writer:kev-v1";
const KEV_TTL_MS = 60 * 60 * 1000;

function kevCacheLoad() {
  try {
    const s = JSON.parse(sessionStorage.getItem(KEV_CACHE_KEY));
    if (s && Array.isArray(s.entries) && Date.now() - s.ts < KEV_TTL_MS) {
      kevMap = new Map(s.entries);
      return true;
    }
  } catch { /* geen/blokkeerde cache (privémodus, file://): opnieuw ophalen */ }
  return false;
}

function kevCacheSave() {
  try {
    // compact opslaan: alleen ID en datum; de volledige feed zou de
    // sessionStorage-quota (meestal 5 MB) onnodig belasten
    const entries = [...kevMap].map(([id, v]) => [id, { cveID: id, dateAdded: v.dateAdded }]);
    sessionStorage.setItem(KEV_CACHE_KEY, JSON.stringify({ ts: Date.now(), entries }));
  } catch { /* quota bereikt: cachen overgeslagen */ }
}

// Het optionele signaal maakt het verzoek afbreekbaar (zie achtergrondRun):
// start de gebruiker een nieuwe generatie terwijl dit verzoek loopt, dan is
// de opbouw achterhaald en wordt de download gekapt. Afbreken is géén uitval:
// kevFailed blijft uit en de volgende beurt probeert het gewoon opnieuw.
async function loadKev(signaal) {
  if (kevFailed && Date.now() - kevFailedAt >= KEV_RETRY_MS) kevFailed = false; // cooldown verlopen
  if (kevMap || kevFailed) return;
  if (kevCacheLoad()) return;      // verse cache uit deze browsersessie
  try {
    const data = await fetchJson(KEV_FEED_URL, { tries: 1, signal: signaal });
    if (Array.isArray(data.vulnerabilities)) {
      kevMap = new Map(data.vulnerabilities.map((v) => [v.cveID, v]));
      kevCacheSave();
    } else {
      kevFailed = true;
      kevFailedAt = Date.now();
    }
  } catch (e) {
    if (e.name === "AbortError") return; // afgebroken door een nieuwe generatie
    kevFailed = true; // feed niet bereikbaar: KEV-regel valt weg (tot de cooldown)
    kevFailedAt = Date.now();
  }
}

// SSVC (Stakeholder-Specific Vulnerability Categorization, CISA) wordt door
// de NVD aangeleverd als metrics.ssvcV203: exploitatiegraad, automatability
// en technische impact. De opties staan als [{ optie: waarde }, ...].
function parseSsvc(cve) {
  const m = cve.metrics || {};
  const key = Object.keys(m).find((k) => k.toLowerCase().startsWith("ssvc"));
  const data = key ? m[key]?.[0]?.ssvcData : null;
  if (!data) return null;
  const get = (optie) => (data.options || []).reduce((acc, o) => (optie in o ? o[optie] : acc), null);
  return {
    exploitatie: get("exploitation"),
    automatable: get("automatable"),
    technicalImpact: get("technicalImpact"),
  };
}

// KEV-/misbruikstatus per CVE. Eerst de gegevens die NVD zelf aanlevert
// (cisaExploitAdd/cisaActionDue en de SSVC-metrics van de CISA-ADP); pas
// daarna de KEV-feed als terugval. Retourneert null als géén bron iets weet.
function kevInfo(cve) {
  if (cve.cisaExploitAdd) {
    return { actief: true, sinds: cve.cisaExploitAdd, actiefrist: cve.cisaActionDue || null, bron: "CISA KEV" };
  }
  const ssvc = parseSsvc(cve);
  if (ssvc?.exploitatie === "active") return { actief: true, sinds: null, actiefrist: null, bron: "SSVC (CISA)" };
  if (ssvc && (ssvc.exploitatie === "poc" || ssvc.exploitatie === "public_exploited")) {
    return { actief: false, poc: true, bron: "SSVC (CISA)" };
  }
  if (ssvc?.exploitatie === "none") return { actief: false, poc: false, bron: "SSVC (CISA)" };
  const kev = kevMap?.get(cve.id);
  if (kev) return { actief: true, sinds: kev.dateAdded, actiefrist: null, bron: "CISA KEV" };
  if (kevMap) return { actief: false, poc: false, bron: "CISA KEV" };
  return null;
}

// Regeltekst voor in de advisory; null = geen bron beschikbaar, regel valt weg.
function kevStatusText(cve) {
  if (cve._fetchFailed) return null; // geen gegevens: geen misbruikclaim doen
  const info = kevInfo(cve);
  if (!info) return null;
  if (info.actief) {
    const sinds = info.sinds ? `sinds ${nlDate(info.sinds) || info.sinds}` : "gemeld";
    const termijn = info.actiefrist ? `, actiefrist ${nlDate(info.actiefrist) || info.actiefrist}` : "";
    return `Er is actief misbruik gemeld in de CISA KEV-catalogus (${info.bron}, ${sinds}${termijn}).`;
  }
  if (info.poc) return "Er is een exploit (proof of concept) beschikbaar, maar nog geen bevestigd actief misbruik (SSVC).";
  return `Er is geen actief misbruik gemeld (${info.bron}).`;
}

// ---------- EPSS (exploitkans, FIRST) --------------------------------------
// EPSS (Exploit Prediction Scoring System) voorspelt de kans dat een CVE in
// de komende 30 dagen daadwerkelijk misbruikt wordt (0-1, met percentiel).
// Bron: de API van FIRST (https://api.first.org/data/v1/epss?cve=...), één
// gebundeld verzoek per beurt (comma-gescheiden lijst, CORS-enabled, zonder
// API-sleutel). De scores worden dagelijks ververst, dus de resultaten
// worden 24 uur in sessionStorage bewaard. Lukt het ophalen niet, dan valt
// de EPSS-regel weg (als bij de KEV-feed) en meldt alleen de statusbalk
// eenmalig dat EPSS niet beschikbaar is; de rest van de app werkt door.

const EPSS_URL = "https://api.first.org/data/v1/epss";
const EPSS_CACHE_KEY = "advisory-writer:epss-v1";
const EPSS_TTL_MS = 24 * 60 * 60 * 1000;

// { id: { score, percentile } }, ook voor "bekend, niet in model"
// ({ score: null }), zodat zoiets niet elke beurt opnieuw wordt opgevraagd.
let epssScores = null;  // null = nog niet uit sessionStorage gelezen
// Zelfde afkoelperiode als bij de KEV-feed: een uitval (of één harde
// timeout) kost de EPSS-regel vijf minuten, niet de hele browsersessie.
let epssFailed = false;
let epssFailedAt = 0;
const EPSS_RETRY_MS = 5 * 60 * 1000;

function epssLezen() {
  if (epssScores) return epssScores;
  try {
    const s = JSON.parse(sessionStorage.getItem(EPSS_CACHE_KEY));
    epssScores = s && s.scores && Date.now() - s.ts < EPSS_TTL_MS ? s.scores : {};
  } catch { epssScores = {}; } // geen/blokkeerde cache: werken zonder
  return epssScores;
}

function epssSchrijven() {
  try {
    sessionStorage.setItem(EPSS_CACHE_KEY, JSON.stringify({ ts: Date.now(), scores: epssScores || {} }));
  } catch { /* quota: cache werkt nog in het geheugen, alleen niet meer na herladen */ }
}

function clearEpssCache() {
  epssScores = null;
  epssFailed = false;
  try { sessionStorage.removeItem(EPSS_CACHE_KEY); } catch { /* al leeg */ }
}

// first.org-respons omzetten naar { id: { score, percentile, date } }.
// De live-API levert een array: data: [{ cve, epss, percentile, date }]
// (geverifieerd 22-11-2026); de objectvorm ({ "CVE-...": "0.97" } met los
// percentile-blok) zoals sommige documentatie toont, blijft als tweede tak
// ondersteund. Niet-numerieke scores worden overgeslagen en een ontbrekend
// percentiel wordt null (nooit een gok). Niet-aangeleverde CVE's komen niet
// in de uitkomst voor; laadEpss markeert die als "niet in model".
function epssUitRespons(data) {
  const out = {};
  const d = data && data.data;
  if (Array.isArray(d)) {
    for (const e of d) {
      const id = String((e && e.cve) || "").toUpperCase();
      const score = Number(e && e.epss);
      if (!id || !isFinite(score)) continue;
      const pct = Number(e.percentile);
      out[id] = { score, percentile: isFinite(pct) ? pct : null, date: e.date || null };
    }
    return out;
  }
  if (d && typeof d === "object") {
    for (const [id, rauw] of Object.entries(d)) {
      const score = Number(rauw);
      if (!isFinite(score)) continue; // API gaf iets anders dan een getal
      const pct = Number(data.percentile && data.percentile[id]);
      out[id] = { score, percentile: isFinite(pct) ? pct : null, date: null };
    }
  }
  return out;
}

// EPSS voor de gegeven CVE's: wat de 24-u-cache kent (inclusief "bekend,
// niet in model") gaat niet meer mee in het verzoek; de open nummers komen
// in één gebundelde call. Het vink "Vers ophalen" geldt hier ook: dan worden
// alle nummers opnieuw opgevraagd en de cache overschreven.
async function laadEpss(ids, signaal) {
  if (epssFailed && Date.now() - epssFailedAt >= EPSS_RETRY_MS) epssFailed = false; // cooldown verlopen
  const cache = epssLezen();
  const vers = typeof noCacheInput !== "undefined" && noCacheInput && noCacheInput.checked;
  const open = [...new Set(ids)].filter((id) => vers || !cache[id]);
  if (!open.length || epssFailed) return;
  try {
    // CVE-nummers bevatten alleen URL-veilige tekens; samenvoegen mag kaal.
    const data = await fetchJson(`${EPSS_URL}?cve=${open.join(",")}`, { tries: 2, signal: signaal });
    const nieuw = epssUitRespons(data);
    for (const id of open) cache[id] = nieuw[id] || { score: null };
    epssSchrijven();
  } catch (e) {
    if (e.name === "AbortError") return; // afgebroken: geen uitval, volgende beurt opnieuw
    epssFailed = true; // regel en badge vallen weg; status meldt het eenmalig
    epssFailedAt = Date.now();
  }
}

// EPSS-gegevens voor dit CVE, of null (onbekend, niet in model of mislukt).
function epssInfo(cve) {
  const e = epssLezen()[cve.id];
  return e && e.score != null ? e : null;
}

// Regel voor Technische Details; null laat de regel weg vallen. Nederlandse
// decimale komma; het percentiel (0-1) getoond als percentage (0,995 → 99,5e).
function epssRegelTekst(cve) {
  if (cve._fetchFailed) return null; // geen gegevens: geen kansclaim doen
  const e = epssInfo(cve);
  if (!e) return null;
  const dec = (x) => String(x).replace(".", ",");
  const pct = e.percentile != null
    ? ` (${dec(Math.round(e.percentile * 1000) / 10)}e percentiel)`
    : "";
  // De modeldatum uit de respons erbij (in het Nederlands via nlDate): de
  // EPSS-cache is maximaal 24 uur oud, dus dit is nagenoeg altijd de meest
  // recente run van het model; een respons zonder datum laat het stukje weg.
  const model = e.date ? `, model ${nlDate(e.date) || e.date}` : "";
  return `EPSS-inschatting: ${dec(e.score)}${pct} \u2014 kans op misbruik in de komende 30 dagen (FIRST EPSS${model}).`;
}

// ---------- Helpers ----------

// De statusbalk is een aria-live-region (zie index.html): schermlezers
// lezen wijzigingen voor. Tijdens genereren komen meldingen in bursts
// (start, één per voltooid CVE, afloop) - onthinderd zou een schermlezer
// élke melding volledig voorlezen. Tijdens de burst wordt de regio daarom
// als busy gemarkeerd (aria-busy); schermlezers slaan updates dan over en
// na 400 ms meldingsstilte valt de vlag weg, zodat de definitieve melding
// wéér wordt voorgelezen (fix 6).
let statusBusyTimer = null;
// Laatste melding onthouden voor de taalwissel: meldingen die via een
// woordenboeksleutel zijn gezet (statusT) kunnen bij een wissel van
// interfacetaal in de nieuwe taal worden herschreven (herhaalStatus);
// samengestelde meldingen (meerdere stukken in één setStatus) blijven in
// de taal waarin ze zijn begonnen.
let statusLaatste = { msg: "", isError: false, sleutel: null, vervangers: null };
function setStatus(msg, isError = false, sleutel = null, vervangers = null) {
  statusLaatste = { msg, isError, sleutel, vervangers };
  statusEl.textContent = msg;
  statusEl.style.color = isError ? "#f87171" : "";
  statusEl.setAttribute("aria-busy", "true");
  clearTimeout(statusBusyTimer);
  statusBusyTimer = setTimeout(() => statusEl.removeAttribute("aria-busy"), 400);
}
function statusT(sleutel, vervangers, isError = false) {
  setStatus(T(sleutel, vervangers), isError, sleutel, vervangers);
}
function herhaalStatus() {
  const s = statusLaatste;
  if (s.sleutel) statusT(s.sleutel, s.vervangers, s.isError);
  else if (s.msg) setStatus(s.msg, s.isError);
}

// Maak een token uit het CVE-veld gelijkvormig: leestekens aan de rand af-
// kappen (geplakte "CVE-2026-123158." of een lijststreepje "-CVE-..." worden
// hierdoor alsnog herkend) en naar hoofdletters zetten.
function cleanCveToken(raw) {
  return raw.trim().replace(/^[^\w]+/, "").replace(/[^\w]+$/, "").toUpperCase();
}

// Geldige CVE-nummers uit de invoer, in volgorde van eerste verschijning en
// zonder duplicaten: hetzelfde nummer twee keer ophalen gaf twee kaarten en
// twee rijen in de CVSS-tabel.
function parseCveList(text) {
  return [...new Set(
    text.split(/[\s,;]+/).map(cleanCveToken).filter((s) => /^CVE-\d{4}-\d{4,}$/.test(s))
  )];
}

// Tokens die vermoedelijk als CVE bedoeld zijn maar het formaat niet matchen
// (typos als "2026-99999" of "CVE2026-1"), zodat die expliciet gemeld worden
// in plaats van stilzwijgend genegeerd. Ruis zonder cijfers ("en",
// "(OpenSSH)") is nooit een bedoeld CVE-nummer en wordt níet gemeld.
function discardedCveTokens(text) {
  const ids = new Set(parseCveList(text));
  return [...new Set(
    text
      .split(/[\s,;]+/)
      .map(cleanCveToken)
      .filter((t) => t && /\d/.test(t) && !ids.has(t))
  )];
}

// NVD-limiet zonder API-sleutel: 5 verzoeken per 30 s (rollend venster). Bij
// meer dan 5 NETWERK-ophaalacties wordt de stap automatisch groter (cachede
// CVE's tellen niet mee): requests met 6,5 s tussenruimte starten op 0, 6,5,
// 13, 19,5, 26 en 32,5 s, zodat op elk moment maximaal vijf verzoeken binnen
// het venster van 30 s liggen.
function nvdStapMs(aantalCves, heeftSleutel) {
  return !heeftSleutel && aantalCves > 5 ? 6500 : 1200;
}

// Datum/tijd in de tijdzone van de lezer (Europe/Amsterdam), niet die van de
// machine: daar stond het label "(Europe/Amsterdam)" tot nu toe bij, terwijl
// de waarden van de systeemtijdzone kwamen. Intl zet ze nu expliciet om
// (hourCycle h23, zodat het uur nooit als "24" terugkomt).
function nowNl() {
  const parts = new Intl.DateTimeFormat("nl-NL", {
    timeZone: "Europe/Amsterdam", hourCycle: "h23",
    day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit",
  }).formatToParts(new Date());
  const g = (t) => parts.find((p) => p.type === t).value;
  return `${g("day")}-${g("month")}-${g("year")} ${g("hour")}:${g("minute")} (Europe/Amsterdam)`;
}

const NL_MONTHS = ["januari", "februari", "maart", "april", "mei", "juni",
  "juli", "augustus", "september", "oktober", "november", "december"];

// Zet "05-11-2026 16:30 (...)" om naar "5 november 2026" voor de aankondigingszin.
function nlDate(dateStr) {
  const m = (dateStr || "").match(/(\d{1,2})-(\d{1,2})-(\d{4})/);
  if (m) return `${+m[1]} ${NL_MONTHS[+m[2] - 1]} ${m[3]}`;
  const d = new Date(dateStr);
  if (!isNaN(d)) return d.toLocaleDateString("nl-NL", { day: "numeric", month: "long", year: "numeric" });
  return null;
}

const SEVERITY_MAP = {
  LOW: { prioriteit: "Laag", badge: "low" },
  MEDIUM: { prioriteit: "Middel", badge: "medium" },
  HIGH: { prioriteit: "Hoog", badge: "high" },
  CRITICAL: { prioriteit: "Kritiek", badge: "critical" },
};

function mapSeverity(sev) {
  return SEVERITY_MAP[(sev || "").toUpperCase()] || { prioriteit: "Onbekend", badge: "unknown" };
}

// Ernstlabel op de kaart in de actieve interface-taal. De brief gebruikt
// altijd mapSeverity().prioriteit (Nederlands); de kaart volgt de taal-
// keuze van de bediening.
const ERNT_EN = { Laag: "Low", Middel: "Medium", Hoog: "High", Kritiek: "Critical", Onbekend: "Unknown" };
function ernstLabel(sev) {
  const p = mapSeverity(sev).prioriteit;
  return uiTaal() === "en" ? (ERNT_EN[p] || p) : p;
}

// De enige HTML-escape van de app (fix 6): ook mdToHtml gebruikt deze
// helper (via esc), zodat er geen tweede, lichtere variant meer is die
// stilzwijgend kan afwijken. De extra " ten opzichte van de oude interne
// esc van mdToHtml is daar winst: de preview-renderer zet tekst in HTML.
const escHtml = (s) => String(s)
  .replace(/&/g, "&amp;").replace(/</g, "&lt;")
  .replace(/>/g, "&gt;").replace(/"/g, "&quot;");

// JSON-replacer die de _cached-markering uit de browseropslag houdt: die vlag
// zegt alleen tijdens de huidige generatiebeurt iets (wel/niet uit de
// CVE-fetchcache) en is in een opgeslagen staat of geschiedenisitem
// betekenisloos. De vergelijkbare _descEdit-markering blijft wél mee: een
// handmatig bewerkte beschrijving moet na herstel exact zo terugkomen als de
// gebruiker hem maakte (en "Opnieuw genereren uit velden" mag die correctie
// niet verliezen).
const jsonZonderCacheVlag = (key, value) => (key === "_cached" ? undefined : value);

// Zwaarste ernst over alle opgehaalde CVE's (bepaalt de automatische prioriteit;
// voorheen werd alleen het eerste CVE gebruikt).
const SEV_ORDER = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

function maxSeverity(list) {
  let best = "UNKNOWN";
  let n = 0;
  for (const c of list) {
    const s = String(overallSeverity(c).severity || "").toUpperCase();
    if ((SEV_ORDER[s] || 0) > n) { n = SEV_ORDER[s]; best = s; }
  }
  return best;
}

// Verwerkingsstatus van de CVE (NVD `vulnStatus` / CVE Program `state`).
// Levert { label, note } op voor afwijkende statussen, anders null.
function cveStatus(cve) {
  const st = String(cve.vulnStatus || cve._state || "").toLowerCase();
  if (st === "rejected") {
    return { label: T("status.afgewezen"), note: T("status.afgewezen.note") };
  }
  if (st === "received" || st === "awaiting analysis") {
    return { label: T("status.nogan"), note: T("status.nogan.note") };
  }
  return null;
}

function collectCvss(cve) {
  // metrics may be an object keyed by type (NVD API 2.0) or an array (legacy)
  const out = [];
  const push = (arr, version) => {
    for (const d of arr || []) out.push({ ...d, _version: version });
  };
  const m = cve.metrics;
  if (Array.isArray(m)) {
    for (const entry of m) {
      push(entry.cvssMetricV40, "4.0");
      push(entry.cvssMetricV31, "3.1");
      push(entry.cvssMetricV30, "3.0");
      push(entry.cvssMetricV2, "2.0");
    }
  } else if (m && typeof m === "object") {
    push(m.cvssMetricV40, "4.0");
    push(m.cvssMetricV31, "3.1");
    push(m.cvssMetricV30, "3.0");
    push(m.cvssMetricV2, "2.0");
  }
  return out;
}

function overallSeverity(cve) {
  // NVD API 2.0 places severity in cvssData.baseSeverity (not metric.severity).
  // Prefer the Primary metric (NVD analysis); fall back to Secondary (CNA),
  // which is the only metric available for recently-published CVEs.
  const metrics = collectCvss(cve).filter((d) => d.cvssData?.baseScore != null);
  const chosen = metrics.find((d) => d.type === "Primary") || metrics[0];
  if (chosen) {
    return {
      severity: chosen.cvssData.baseSeverity || chosen.severity || "UNKNOWN",
      score: chosen.cvssData.baseScore,
      vector: chosen.cvssData.vectorString,
      version: chosen._version,
      type: chosen.type,
      source: chosen.source,
    };
  }
  return { severity: "UNKNOWN" };
}

// --- CVSS per familie (v4.0 en v3.1 los) ---------------------------------
// Kiest binnen een CVSS-versie de Primary (NVD) metric, anders Secondary (CNA).
function pickMetric(cve, version) {
  const metrics = collectCvss(cve).filter((d) => d._version === version && d.cvssData?.baseScore != null);
  const chosen = metrics.find((d) => d.type === "Primary") || metrics[0];
  if (!chosen) return null;
  return {
    score: chosen.cvssData.baseScore,
    severity: chosen.cvssData.baseSeverity || chosen.severity || "UNKNOWN",
    vector: chosen.cvssData.vectorString,
    version,
    type: chosen.type,
    source: chosen.source,
  };
}

// Levert per CVSS-familie de gekozen metric; ontbrekend = null. v3.0 en v2.0
// worden ook meegenomen: oudere CVE's hebben vaak alleen die versies en
// toonden dan twee keer "Niet beschikbaar" terwijl er wél een score is.
function cvssByFamily(cve) {
  return {
    v4: pickMetric(cve, "4.0"),
    v31: pickMetric(cve, "3.1"),
    v30: pickMetric(cve, "3.0"),
    v20: pickMetric(cve, "2.0"),
  };
}

// Celtekst voor de CVSS-tabel in de advisory (markdown, inclusief <br> voor de
// vectorstring; de preview-renderer en de printstijl kennen die opmaak).
function cvssCell(m) {
  if (!m || m.score == null) return "*Niet beschikbaar*";
  let s = `**${m.score} (${mapSeverity(m.severity).prioriteit})**`;
  if (m.type) s += ` \u2014 ${m.type}`;
  if (m.vector) s += `<br>Vector: \`${m.vector}\``;
  return s;
}

function extractCwes(cve) {
  const out = new Set();
  for (const w of cve.weaknesses || []) {
    for (const d of w.description || []) {
      // Match 'CWE-<nummer>' ook binnen langere CNA-omschrijvingen
      // ("CWE-59 Improper Link Resolution..."); NVD-CWE-noinfo valt weg.
      const m = String(d.value || "").match(/CWE-\d+/i);
      if (m) out.add(m[0].toUpperCase());
    }
  }
  return [...out];
}

function versionRange(versions) {
  const aff = (versions || []).find((v) => v.status === "affected");
  if (!aff) return "";
  if (aff.lessThan) return `< ${aff.lessThan}`;
  if (aff.version) return aff.version;
  return "";
}

function extractProducts(cve) {
  const names = new Set();
  // New NVD format: affected[].affectedData[]
  for (const block of cve.affected || []) {
    for (const a of block.affectedData || []) {
      if (a.product && a.product !== "*") {
        const range = versionRange(a.versions);
        const vendor = a.vendor && a.vendor !== "*" && a.vendor !== "n/a" ? `${a.vendor} ` : "";
        const plats = (a.platforms || []).length ? ` (${a.platforms.join(", ")})` : "";
        names.add(`${vendor}${a.product}${range ? " " + range : ""}${plats}`.trim());
      }
    }
  }
  // Legacy NVD format: configurations.nodes[].cpeMatch[]
  for (const node of cve.configurations?.nodes || []) {
    const collect = (cpe) => {
      const parts = (cpe.criteria || "").split(":");
      if (parts.length > 5) {
        const vendor = parts[3];
        const product = parts[4];
        if (product && product !== "*") names.add(`${vendor} ${product}`.replace(/\bnull\b/g, "").trim());
      }
    };
    (node.cpeMatch || []).forEach(collect);
    (node.children || []).forEach((c) => (c.cpeMatch || []).forEach(collect));
  }
  return [...names];
}

// Kaal productnaam (voor de titel en de aankondigingszin), bijv. "OpenSSH".
function firstProductName(cve) {
  if (!cve) return null;
  for (const block of cve.affected || []) {
    for (const a of block.affectedData || []) {
      if (a.product && a.product !== "*") return a.product;
    }
  }
  for (const node of cve.configurations?.nodes || []) {
    for (const cm of node.cpeMatch || []) {
      const p = (cm.criteria || "").split(":")[4];
      if (p && p !== "*") return p;
    }
  }
  return null;
}

// Vendor van het eerste affected-product (default voor "aangekondigd door").
function firstVendor(cve) {
  if (!cve) return null;
  for (const block of cve.affected || []) {
    for (const a of block.affectedData || []) {
      if (a.vendor && a.vendor !== "*" && a.vendor !== "n/a") return a.vendor;
    }
  }
  return null;
}

// Meerdere producten netjes benoemen in één looptekst: "OpenSSH",
// "nginx en OpenSSL", "a, b en c"; bij vier of meer de eerste drie met "e.a.".
function benoemProducten(namen) {
  if (!namen.length) return null;
  if (namen.length === 1) return namen[0];
  if (namen.length === 2) return `${namen[0]} en ${namen[1]}`;
  if (namen.length === 3) return `${namen[0]}, ${namen[1]} en ${namen[2]}`;
  return `${namen.slice(0, 3).join(", ")} e.a.`;
}

// Standaard-impacttekst, afgeleid uit de vector van de zwaarste CVE: een
// lokale privilege-escalatie (AV:L/PR:L) leest anders dan een RCE zonder
// rechten en zonder interactie (AV:N/PR:N/UI:N). Vectoronderdelen heten in
// CVSS v3 en v4 gelijk (AV/PR/UI); de afkortingen in de vectorstring zijn in
// beide versies één letter (N, L, H).
function impactFromCvss(cves, productNaam) {
  const s = maxSeverity(cves);
  const ergste = cves.find((c) => String(overallSeverity(c).severity).toUpperCase() === s) || cves[0];
  const vector = (ergste && overallSeverity(ergste).vector) || "";
  const waarde = (k) => (vector.match(new RegExp(`(?:^|/)${k}:(\\w+)`)) || [])[1];
  const pr = waarde("PR");
  const ui = waarde("UI");
  const remote = waarde("AV") === "N";
  const rechten = !pr || pr === "N" ? "zonder rechten" : pr === "L" ? "met lage rechten" : "met hoge rechten";
  const interactie = !ui || ui === "N" ? "zonder gebruikersinteractie" : "met gebruikersinteractie";
  if (!vector) {
    return `Een succesvolle aanval kan leiden tot overname van de getroffen ${productNaam}-dienst. Dit betekent mogelijk:\n\n- toegang tot, manipulatie of verlies van gegevens;\n- verstoring van de dienstverlening;\n- verdere toegang tot achterliggende systemen, afhankelijk van de positie en rechten van het getroffen systeem.`;
  }
  if (remote && pr === "N" && ui === "N") {
    return "Een succesvolle aanval kan leiden tot het op afstand uitvoeren van willekeurige code op een kwetsbaar systeem, zonder autorisatiestap of gebruikersinteractie (unauthenticated remote code execution). Dit betekent mogelijk:\n\n- overname van de getroffen dienst;\n- toegang tot, manipulatie of verlies van gegevens;\n- verstoring van de dienstverlening;\n- verdere toegang tot achterliggende systemen, afhankelijk van de positie en rechten van het getroffen systeem.";
  }
  const bron = remote ? "vanaf het netwerk" : "lokaal op het systeem";
  return `Een succesvolle aanval kan ${bron} leiden tot het uitvoeren van code of het uitbreiden van bevoegdheden (${rechten}, ${interactie}). Dit betekent mogelijk:\n\n- overname van de dienst of uitbreiding van rechten op het systeem zelf;\n- toegang tot, manipulatie of verlies van gegevens;\n- verstoring van de dienstverlening.`;
}

// Vaste versie waarbeneden het product getroffen is (patchversie), bijv. "10.6p2".
// NVD gebruikt soms "*" als placeholder voor lessThan; dat is geen versie.
function fixedVersion(cve) {
  for (const block of cve.affected || []) {
    for (const a of block.affectedData || []) {
      const aff = (a.versions || []).find((v) => v.status === "affected" && v.lessThan && v.lessThan !== "*");
      if (aff) return aff.lessThan.replace(/^\s*\(.*?\)\s*/, "");
    }
  }
  return null;
}

// Patchregel per CVE: gebruikt het product van DIT CVE, niet dat van het
// eerste CVE — bij gemengde advisories (bijv. nginx + OpenSSL) klopte de
// productnaam anders niet. De fallbackProduct (titelproduct) wordt alleen
// gebruikt als dit CVE zelf geen productnaam heeft.
function patchLine(cve, fallbackProduct) {
  const fix = fixedVersion(cve);
  if (!fix) return null;
  const prod = firstProductName(cve) || fallbackProduct || "het product";
  return `${cve.id}: patch beschikbaar (${prod} ${fix}) \u2014 zie referenties.`;
}

// ---------- Taal van de CVE-beschrijvingen (optie 2: meertaligheid) -----
// Een CVE-respons bevat per beschrijving een taaltag; de NVD levert waar
// beschikbaar meerdere talen mee (naast het Engelse CNA-exemplaar soms een
// NVD-vertaling), en de CNA-backstop levert wat de CNA zelf aanlevert - bij
// Nederlandstalige CNAs soms gewoon Nederlands. De advisory-tekst is dat
// niet: die is en blijft Nederlands. Deze voorkeur gaat daarom alleen over
// de opgehaalde beschrijving, op de kaart en in Technische Details. Een
// handmatig bewerkte beschrijving gaat altijd boven élke taalkeuze.
// De UI zelf (koppen, labels, knoppen) blijft Nederlands: een volledige
// Engelstalige interface is een groter karwei en is hier bewust buiten
// beschouwing gelaten (zie README, optie "meertaligheid").
function taalVoorkeur() {
  const v = (typeof taalSelect !== "undefined" && taalSelect && taalSelect.value) || "auto";
  if (v === "nl" || v === "en") return v;
  // "auto": volg de taal van de browser (nl-* → Nederlands, anders Engels).
  const nav = (typeof navigator !== "undefined" && navigator && navigator.language) || "";
  return String(nav).toLowerCase().replace("_", "-").startsWith("nl") ? "nl" : "en";
}

// Het beschrijvingsexemplaar voor de voorkeurstaal, of null bij een lege
// lijst. De valroute is bewust kort en voorspelbaar: eerst een exacte tag
// (genormaliseerd, zodat "en-US" onder "en" valt), dan dezelfde hoofdtalige
// (nl-BE telt voor "nl"), dan het Engelse exemplaar als wereldwijde
// standaard, en anders de eerste beschrijving. Die laatste stap is precies
// de oude vaste valroute, zodat een CVE zonder énige NL-beschrijving er bij
// voorkeur "nl" op precies hetzelfde uitkomt als voorheen.
function kiesBeschrijving(descriptions, voorkeur) {
  const d = Array.isArray(descriptions) ? descriptions : [];
  if (!d.length) return null;
  const norm = (x) => String(x || "").toLowerCase().replace("_", "-");
  const basis = (x) => norm(x).split("-")[0];
  const taaltalig = (x) => x && typeof x === "object" && !!String(x.value || "").trim();
  return d.find((x) => taaltalig(x) && norm(x.lang) === voorkeur)
    || d.find((x) => taaltalig(x) && basis(x.lang) === voorkeur)
    || d.find((x) => taaltalig(x) && basis(x.lang) === "en")
    || d.find(taaltalig)
    || null;
}

function bestDescription(cve) {
  // Een handmatig bewerkte beschrijving (op de CVE-kaart) heeft voorrang.
  if (cve._descEdit && cve._descEdit.trim()) return cve._descEdit.trim();
  const d = kiesBeschrijving(cve.descriptions, taalVoorkeur());
  return (d && d.value) || "(geen beschrijving beschikbaar)";
}

function bestReferences(cve) {
  // Vendor Advisory / Patch tags first, cap at 6
  const score = (r) => (r.tags || []).includes("Vendor Advisory") ? 0
    : (r.tags || []).includes("Patch") ? 1
    : (r.tags || []).includes("Third Party Advisory") ? 2 : 3;
  return [...(cve.references || [])]
    .sort((a, b) => score(a) - score(b))
    .slice(0, 6);
}

// Opslagvariant van de referenties voor compactAdvisory: de zes die de
// advisory zelf toont (bestReferences), plus de eventuele
// extra-trackerreferenties (Rocky/Arch). Die overleven de kap van zes
// anders niet als ze erbuiten vallen, terwijl de distributeurregel er wél
// een link op bouwt — zonder deze aanvulling verdwijnt zo'n link na
// geschiedenisherstel. De Set werkt op objectidentiteit: wat al in de basis
// zat, komt niet twee keer mee.
function referentiesVoorOpslag(c) {
  const basis = bestReferences(c);
  const extra = (c.references || []).filter((r) => isExtraTrackerUrl(r.url));
  return [...new Set([...basis, ...extra])];
}

// Compacte kopie van een CVE voor de browseropslag (geschiedenis én
// staatsherstel): een volledige NVD-record is tienduizenden tekens, waarvan
// de bouwer en de kaart het grootste deel nooit gebruiken — references
// (soms honderden regels), beschrijvingen in elke taal en analytische
// velden als dateModified en evaluations. De kopie bevat precies wat
// buildMarkdown en renderCveCards nodig hebben: identiteit en status, de
// CVSS-metrics, weaknesses, affected/configurations (product en patch),
// publicatiedatum en de KEV-velden. Referenties worden gekapt op dezelfde
// zes die de advisory zelf toont (bestReferences), aangevuld met de
// eventuele extra-trackerreferenties (referentiesVoorOpslag), en
// beschrijvingen tot het Engelse exemplaar, het eerste én het exemplaar van
// de huidige taalkeuze (de valroute van bestDescription; de taalkeuze-mee-
// name zorgt dat een na geschiedenisherstel met voorkeur "nl" gebouwde
// advisory alsnog op Engels terugvalt als de NL-beschrijving werd wegge-
// compact). De originele objecten in de CVE-fetchcache blijven onaangeroerd: het is
// een níeuw object, alleen de sub-arrays worden gedeeld (nooit gemuteerd).
// Opgeslagen compacte items herstellen exact dezelfde advisory: herhaalde
// compactie (bijv. kopiëren ná een herstel) levert opnieuw exact hetzelfde
// object op.
function compactAdvisory(c) {
  if (c._fetchFailed) return { id: c.id, _fetchFailed: true }; // mislukte stub: niets te compacteren
  const d = Array.isArray(c.descriptions) ? c.descriptions : [];
  // Eerste beschrijving, het Engelse exemplaar en het exemplaar van de
  // huidige taalkeuze (de volgorde van d blijft voorop staan, zodat
  // herhaalde compactie — bijv. kopiëren ná een herstel — exact hetzelfde
  // object oplevert; de taalknop is een identiek object uit dezelfde lijst,
  // dus de Set voegt niets toe als de keuze al meekwam). bestDescription
  // kiest daarbinnen zelf per taal, dus de advies-tekst is
  // volgorde-onafhankelijk en taal-bestendig binnen één voorkeur.
  const besch = [...new Set([d[0], d.find((x) => x && x.lang === "en"),
    kiesBeschrijving(d, taalVoorkeur())].filter(Boolean))];
  const uit = {
    id: c.id,
    descriptions: besch,
    references: referentiesVoorOpslag(c), // max 6 + extra-trackers, Vendor Advisory/Patch eerst
    metrics: c.metrics,
    weaknesses: c.weaknesses,
    affected: c.affected,
    configurations: c.configurations,
    published: c.published,
    vulnStatus: c.vulnStatus,
    cisaExploitAdd: c.cisaExploitAdd,
    cisaActionDue: c.cisaActionDue,
    _source: c._source,
    _state: c._state,
  };
  if (c._descEdit != null) uit._descEdit = c._descEdit; // handmatige beschrijving blijft
  for (const k of Object.keys(uit)) if (uit[k] === undefined) delete uit[k];
  return uit;
}

// Referenties per CVE groeperen met een totaalplafond: drie CVE's konden
// samen ~18 links in één platte lijst opleveren, waar de voorbeeldadvisories
// een korte, gegroepeerde lijst laten zien. Max PER_CVE per CVE, maximaal
// TOTAAL in de hele advisory; dubbele URL's (vanwege de vele NVD
// third-party-advisories) blijven één keer over.
function groepeerReferenties(list) {
  const PER_CVE = 4;
  const TOTAAL = 10;
  const seen = new Set();
  const groups = [];
  let used = 0;
  for (const c of list) {
    if (c._fetchFailed || used >= TOTAAL) continue;
    const fresh = bestReferences(c).filter((r) => r.url && !seen.has(r.url));
    const take = fresh.slice(0, Math.min(PER_CVE, TOTAAL - used));
    for (const r of take) seen.add(r.url);
    used += take.length;
    if (take.length) groups.push({ id: c.id, refs: take });
  }
  return groups;
}

// ---------- Distributeurtrackers ----------
// Standaardcontrolelinks per CVE-nummer bij de zeven Linux-distributie-
// trackers met een vast URL-formaat (vormen live geverifieerd 22-11-2026,
// Alpine 26-11-2026): Debian en Ubuntu houden het nummer zoals het is, Red
// Hat gebruikt kleine letters. SUSE laat het nummer staan met afsluitende
// slash (canonical vorm; een aangevraagde slash-vorm werkt daar ook). Let
// op: een distributeur die een CVE niet volgt, geeft op zo'n link een 404 -
// dat is géén fout van de link, maar het antwoord van de tracker. De links
// doen zelf geen uitspraak over de pakketstatus in de omgeving van de lezer;
// ze zijn het startpunt van de controle die de patchregel al aanraadt.
// Uitbreidingsronde erbij: Amazon Linux via ALAS met .html-achtervoegsel
// (live geverifieerd: alas.aws.amazon.com/cve/html/CVE-2024-6387.html toont
// de platformstatus-tabel per release). Fedora via de officiële CVE-website
// cve.fedoraproject.org — dat is een JavaScript-app met hash-route #/cve/<id>
// (oudere lookaside-tracker is buiten gebruik; de route is de officiële
// per-CVE-pagina van die website). Een route-wijziging is daar dus één regel.
const DISTRIBUTEUR_TRACKERS = [
  ["Debian", (id) => `https://security-tracker.debian.org/tracker/${id}`],
  ["Ubuntu", (id) => `https://ubuntu.com/security/${id}`],
  ["Red Hat", (id) => `https://access.redhat.com/security/cve/${id.toLowerCase()}`],
  ["SUSE", (id) => `https://www.suse.com/security/cve/${id}/`],
  ["Fedora", (id) => `https://cve.fedoraproject.org/#/cve/${id}`],
  ["Amazon Linux", (id) => `https://alas.aws.amazon.com/cve/html/${id}.html`],
  // Tweede uitbreidingsronde (optie 4): Alpine. De eerdere uitzetting "geen
  // per-CVE-pagina" gold voor de secdb (alleen YAML-overzichten per
  // release), maar de Alpine Security Tracker heeft die wél: per CVE toont
  // die pagina de pakketstatus per branch (live geverifieerd 26-11-2026 aan
  // CVE-2024-6387: "fixed" per release). Daarmee telt de vaste set zeven.
  ["Alpine", (id) => `https://security.alpinelinux.org/vuln/${id}`],
];

// Extra distributeurlinks uit de NVD-referenties zelf (optie 4):
// distributeurs buiten de vaste set die een per-CVE-URL met het eigen
// nummer in de referenties van dít CVE hebben, verdienen een extra
// vermelding — zo'n referentie bestaat immers alleen als de distributeur
// het nummer volgt. Patronen live waargenomen in NVD-referenties
// (26-11-2026): Rocky Linux via sig-security.rocky.page en Arch Linux via
// security.archlinux.org. Een URL met een ander CVE-nummer dan het eigen
// (referenties kunnen over gerelateerde nummers gaan) telt niet mee; een
// nieuwe distributeur is één regel in onderstaande lijst.
const EXTRA_TRACKERS = [
  ["Rocky Linux", /^https?:\/\/sig-security\.rocky\.page\/issues\/(CVE-\d{4}-\d{4,})\/?$/i],
  ["Arch Linux", /^https?:\/\/security\.archlinux\.org\/(CVE-\d{4}-\d{4,})$/i],
];

function isExtraTrackerUrl(url) {
  return EXTRA_TRACKERS.some(([, re]) => re.test(String(url || "")));
}

// De extra links per CVE: "Naam URL" per gevonden tracker, dedup per naam,
// in de volgorde van de referenties; puur op de eigen CVE-referenties.
function extraTrackers(cve) {
  const out = [];
  const gezien = new Set();
  for (const r of cve.references || []) {
    for (const [naam, re] of EXTRA_TRACKERS) {
      const m = re.exec(String(r.url || ""));
      if (m && m[1].toUpperCase() === cve.id && !gezien.has(naam)) {
        gezien.add(naam);
        out.push(`${naam} ${r.url}`);
      }
    }
  }
  return out;
}

// Eén regel per CVE (max 3: daarboven wordt de blok langer dan hij nuttig
// is): eerst de vaste zeven links, daarna de eventuele extra's uit de
// referenties. CVE's zonder opgehaalde gegevens overslaan: een trackerlink
// bij een nummer waarvan de gegevens ontbreken, is raden.
function distributeurRegels(list) {
  return list
    .filter((c) => !c._fetchFailed)
    .slice(0, 3)
    .map((c) => `- ${c.id}: ${[
      ...DISTRIBUTEUR_TRACKERS.map(([naam, fn]) => `${naam} ${fn(c.id)}`),
      ...extraTrackers(c),
    ].join(" \u00b7 ")}`);
}

// ---------- Fetching ----------

// ---------- CVE-fetchcache (sessionStorage) ----------
// Elke generatie haalde álle CVE's opnieuw op: één nummer toevoegen aan een
// bestaande advisory kostte daarmee een volledige her-download en riskeerde
// zonder API-sleutel het 30s-limietvenster van NVD. Opgehaalde CVE-gegevens
// worden daarom één uur per browsersessie gecachet (zelfde TTL als de
// KEV-feed). Vink "Vers ophalen" aan of wis de velden om de cache te omzeilen.

const CVE_CACHE_KEY = "advisory-writer:cve-cache-v1";
const CVE_TTL_MS = 60 * 60 * 1000;
let cveCache = null; // lazisch geladen: { id: { ts, cve } }

function cveCacheRead() {
  if (cveCache) return cveCache;
  try { cveCache = JSON.parse(sessionStorage.getItem(CVE_CACHE_KEY)) || {}; }
  catch { cveCache = {}; } // geen/blokkeerde cache: werken zonder
  return cveCache;
}

// Verse cache-entry voor dit CVE-nummer, anders null.
function cveCacheGet(id) {
  const e = cveCacheRead()[id];
  return e && Date.now() - e.ts < CVE_TTL_MS ? e.cve : null;
}

function cveCacheSet(id, cve) {
  const c = cveCacheRead();
  c[id] = { ts: Date.now(), cve };
  try { sessionStorage.setItem(CVE_CACHE_KEY, JSON.stringify(c)); }
  catch { /* quota bereikt: cache werkt nog in het geheugen, alleen niet meer na herladen */ }
}

function clearCveCache() {
  cveCache = {};
  try { sessionStorage.removeItem(CVE_CACHE_KEY); } catch { /* al leeg */ }
}

// Welke CVE's de facto het netwerk opgaan: cachede hits vallen buiten de
// set en komen direct uit fetchCve terug. Het veld 'count' is het aantal
// netwerkophaalacties en bepaalt de stapgrootte (zie nvdStapMs). Tot vóór
// de bundeling waren de waarden tevens vertraging-indexen (0, 1, 2, ...);
// sinds de chunkvertraging de chunkindex gebruikt, is die index een
// overblijfsel en is een Set toereikend (verbeterpunt 3).
function netIndexen(ids, useCache) {
  const net = new Set();
  for (const id of ids) {
    if (!(useCache && cveCacheGet(id))) net.add(id);
  }
  return { net, count: net.size };
}

// Harde bovengrens per poging: zonder timeout zou een hangende verbinding
// (geen respons, geen fout) de genereerbeurt oneindig laten wachten. 30 s is
// royaal: de KEV-feed is meerdere MB en mag over een trage verbinding tijd
// kosten. De grens dekt de tijd tot de respons binnenkomt; de body-parsing
// daarna niet. Een timeout wordt als onherstelbaar beschouwd (noRetry): als
// er 30 seconden lang niets binnenkwam, wordt het binnen een retry-vertraging
// van enkele seconden ook niet beter — de NVD-catch valt dan af op het CVE
// Program, EPSS en KEV laten hun regel weg zoals bij elke andere uitval.
const FETCH_TIMEOUT_MS = 30000;

// Met beperkte retry/backoff: de NVD-API geeft bij drukte regelmatig 429/503.
// Optioneel signal: een afgebroken verzoek (AbortError) is een bewuste keus
// van de app zelf, geen netwerkstoring — daarop wordt niet opnieuw geprobeerd.
async function fetchJson(url, { tries = 3, baseDelay = 1200, headers = {}, signal, timeoutMs = FETCH_TIMEOUT_MS } = {}) {
  let lastErr;
  for (let i = 0; i < tries; i++) {
    let timer = null;
    try {
      // Wedloop tussen de fetch en een wekker: bij een hangende verbinding
      // wint de wekker en gaat de beurt door naar de normale uitvalafhandeling.
      // De onderliggende request wordt niet geannuleerd (daarvoor zou dit
      // signaal met dat van de aanroeper gecombineerd moeten worden); de app
      // wacht er in ieder geval niet meer op. Zonder timeoutMs gedraagt de
      // functie zich exact als voorheen.
      const res = await new Promise((resolve, reject) => {
        if (timeoutMs) {
          timer = setTimeout(() => reject(Object.assign(
            new Error(`geen respons binnen ${Math.round(timeoutMs / 1000)} s (timeout)`),
            { noRetry: true }
          )), timeoutMs);
        }
        fetch(url, { headers, signal }).then(resolve, reject);
      });
      // 429: het NVD-venster van 30 s is binnen de retry-vertragingen niet
      // geleegd, dus doelloos opnieuw proberen overslaan en direct een
      // heldere melding geven (API-sleutel lost het op).
      if (res.status === 429) {
        throw Object.assign(
          new Error("HTTP 429 — NVD-limiet bereikt; voeg een API-sleutel toe voor meer CVE's tegelijk"),
          { noRetry: true }
        );
      }
      if (!res.ok) {
        // 4xx is een permanente fout (typo, onbekend nummer, ongeldige
        // API-sleutel): opnieuw proberen binnen enkele seconden lost die niet
        // op, dus niet doen - de aanroeper valt meteen terug. 5xx is
        // vluchtig (NVD-hiccup): die gaat door naar de retry hieronder.
        throw Object.assign(new Error(`HTTP ${res.status}`), { noRetry: res.status < 500 });
      }
      return await res.json();
    } catch (e) {
      lastErr = e;
      if (e.noRetry || e.name === "AbortError") throw e;
      if (i < tries - 1) await new Promise((r) => setTimeout(r, baseDelay * (i + 1)));
    } finally {
      if (timer) clearTimeout(timer);
    }
  }
  throw lastErr;
}

async function fetchNvd(cveId) {
  const key = apiKeyInput.value.trim();
  const data = await fetchJson(
    `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`,
    // Optionele API-sleutel: verhoogt de limiet van 5 naar 50 requests/30 s.
    { headers: key ? { apiKey: key } : {} }
  );
  if (!data.vulnerabilities?.length) throw new Error("niet gevonden in NVD");
  return data.vulnerabilities[0].cve;
}

// Gebundelde variant van fetchNvd: één verzoek voor meerdere nummers via de
// parameter cveIds (comma-gescheiden; de API staat er 100 toe, NVD
// Developers - Vulnerability API). Het chunkplafond van de aanroeper is
// lager: elke CVE-record is tienduizenden tekens en één respons moet binnen
// de harde timeout van 30 s passen. Wat NVD niet teruggeeft, ontbreekt in
// de Map; de aanroeper (generateUitvoeren) valt daarop terug op fetchCve
// per nummer, dus de uitvalafhandeling (CVE Program-backstop, "niet
// gevonden") is identiek aan de route van toen. Het bundelgedrag bij
// onbekende nummers is live geverifieerd (25-11-2026): een chunk met één
// onbekend nummer ernaast geeft 200 met uitsluitend de gevonden nummers —
// één typo laat de hele bundel dus niet falen, alleen dat ene nummer
// betaalt de terugval — en een chunk met uitsluitend onbekende nummers
// geeft 200 met een lege vulnerabilities-lijst.
const NVD_BATCH_MAX = 20;

async function fetchNvdBatch(cveIds) {
  const key = apiKeyInput.value.trim();
  const data = await fetchJson(
    `https://services.nvd.nist.gov/rest/json/cves/2.0?cveIds=${cveIds.join(",")}`,
    // Optionele API-sleutel: verhoogt de limiet van 5 naar 50 requests/30 s.
    { headers: key ? { apiKey: key } : {} }
  );
  const out = new Map();
  for (const v of data.vulnerabilities || []) {
    const id = v?.cve?.id;
    if (id) out.set(String(id).toUpperCase(), v.cve);
  }
  return out;
}

function normalizeCnaMetrics(cna) {
  // CVE JSON 5.x: containers.cna.metrics is an ARRAY of objects keyed
  // cvssV4_0 / cvssV3_1 / cvssV3_0 / cvssV2_0 (underscores!), not the
  // NVD-style cvssMetricV31 object. Normalise to the NVD shape so that
  // collectCvss()/overallSeverity() work identically for both sources.
  const out = {};
  const KEYMAP = {
    cvssV4_0: "cvssMetricV40", cvssV40: "cvssMetricV40",
    cvssV3_1: "cvssMetricV31", cvssV31: "cvssMetricV31",
    cvssV3_0: "cvssMetricV30", cvssV30: "cvssMetricV30",
    cvssV2_0: "cvssMetricV2", cvssV20: "cvssMetricV2",
  };
  const entries = Array.isArray(cna.metrics) ? cna.metrics : [cna.metrics].filter(Boolean);
  for (const entry of entries) {
    for (const [key, target] of Object.entries(KEYMAP)) {
      if (entry[key]) (out[target] ||= []).push({ type: "Primary", source: "CNA", cvssData: entry[key] });
    }
  }
  return out;
}

async function fetchCveProgram(cveId) {
  const data = await fetchJson(`https://cveawg.mitre.org/api/cve/${cveId}`);
  const cna = data.containers?.cna || {};
  // Normalise into an NVD-like shape
  return {
    id: cveId,
    // CVE JSON 5.x: publicatiedatum staat in cveMetadata.datePublished
    // ('timePublished' is het oude 4.x-veld en bestaat in 5.x niet meer).
    published: data.cveMetadata?.datePublished || data.timePublished,
    descriptions: (cna.descriptions || []).map((d) => ({ lang: d.lang, value: d.value })),
    weaknesses: cna.problemTypes?.length
      ? [{
          // CNA-levert 'cweId' en een losse 'description' (geen 'value');
          // de normalisatie kiest cweId eerst, extractCwes() is de vangnet
          // voor lange omschrijvingen zonder cweId-veld.
          description: cna.problemTypes
            .flatMap((p) => p.descriptions || [])
            .map((d) => ({ value: d.cweId || d.description || d.value })),
        }]
      : [],
    metrics: normalizeCnaMetrics(cna),
    references: (cna.references || []).map((r) => ({ url: r.url, tags: r.tags || [] })),
    // CVE JSON 5.x gebruikt 'product'; het oude 4.x-formaat gebruikte 'name'.
    // Beide accepteren en normaliseren naar de NVD-vorm, anders blijven
    // titel/productnamen bij de fallback leeg.
    affected: (cna.affected || []).map((block) => ({
      affectedData: [{ vendor: block.vendor, product: block.product || block.name, versions: block.versions }],
    })),
    _state: data.cveMetadata?.state,
    _source: "CVE Program API",
  };
}

async function fetchCve(cveId) {
  // Cache only op verzoek overslaan (vink "Vers ophalen"); anders eerst
  // kijken of we dit CVE al eerder deze sessie hebben opgehaald.
  const noCache = typeof noCacheInput !== "undefined" && noCacheInput && noCacheInput.checked;
  if (!noCache) {
    const hit = cveCacheGet(cveId);
    if (hit) { hit._cached = true; return hit; }
  }
  let cve;
  try {
    cve = await fetchNvd(cveId);
    cve._source = "NVD";
  } catch (e) {
    statusT("status.nvd-poging", { id: cveId, reden: e.message });
    cve = await fetchCveProgram(cveId);
  }
  // Alleen succesvolle ritten cachen; een _cached-vlag van een eerdere
  // hit hoort niet in het opgeslagen exemplaar.
  delete cve._cached;
  cveCacheSet(cveId, cve);
  return cve;
}

// ---------- Stroomschema-afbidding ----------
// Optioneel afbeeldingsveld onder de Handelingsperspectieven & Adviezen: een
// eigen proces- of beslissingsplaatje (URL, bijv. vanaf het intranet). Een
// kaal URL'tje krijgt de markdown-afbeeldingsnotatie; een volledig blok
// ![bijschrift](url) wordt als zodanig overgenomen (dan is het bijschrift
// vrij te kiezen). Leeg blijft de output byte-voor-byte zoals voorheen. In
// de preview en de printdialoog is het beeld echt te zien; de jsPDF-
// tekstexport zet "bijschrift: url" als regel, want jsPDF haalt zelf geen
// externe plaatjes op (de html2canvas-route kan dat wél, zij het als raster).
// URL-schemabeveiliging: een relatieve URL (geen schema, bijv. "stroom.png"
// of "/img/plaatje.png" vanaf het eigen intranet) is altijd oké. Staat er
// wél een schema, dan alleen http, https of data:image — een verrassing als
// "javascript:...", "blob:" of "ftp:" is vrijwel altijd een plakfout en zou
// anders een kapot of onverwacht beeld in preview, print en export slepen.
function stroomUrlToegestaan(url) {
  const m = url.match(/^([A-Za-z][A-Za-z0-9+.-]*:)/);
  if (!m) return true; // relatief: geen schema om op stuk te lopen
  const s = m[1].toLowerCase();
  return s === "http:" || s === "https:" || url.toLowerCase().startsWith("data:image/");
}

// Het URL-deel van het veld: een kaal URL'tje zoals het staat, een volledig
// ![bijschrift](url)-blok zonder haakjes. De ene plek waar de veldvorm
// wordt opengeslagen, zodat beeldregel en weigeringsmelding nooit over
// welk URL'er ze oordelen uit elkaar kunnen lopen.
function stroomUrlUitVeld() {
  const rauw = stroomInput.value.trim();
  if (!rauw) return "";
  if (/^!\[[^\]]*\]\([^)]*\)$/.test(rauw)) return rauw.slice(rauw.indexOf("(") + 1, -1);
  return rauw;
}

function stroomRegelTekst() {
  const rauw = stroomInput.value.trim();
  if (!rauw) return "";
  if (/^!\[[^\]]*\]\([^)]*\)$/.test(rauw)) {
    // complete notatie: het schema van de ópgenomen URL geldt,
    // een afgewezen schema laat de hele regel vallen
    return stroomUrlToegestaan(stroomUrlUitVeld()) ? rauw : "";
  }
  return stroomUrlToegestaan(rauw) ? `![Stroomschema](${rauw})` : "";
}

// Zichtbare weigering (evaluatieronde punt 5): een geweigerd URL-schema liet
// de beeldregel woordloos vallen, waarna "waar is mijn plaatje?" de enige
// feedback was. Deze helper is de boodschap: wél invoer, maar géén
// beeldregel opgeleverd, dan is er geweigerd en noemt de melding het schema
// en de URL erbij. Leeg veld of toegestaan schema: null, niets te melden.
function stroomWaarschuwing() {
  const url = stroomUrlUitVeld();
  if (!url || stroomUrlToegestaan(url)) return null;
  const schema = url.match(/^([A-Za-z][A-Za-z0-9+.-]*:)/)[1];
  return T("stroom.geweigerd", { schema, url });
}

// De weigering is een toestand, geen eenmalige gebeurtenis: zolang het veld
// het geweigerde schema houdt, komt de melding bij élke herbouw terug. Op
// het moment dat het veld is hersteld, klinkt één keer een korte
// bevestiging — daarna blijft de statusbalk met rust, anders zou élke
// toetsaanslag in welk veld dan ook er iets op gaat zetten.
let stroomMeldingActief = false;
function toonStroomStatus() {
  const boodschap = stroomWaarschuwing();
  if (boodschap) {
    stroomMeldingActief = true;
    setStatus(boodschap, true);
    return;
  }
  if (!stroomMeldingActief) return;
  stroomMeldingActief = false;
  if (stroomInput.value.trim()) statusT("stroom.hersteld");
}

// ---------- Markdown generation (advisory template, CERT-briefstijl) ----------

function buildMarkdown() {
  const first = advisories[0];
  const producten = [...new Set(advisories.flatMap(extractProducts))];
  // Eén productnaam per CVE. Titel en aankondigingszin noemen álle producten;
  // eerder stond er alleen het product van het eerste CVE, waardoor een
  // advisory over nginx + OpenSSL toch "in nginx" heette. productNaam (het
  // eerste product) blijft als fallback voor de patchregel en de *-dienst-
  // formulering in de impacttekst.
  const productNamen = [...new Set(advisories.map(firstProductName).filter(Boolean))];
  const productLijst = benoemProducten(productNamen) || producten[0] || "het betreffende product";
  const productNaam = productNamen[0] || producten[0] || "het betreffende product";
  const aantal = advisories.length;
  const enkel = aantal === 1;
  const kwets = enkel ? "kwetsbaarheid" : "kwetsbaarheden";

  const sev = { severity: maxSeverity(advisories) }; // zwaarste over alle CVE's
  const prioriteit = prioriteitSelect.value !== "auto"
    ? prioriteitSelect.value
    : mapSeverity(sev.severity).prioriteit;
  const kritiek = prioriteit === "Kritiek";

  // Titel: "Kritieke kwetsbaarheden in nginx" / "Belangrijke kwetsbaarheid in OpenSSH"
  const titel = titleInput.value.trim() ||
    `${kritiek ? "Kritieke" : "Belangrijke"} ${kwets} in ${productLijst}`;

  const pubDate = dateInput.value.trim() || nowNl();
  const ref = refInput.value.trim();
  const versie = versieInput.value.trim() || "1.0";
  const aanhef = aanhefInput.value.trim();
  const opening = openingInput.value.trim();
  const bijnaam = bijnaamInput.value.trim();
  const partij = aankondigerInput.value.trim() || firstVendor(first) || "de leverancier";
  const aankondigingDatum = aankondigingDatumInput.value.trim() || nlDate(pubDate) || "onlangs";
  const meldpunt = meldpuntInput.value.trim() || "het CERT";
  const geadresseerden = geadresseerdenInput.value.trim();
  const stroomRegel = stroomRegelTekst(); // optioneel beeld onder de adviezen

  // --- Aankondigingsparagraaf ---
  const hebben = /\sen\s|,\s/.test(partij) ? "hebben" : "heeft";
  let aankondiging = `Op ${aankondigingDatum} ${hebben} ${partij} een aankondiging gedaan dat er ` +
    `${enkel ? "een " : ""}${kritiek ? "kritieke" : "belangrijke"} ${kwets} ${enkel ? "zit" : "zitten"} in ${productLijst}.`;
  if (bijnaam) aankondiging += ` Deze ${kwets} ${enkel ? "wordt" : "worden"} \u201c${bijnaam}\u201d genoemd.`;

  // --- Impact ---
  // Standaard-impact wordt uit de zwaarste CVSS-vector afgeleid (AV/PR/UI);
  // een eigen ingevulde tekst heeft altijd voorrang.
  const impactBlock = impactInput.value.trim() || impactFromCvss(advisories, productNaam);

  // --- Handelingsperspectieven & Adviezen ---
  // Drie categorieën uit elkaar houden: wél een patchversie gevonden, géén
  // patchversie in de gegevens, en CVE's waarvan de gegevens zelf niet
  // opgehaald konden worden (die laatste is geen oordeel over een patch).
  const patchItems = advisories
    .filter((c) => !c._fetchFailed)
    .map((c) => patchLine(c, productNaam))
    .filter(Boolean);
  const mislukt = advisories.filter((c) => !c._fetchFailed && !fixedVersion(c)).map((c) => c.id);
  if (mislukt.length) {
    patchItems.push(`${mislukt.join(", ")}: controleer bij de leverancier/distributeur welke patchversie geldt \u2014 zie referenties.`);
  }
  const geblokt = advisories.filter((c) => c._fetchFailed).map((c) => c.id);
  if (geblokt.length) {
    patchItems.push(`${geblokt.join(", ")}: gegevens konden niet worden opgehaald \u2014 controleer het CVE-nummer en de beschikbaarheid van NVD/CVE Program.`);
  }

  const eigen = handelInput.value
    .split(/\n+/)
    .map((s) => s.replace(/^[-*]\s*/, "").trim())
    .filter(Boolean);
  const adviezen = [
    ...patchItems,
    ...eigen,
    `Controleer of ${productLijst} in uw omgeving aanwezig is, ook op onverwachte plekken (Docker-images, minimale Linux-installaties, embedded systemen).`,
    `Indien u niet direct kunt (laten) patchen, beperk dan de bereikbaarheid van de betreffende dienst en patch zodra het kan.`,
    `Opent u alstublieft geen eigen interne communicatiekanalen buiten uw afdeling, maar centraliseer uw vragen richting ${meldpunt}.`,
  ].map((b) => `- ${b}`).join("\n");

  // --- Technische Details (per CVE: beschrijving, CWE, geraakte producten) ---
  const tech = advisories
    .map((c) => {
      const cwes = extractCwes(c);
      const lines = [];
      if (c._fetchFailed) {
        return `- **${c.id}:** de gegevens konden niet worden opgehaald (NVD en CVE Program API niet bereikbaar of onbekend nummer) \u2014 controleer het nummer en genereer opnieuw.`;
      }
      if (cwes.length) lines.push(`Type: ${cwes.join(", ")}.`);
      const prod = extractProducts(c);
      if (prod.length) lines.push(`Geraakt: ${prod.join("; ")}.`);
      const kev = kevStatusText(c);
      if (kev) lines.push(kev);
      const epss = epssRegelTekst(c);
      if (epss) lines.push(epss);
      const status = cveStatus(c);
      if (status) lines.push(status.note);
      return `- **${c.id}:** ${bestDescription(c)}${lines.length ? "\n\n" + lines.map((l) => `  ${l}`).join("\n\n") : ""}`;
    })
    .join("\n\n");

  // --- CVSS-tabel: aparte kolommen (vakken) voor v4.0 en v3.1 per CVE ---
  const cvssTable = [
    "| CVE | CVSS v4.0 | CVSS v3.1 |",
    "| --- | --- | --- |",
    ...advisories.map((c) => {
      if (c._fetchFailed) return `| ${c.id} | *geen gegevens* | *geen gegevens* |`;
      const { v4, v31 } = cvssByFamily(c);
      return `| ${c.id} | ${cvssCell(v4)} | ${cvssCell(v31)} |`;
    }),
  ].join("\n");

  // Oudere CVE's hebben vaak alleen CVSS v3.0/v2.0; toon die score dan als
  // toelichting onder de tabel in plaats van tweemaal "Niet beschikbaar".
  const cvssNotes = advisories
    .map((c) => {
      const { v4, v31, v30, v20 } = cvssByFamily(c);
      if (v4 || v31) return null;
      const older = v30 || v20;
      if (!older) return null;
      let s = `*Let op: voor ${c.id} is alleen CVSS ${older.version} beschikbaar: score **${older.score} (${mapSeverity(older.severity).prioriteit})**`;
      if (older.vector) s += `, vector \`${older.vector}\``;
      return s + ".*";
    })
    .filter(Boolean);
  const cvssBlock = cvssTable + (cvssNotes.length ? "\n\n" + cvssNotes.join("\n") : "");

  // --- Referenties ---
  // Gegroepeerd per CVE bij meerdere CVE's (elke groep met eigen kopje),
  // plat als er maar één CVE referenties heeft. Kale URL's (geen <... >-
  // autolink): de voorbeeldadvisories gebruiken kale URL's, die in e-mail en
  // de meeste editors direct klikbaar zijn.
  const refGroups = groepeerReferenties(advisories);
  let refsBlock = "- (geen referenties gevonden)";
  if (refGroups.length === 1) {
    refsBlock = refGroups[0].refs.map((r) => `- ${r.url}`).join("\n");
  } else if (refGroups.length > 1) {
    refsBlock = refGroups
      .map((g) => `**${g.id}:**\n${g.refs.map((r) => `- ${r.url}`).join("\n")}`)
      .join("\n\n");
  }

  // Distributeurtrackers ná de referenties: kale URL's (dezelfde conventie),
  // één regel per CVE. Bij uitsluitend mislukte CVE's vervalt het blok.
  const distrRegels = distributeurRegels(advisories);
  const distrBlock = distrRegels.length
    ? `\n**Distributeurtrackers (controleer de pakketstatus per distributie):**\n\n${distrRegels.join("\n")}\n`
    : "";

  const disclaimerBlock = (disclaimerText || DEFAULT_DISCLAIMER).trim();

  return `Versie: ${versie}${ref ? ` \u2014 ${ref}` : ""}

${aanhef ? aanhef + "\n\n" : ""}${opening ? opening + "\n\n" : ""}# ${titel}

${aankondiging}

## Impact

${impactBlock}

## Handelingsperspectieven & Adviezen

${adviezen}
${stroomRegel ? `\n${stroomRegel}\n` : ""}
## Technische Details

${tech}

**CVSS-scores per kwetsbaarheid:**

${cvssBlock}

**Aanvullende informatie:**

${refsBlock}
${distrBlock}
Deze berichtgeving zal worden bijgewerkt indien nieuwe informatie beschikbaar komt.
${geadresseerden ? `\nDeze mail is gestuurd aan: ${geadresseerden}\n` : ""}
## Disclaimer

${disclaimerBlock}
`;
}

// ---------- Tiny markdown renderer (preview) ----------

function mdToHtml(md) {
  const esc = escHtml; // gedeelde helper (fix 6): geen tweede escape-variant
  const inline = (s) => s
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/\*([^*]+)\*/g, "<em>$1</em>")
    // Afbeelding vóór de koppeling: ![alt](url) deelt de syntaxis met
    // [tekst](url). De HTML-escaping (esc draait vóór inline) garandeert
    // dat de src hier geen quotes bevat die uit het src-attribuut breken.
    // Afbeeldingen laden lazy (fix 6: geen blokkerende fetch tijdens de
    // herbouw) en zenden geen referrer naar externe plaatjesservers. De
    // printdialoog en de raster-PDF werken op dezelfde HTML; beide laden de
    // plaatjes zelf (print-rendering en html2canvas' eigen imagelader), dus
    // de lazy-attributen kosten hun niets.
    .replace(/!\[([^\]]*)\]\(([^)]+)\)/g, '<img src="$2" alt="$1" loading="lazy" referrerpolicy="no-referrer">')
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>')
    .replace(/&lt;(https?:\/\/[^&\s>]+)&gt;/g, '<a href="$1" target="_blank" rel="noopener">$1</a>')
    // Autolink. De afsluitende punt, komma of sluitende haak van een zin hoort
    // bij de omtrek en niet bij de URL: "Zie https://x.nl/a." linkte de punt
    // mee in de href. De URL-groep is daarom lui (zo kort mogelijk) en een
    // lookahead dwingt af dat hij op een echte woordgrens stopt; de
    // punctuatiegroep valt daarna buiten de ankertag (groep $3).
    .replace(/(^|[\s(])(https?:\/\/[^\s<)"]+?)([.,;:!?)]*)(?=$|[\s(])/g,
      '$1<a href="$2" target="_blank" rel="noopener">$2</a>$3')
    .replace(/&lt;br\s*\/?&gt;/g, "<br>");

  const lines = esc(md).split("\n");
  const out = [];
  let inTable = false, inList = false, inCode = false, para = [];

  const flushPara = () => { if (para.length) { out.push(`<p>${inline(para.join(" "))}</p>`); para = []; } };
  const closeList = () => { if (inList) { out.push("</ul>"); inList = false; } };
  const closeTable = () => { if (inTable) { out.push("</table>"); inTable = false; } };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/^```/.test(line)) { flushPara(); closeList(); closeTable();
      out.push(inCode ? "</code></pre>" : "<pre><code>"); inCode = !inCode; continue; }
    if (inCode) { out.push(line + "\n"); continue; }

    if (/^\|/.test(line)) {
      flushPara(); closeList();
      const cells = line.split("|").slice(1, -1).map((c) => c.trim());
      if (/^[\s:|-]+$/.test(line)) continue; // separator row
      if (!inTable) { out.push("<table>"); inTable = true;
        out.push("<tr>" + cells.map((c) => `<th>${inline(c)}</th>`).join("") + "</tr>");
      } else {
        out.push("<tr>" + cells.map((c) => `<td>${inline(c)}</td>`).join("") + "</tr>");
      }
      continue;
    }
    closeTable();

    if (/^- /.test(line.trim())) { flushPara();
      if (!inList) { out.push("<ul>"); inList = true; }
      out.push(`<li>${inline(line.trim().slice(2))}</li>`); continue; }
    closeList();

    // Alinea-grenzen: de alinea wordt alleen gesloten op blokovergangen (kop,
    // citation, hr) en op lege regels. Eerder stond de flushPara bovenaan deze
    // aftakking, waardoor élke losse regel zijn eigen <p> kreeg en twee
    // opeenvolgende tekstregels nooit samenvoegden zoals markdown voorschrijft.
    let m;
    if ((m = line.match(/^(#{1,4})\s+(.*)/))) { flushPara(); out.push(`<h${m[1].length}>${inline(m[2])}</h${m[1].length}>`); continue; }
    // Let op: de regels zijn allang escaped (esc() draait vóór de lus), dus een
    // citation-teken staat hier als &gt;. De oorspronkelijke test /^>/ was daardoor
    // nooit waar en blokkeerde het blockquote-subdeel (nu getest, sectie 16).
    if (/^&gt;\s?/.test(line)) { flushPara(); out.push(`<blockquote>${inline(line.replace(/^&gt;\s?/, ""))}</blockquote>`); continue; }
    if (/^---+$/.test(line.trim())) { flushPara(); out.push("<hr>"); continue; }
    if (line.trim()) para.push(line.trim()); else flushPara(); // lege regel: alinea-einde
  }
  flushPara(); closeList(); closeTable();
  if (inCode) out.push("</code></pre>");
  return out.join("\n");
}

// ---------- CVE cards UI ----------

// Debounce: na een veldwijziging de advisory direct (live) herbouwen zonder
// opnieuw op te halen — voor zover er al gegevens opgehaald zijn.
let refreshTimer = null;
function queueRefresh() {
  if (!advisories.length) return; // nog niets gegenereerd: niets te herbouwen
  clearTimeout(refreshTimer);
  refreshTimer = setTimeout(refreshOutput, 150);
}

// Bouw de advisory opnieuw uit de huidige gegevens (bijv. na een bewerkte
// beschrijving op een kaart), zonder opnieuw te fetchen. Handmatig bewerkte
// raw-tekst heeft voorrang: die wordt niet overschreven door veldwijzigingen
// (dat kan expliciet via "Opnieuw genereren uit velden").
function refreshOutput() {
  if (!advisories.length) return;
  if (!manualEdits) {
    lastMarkdown = buildMarkdown();
    previewEl.innerHTML = mdToHtml(lastMarkdown);
    rawEl.value = lastMarkdown;
  }
  toonStroomStatus(); // geweigerd stroomschema-schema meldt zich direct (eval. punt 5)
  saveState();
}

// ---------- Bewerkbare raw-markdown ----------
// De raw-tab is een textarea: een enkele zinsdraai corrigeren kan nu in de
// app zelf. Na handmatig editten bouwen veldwijzigingen de tekst niet meer
// over; de knop "Opnieuw genereren uit velden" herstelt de automatische tekst.
rawEl.addEventListener("input", () => {
  if (!advisories.length) return;
  manualEdits = true;
  lastMarkdown = rawEl.value;
  previewEl.innerHTML = mdToHtml(lastMarkdown);
  if (regenBtn) regenBtn.disabled = false;
  saveState();
});

if (regenBtn) {
  regenBtn.addEventListener("click", () => {
    manualEdits = false;
    refreshOutput();
    if (advisories.length) statusT("status.opnieuw");
  });
}

// ---------- Geschiedenis van gegenereerde advisory's ----------
// De laatste N resultaten (max HISTORY_MAX) blijven in LocalStorage bewaren
// en zijn via de dropdown terug te zetten: tekst, onderliggende CVE-gegevens,
// de ingevulde CVE-lijst én de briefvelden van dat moment (titel, nummer,
// datum, prioriteit, tekstvelden). Items van vóór de veldsnapshots herstellen
// alleen de tekst; één item of de hele lijst wissen kan via de knoppen naast
// de dropdown, en elke regel kan een eigen naam krijgen via het labelveld
// ("Testomgeving maart" in plaats van alleen een tijdstempel).

const HISTORY_KEY = "advisory-writer:history-v1";
const HISTORY_MAX = 8;

// Snapshot van de briefvelden: de content van de brief, zonder
// browservoorkeuren (API-sleutel, "Vers ophalen", "PDF via printdialoog" en
// de beschrijvingstaal — die laatste is een weergavekeuze die bij herstel
// juist NIET mee mag met een oud moment, temeer omdat de kaarten bij herstel
// vóór applyFields worden getekend) en zonder het CVE-veld (dat apart als
// cves-lijst meegaat).
const HISTORY_FIELD_IDS = MEMORIZED_FIELDS.filter(
  (id) => id !== "nvd-apikey" && id !== "no-cache" && id !== "pdf-print"
    && id !== "taal-select" && id !== "ui-taal" && id !== "cve-input"
);

function captureFields() {
  const velden = {};
  for (const id of HISTORY_FIELD_IDS) {
    const el = document.getElementById(id);
    if (!el) continue;
    const v = el.type === "checkbox" ? el.checked : el.value;
    if (v !== "" && v != null) velden[id] = v; // lege velden hoeven niet mee
  }
  return velden;
}

function applyFields(velden) {
  if (!velden) return; // oud item zonder snapshot: alleen de tekst herstellen
  for (const [id, v] of Object.entries(velden)) {
    const el = document.getElementById(id);
    if (!el) continue;
    if (el.type === "checkbox") el.checked = !!v;
    else el.value = v;
    saveField(el); // ook in het veldgeheugen: herstel overleeft een herladen
  }
}

function historyRead() {
  try { return JSON.parse(localStorage.getItem(HISTORY_KEY)) || []; }
  catch { return []; }
}

function historyPush() {
  if (!advisories.length || !lastMarkdown) return;
  const list = historyRead();
  if (list.length && list[0].markdown === lastMarkdown) return; // geen dubbele regels
  const ids = advisories.map((c) => c.id).filter(Boolean);
  const ts = new Date().toISOString();
  const label = new Intl.DateTimeFormat("nl-NL", {
    day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit", timeZone: "Europe/Amsterdam",
  }).format(new Date(ts));
  list.unshift({
    key: `${ts}`,
    label,
    ref: refInput.value.trim() || "",
    cves: ids,
    markdown: lastMarkdown,
    manual: manualEdits,
    fields: captureFields(), // veldwaarden van dit moment, voor trouw herstel
    advisories: advisories.map(compactAdvisory), // compact: alleen wat herstel nodig heeft
  });
  try {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(list.slice(0, HISTORY_MAX), jsonZonderCacheVlag));
  } catch {
    // quota: probeer met minder regels (compacte records zijn al veel kleiner
    // dan de volledige NVD-objecten, maar acht regels met grote CVSS-metrics
    // en configurations kunnen de 5 MB alsnog raken)
    try { localStorage.setItem(HISTORY_KEY, JSON.stringify(list.slice(0, 3), jsonZonderCacheVlag)); } catch { /* opgegeven */ }
  }
  renderHistory();
}

// Tekst van één dropdownregel: eigen naam (optioneel) vóór de tijdstempel;
// de tijdstempel blijft altijd zichtbaar, want die bepaalt de volgorde en het
// tijdstip. Naamloze en oude regels (zonder naamveld) tonen dus exact hetzelfde
// als voorheen. Aparte functie, zodat de notatie los testbaar is (de DOM-stub
// bewaart geen kindopties, dus via renderHistory is de tekst niet te zien).
function geschiedenisOptieTekst(e) {
  const wat = e.ref || (e.cves && e.cves[0]) || "advisory";
  return `${e.naam ? `${e.naam} \u00b7 ` : ""}${e.label} \u2014 ${wat}${e.manual ? ` ${T("hist.handmatig")}` : ""}`;
}

function renderHistory() {
  const list = historyRead();
  const prev = historySelect.value; // gemaakte keuze behouden na push/wissen
  historySelect.innerHTML = "";
  const ph = document.createElement("option");
  ph.value = "";
  ph.textContent = list.length ? "—" : T("hist.leeg");
  historySelect.appendChild(ph);
  for (const e of list) {
    const o = document.createElement("option");
    o.value = e.key;
    o.textContent = geschiedenisOptieTekst(e);
    historySelect.appendChild(o);
  }
  historySelect.value = list.some((e) => e.key === prev) ? prev : "";
  historySelect.disabled = !list.length;
  if (histDelBtn) histDelBtn.disabled = !historySelect.value;
  if (histClearBtn) histClearBtn.disabled = !list.length;
  // Het labelveld toont de naam van de geselecteerde regel (bewaarbaar met
  // Enter of blur); zonder selectie staat het leeg — een ingetypte naam bij
  // geen geselecteerde regel is een halve toestand die je beter niet laat
  // staan, en de change-handler meldt dat.
  if (histLabelInput) {
    const geselecteerd = list.find((e) => e.key === historySelect.value);
    histLabelInput.value = geselecteerd && geselecteerd.naam ? geselecteerd.naam : "";
    histLabelInput.disabled = !list.length;
  }
}

function historyRestore(key) {
  const e = historyRead().find((x) => x.key === key);
  if (!e) return;
  advisories = Array.isArray(e.advisories) ? e.advisories : [];
  lastMarkdown = e.markdown || "";
  manualEdits = !!e.manual;
  if (advisories.length) {
    renderCveCards();
    dataPanel.classList.remove("hidden");
  } else {
    // Item zónder CVE-gegevens (oud of handmatig leeg item): voorheen bleven
    // de kaarten van de vorige advisory op scherm staan, alsof ze bij de
    // herstelde tekst hoorden. Nu worden ze gewist en gaat het paneel weg.
    cveCards.innerHTML = "";
    dataPanel.classList.add("hidden");
  }
  previewEl.innerHTML = mdToHtml(lastMarkdown);
  rawEl.value = lastMarkdown;
  if (regenBtn) regenBtn.disabled = !manualEdits;
  outputPanel.classList.remove("hidden");
  copyBtn.disabled = downloadBtn.disabled = pdfBtn.disabled = false;
  if (pdfOpmaakBtn) pdfOpmaakBtn.disabled = false;
  if (e.cves && e.cves.length) {
    cveInput.value = e.cves.join("\n");
    saveField(cveInput);
  }
  applyFields(e.fields); // ook titel, nummer, datum, prioriteit en tekstvelden
  if (historySelect.value !== e.key) historySelect.value = e.key;
  // Dropdown en labelveld synchroniseren: de select staat nu op dit item,
  // dus het labelveld moet diens naam tonen (renderHistory behoudt de keuze).
  renderHistory();
  statusT("hist.hersteld", { wie: e.naam ? `${e.naam}, ` : "", label: e.label });
}

// Eigen naam voor een geschiedenisregel: de tijdstempel blijft, de naam gaat
// ervoor staan (dropdown én herstelmelding). Lege invoer maakt de regel weer
// naamloos; spaties worden gecolapst en de naam afgekapt op 60 tekens (de
// maxlength van het veld, de kap is ook voor oude/ingetikte plaktekst). De
// naam is een extra veld in de bestaande JSON: oude items zonder naam en
// items die al vóór deze functie zijn opgeslagen, gedragen zich onveranderd.
function historyRename(key, naam) {
  const list = historyRead();
  const e = list.find((x) => x.key === key);
  if (!e) return null; // intussen gewist: niets te doen
  const schone = String(naam || "").replace(/\s+/g, " ").trim().slice(0, 60);
  if (schone) e.naam = schone;
  else delete e.naam; // lege invoer = terug naar alleen de tijdstempel
  try { localStorage.setItem(HISTORY_KEY, JSON.stringify(list)); }
  catch { try { localStorage.setItem(HISTORY_KEY, JSON.stringify(list.slice(0, 3))); } catch { /* opgegeven */ } }
  renderHistory();
  return schone; // "" betekent: naamloos gemaakt
}

// Eén item wissen ("Wis item") of de hele lijst legen ("Wis alles").
function historyDelete(key) {
  const list = historyRead().filter((e) => e.key !== key);
  try { localStorage.setItem(HISTORY_KEY, JSON.stringify(list)); }
  catch { try { localStorage.setItem(HISTORY_KEY, JSON.stringify(list.slice(0, 3))); } catch { /* opgegeven */ } }
  renderHistory();
}

function historyClearAll() {
  try { localStorage.removeItem(HISTORY_KEY); } catch { /* al leeg */ }
  renderHistory();
}

// ---------- Staatsherstel: laatste resultaat bewaren voor na herladen ----------

const STATE_KEY = "advisory-writer:state-v1";

function saveState() {
  try {
    localStorage.setItem(STATE_KEY, JSON.stringify(
      { advisories: advisories.map(compactAdvisory), markdown: lastMarkdown, manual: manualEdits },
      jsonZonderCacheVlag));
  } catch { /* te groot of geblokkeerd: niet opslaan */ }
}

function restoreState() {
  let s = null;
  try { s = JSON.parse(localStorage.getItem(STATE_KEY)); } catch { s = null; }
  if (!s || !Array.isArray(s.advisories) || !s.advisories.length) return false;
  advisories = s.advisories;
  lastMarkdown = s.markdown || "";
  manualEdits = !!s.manual;
  renderCveCards();
  dataPanel.classList.remove("hidden");
  previewEl.innerHTML = mdToHtml(lastMarkdown);
  rawEl.value = lastMarkdown;
  if (regenBtn) regenBtn.disabled = !manualEdits;
  outputPanel.classList.remove("hidden");
  copyBtn.disabled = downloadBtn.disabled = pdfBtn.disabled = false;
  if (pdfOpmaakBtn) pdfOpmaakBtn.disabled = false;
  statusT("state.hersteld");
  // KEV en EPSS op de achtergrond bijladen als die gegevens ontbreken
  // (dezelfde route als in generate()). Twee losse .then-callbacks bouwden
  // de advisory hier twee keer na elkaar herbouwen; gebundeld in één
  // Promise.all is het nog één herbouw. De verzoeken dragen een eigen
  // AbortController: zodra de gebruiker zelf genereert, zijn ze achterhaald
  // (die beurt haalt KEV/EPSS zélf op) en wordt de download — bij de KEV-
  // feed al snel meerdere MB — afgebroken in plaats van ná afloop over het
  // nieuwe resultaat heen te renderen. Bij handmatig bewerkte tekst blijven
  // de kaarten met badge ververst, maar wordt de tekst niet herschreven
  // (refreshOutput doet dat zelf).
  const openKev = advisories.some((c) => !c._fetchFailed && kevInfo(c) === null);
  const openEpss = advisories.filter((c) => !c._fetchFailed && !epssInfo(c)).map((c) => c.id);
  if (openKev || openEpss.length) {
    const controller = typeof AbortController !== "undefined" ? new AbortController() : null;
    achtergrondRun = controller;
    const signaal = controller ? controller.signal : undefined;
    const nogGeldig = () => !controller || !controller.signal.aborted;
    const laden = [];
    if (openKev) laden.push(loadKev(signaal));
    if (openEpss.length) laden.push(laadEpss(openEpss, signaal));
    Promise.all(laden).then(() => {
      if (nogGeldig()) { renderCveCards(); refreshOutput(); }
    });
  }
  return true;
}

function renderCveCards() {
  cveCards.innerHTML = "";
  for (const c of advisories) {
    if (c._fetchFailed) {
      const card = document.createElement("div");
      card.className = "cve-card";
      card.innerHTML = `
        <h3>${c.id} <span class="badge unknown">${T("kaart.geen-gegevens")}</span></h3>
        <div class="warn">${T("kaart.mislukt")}</div>`;
      cveCards.appendChild(card);
      continue;
    }
    const s = overallSeverity(c);
    const m = mapSeverity(s.severity);
    const cwes = extractCwes(c);
    const products = extractProducts(c);
    const { v4, v31, v30, v20 } = cvssByFamily(c);
    const older = !v4 && !v31 ? v30 || v20 : null; // oudere CVE: alleen v3.0/v2.0
    const cvssBox = (label, mm) => {
      if (!mm || mm.score == null) {
        return `<div class="cvss-box"><span class="label">${label}</span><div class="na">${T("kaart.niet-beschikbaar")}</div></div>`;
      }
      const mb = mapSeverity(mm.severity);
      return `<div class="cvss-box"><span class="label">${label}</span>` +
        `<div><span class="badge ${mb.badge}">${ernstLabel(mm.severity)} ${mm.score}</span>` +
        `${mm.type ? ` <span class="badge unknown">${mm.type}</span>` : ""}</div>` +
        `${mm.vector ? `<code class="vector">${mm.vector}</code>` : ""}</div>`;
    };
    const status = cveStatus(c);
    const info = kevInfo(c);
    const ssvc = parseSsvc(c);
    let kevBadge = `<span class="badge unknown">${T("kaart.kev-onbekend")}</span>`;
    if (info) {
      kevBadge = info.actief
        ? `<span class="badge critical">${T("kaart.kev-actief")}${info.sinds ? ` ${T("kaart.sinds")} ${nlDate(info.sinds) || info.sinds}` : ""}</span>`
        : info.poc
          ? `<span class="badge medium">${T("kaart.poc")}</span>`
          : `<span class="badge low">${T("kaart.kev-geen")}</span>`;
    }
    const ssvcBadge = ssvc
      ? ` <span class="badge unknown" title="SSVC (CISA): exploitatie / automatability / technische impact">SSVC: ${escHtml([ssvc.exploitatie, ssvc.automatable, ssvc.technicalImpact].map((x) => x || "?").join(" / "))}</span>`
      : "";
    // EPSS-badge: groen < 0,05, geel 0,05-0,5, oranje >= 0,5 (de FIRST-
    // schaal; een hoge score = grote kans op misbruik in 30 dagen).
    const epss = epssInfo(c);
    const epssBadge = epss
      ? ` <span class="badge ${epss.score >= 0.5 ? "high" : epss.score >= 0.05 ? "medium" : "low"}" title="EPSS (FIRST): geschatte kans op misbruik in de komende 30 dagen${epss.percentile != null ? `; percentiel ${String(epss.percentile).replace(".", ",")}` : ""}">EPSS ${String(epss.score).replace(".", ",")}</span>`
      : "";
    const card = document.createElement("div");
    card.className = "cve-card";
    card.innerHTML = `
      <h3>${c.id} <span class="badge ${m.badge}">${s.severity}${s.score != null ? " " + s.score : ""}</span>
        <span class="badge unknown">${c._source || "NVD"}</span>${kevBadge}${ssvcBadge}${epssBadge}${status ? ` <span class="badge medium">${status.label}</span>` : ""}</h3>
      <textarea class="desc-edit" rows="3" spellcheck="false" aria-label="${T("kaart.desc-label", { id: c.id })}" title="${T("kaart.desc-title")}">${escHtml(bestDescription(c))}</textarea>
      <div class="cvss-boxes">${cvssBox("CVSS v4.0", v4)}${cvssBox("CVSS v3.1", v31)}${older ? cvssBox("CVSS " + older.version, older) : ""}</div>
      <div class="meta-grid">
        <div><b>${T("kaart.publicatie")}</b> ${c.published ? new Date(c.published).toLocaleDateString("nl-NL") : "?"}</div>
        <div><b>CWE:</b> ${cwes.join(", ") || "?"}</div>
      </div>
      <div class="meta-grid"><div><b>${T("kaart.producten")}</b> ${products.map(escHtml).join(", ") || T("kaart.geen-producten")}</div></div>
      ${status ? `<div class="warn">${status.note}</div>` : ""}
      ${c._source === "CVE Program API" ? `<div class="warn">${T("kaart.cveprog")}</div>` : ""}
    `;
    card.querySelector(".desc-edit").addEventListener("input", (e) => {
      c._descEdit = e.target.value;
      refreshOutput();
    });
    cveCards.appendChild(card);
  }
}

// ---------- Main flow ----------

// Retry-knop na uitval (optie 7): na een beurt met ten minste één zachte
// uitval (mislukte CVE-nummers, KEV- of EPSS-uitval, geweigerd stroomschema)
// verschijnt de knop onder de statusbalk. Hij draait een volledige nieuwe
// generatie: geslaagde nummers komen uit de CVE-cache van een uur, dus alleen
// de uitvallen gaan opnieuw het netwerk op - en een expliciete klik heft de
// KEV/EPSS-afkoelperiode op, want de gebruiker oordeelt zelf dat een storing
// voorbij is in plaats van vijf minuten te wachten. Bij een volledig
// geslaagde beurt verdwijnt de knop weer; hij weerspiegelt steeds de uitkomst
// van de LAATSTE generatiebeurt (herstel vanuit de geschiedenis laat hem
// daarom intact). De whereheid van de knop wordt bijgehouden in
// retryKnopVisible, zodat tests en eventuele toekomstige UI-logica de toestand
// kunnen opvragen zonder de DOM te lezen.
let retryKnopVisible = false;
function toonRetryKnop(toon) {
  retryKnopVisible = toon;
  if (!retryBtn) return;
  retryBtn.classList[toon ? "remove" : "add"]("hidden");
}

// Taalkeuze (optie 2): bij een andere voorkeur moeten de kaarten mee — hun
// beschrijvingsteksten zijn bij het renderen met de vorige taal ingevuld.
// Opslaan en advisory-herbouw doet het veldgeheugen al (taal-select staat in
// MEMORIZED_FIELDS: change → saveField + queueRefresh); dit is alleen de
// kaartverversing erbij.
if (taalSelect) {
  taalSelect.addEventListener("change", () => {
    if (advisories.length) renderCveCards();
  });
}

// Interface-taal (optie 2, volledig): statieveel, kaarten, geschiedenis en
// de statusregel gaan direct mee naar de nieuwe taal. Het veld onthouden
// doet het veldgeheugen al (ui-taal staat in MEMORIZED_FIELDS).
if (uiTaalSelect) {
  uiTaalSelect.addEventListener("change", () => {
    vertaalUi();
    if (advisories.length) renderCveCards();
    renderHistory();
    herhaalStatus();
  });
}

if (retryBtn) {
  retryBtn.addEventListener("click", () => {
    // Expliciet proberen = de gebruiker vindt de storing voorbij: de
    // afkoelperiodes van KEV en EPSS worden gereset, anders slaan
    // loadKev/laadEpss de poging binnen de vijf minuten over en is de
    // knop een lege belofte. Mislukte nummers staan per definitie niet in
    // de CVE-cache (alleen successen worden gecachet), dus die gaan hoe dan
    // ook opnieuw het netwerk op. De return maakt de handler afwachtbaar
    // (de tests sluiten erop aan).
    if (kevFailed) { kevFailed = false; kevFailedAt = 0; }
    if (epssFailed) { epssFailed = false; epssFailedAt = 0; }
    return generate();
  });
}

async function generate() {
  const ids = parseCveList(cveInput.value);
  const genegeerd = discardedCveTokens(cveInput.value);
  if (!ids.length) {
    // Bij een volledig ongeldige lijst is de herkenningshint extra nuttig:
    // bij typos als 2026-99999 staat meteen in de melding wat er niet werd
    // herkend, in plaats van alleen de standaardtekst.
    setStatus(T("gen.ongeldig") +
      (genegeerd.length ? T("gen.niet-herkend", { lijst: genegeerd.join(", ") }) : ""), true);
    return;
  }

  // Een nieuwe generatie maakt achtergrondverzoeken van een herstel
  // ongedaan: KEV/EPSS worden nu binnen deze beurt opgehaald, dus een
  // herbouw ná afloop van die verzoeken zou over het nieuwe resultaat heen
  // renderen. Afbreken scheelt bovendien de halve download van de KEV-feed.
  if (achtergrondRun) {
    try { achtergrondRun.abort(); } catch { /* al weg */ }
    achtergrondRun = null;
  }

  fetchBtn.disabled = true;
  copyBtn.disabled = true;
  downloadBtn.disabled = true;
  pdfBtn.disabled = true;
  if (pdfOpmaakBtn) pdfOpmaakBtn.disabled = true;
  try {
    await generateUitvoeren(ids, genegeerd);
  } catch (e) {
    // Onverwachte fout (netwerkfouten zijn dat niet: die worden per CVE
    // opgevangen en worden stubs). Zonder deze catch zou de rejection alleen
    // in de console verschijnen terwijl de statusbalk op "Ophalen..." staat.
    console.error("Advisory Writer: onverwachte fout tijdens genereren", e);
    statusT("gen.onverwacht", { reden: e.message }, true);
    toonRetryKnop(true); // ook een onverwachte fout mag met één klik opnieuw
  } finally {
    // Punt 4 schone run, uitgebreid door fix 2: álle vijf knoppen die
    // generate() hierboven uitschakelt worden altíjd weer bedienbaar — bij
    // succes, bij een onverwachte fout (bijv. een renderingbug) én bij de
    // vroegtijdige return bij een volledige ophaalmislukking. Daarvoor
    // herstelde deze finally alleen de genereerknop en de andere vier zich
    // pas in de geslaagde afloop van generateUitvoeren: na een onverwachte
    // fout of een volledige mislukking bleven kopiëren, downloaden en beide
    // PDF-knoppen op slot staan tot een geslaagde beurt.
    fetchBtn.disabled = false;
    copyBtn.disabled = false;
    downloadBtn.disabled = false;
    pdfBtn.disabled = false;
    if (pdfOpmaakBtn) pdfOpmaakBtn.disabled = false;
  }
}

// Het eigenlijke werk van generate(); onverwachte fouten worden opgevangen
// en de knoppen hersteld door de wrapper erboven.
async function generateUitvoeren(ids, genegeerd) {
  advisories = [];
  manualEdits = false; // verse generatie: de automatische tekst doet weer mee
  if (regenBtn) regenBtn.disabled = true;
  toonRetryKnop(false); // knop verdwijnt tijdens de beurt; de uitkomst bepaalt of hij terugkomt

  await loadDisclaimer(); // opnieuw proberen, zodat een nieuw geplaatst bestand direct werkt

  // Alleen CVE's die echt het netwerk op krijgen rate-limit-vertraging:
  // cachede hits worden direct teruggegeven en hoeven niet in de rij te
  // staan. De stapgrootte schaalt daarom mee met het aantal
  // netwerkophaalacties, niet met het totaal (zie nvdStapMs).
  const { net: netIdSet } = netIndexen(ids, !noCacheInput.checked);
  // Van set naar array: het chunkplafond en de chunkvertraging lopen de
  // nummers per index af.
  const netIds = [...netIdSet];
  const stap = nvdStapMs(netIds.length, !!apiKeyInput.value.trim());
  // Echte voortgang: één startmelding (met de cache-verdeling) en daarna een
  // update per VOLTOOIDE ophaalactie. De meldingen hiervoor stonden vóór de
  // eerste await in de map-callback: die draaiden allemaal synchroon op t=0,
  // zodat alleen het laatste nummer zichtbaar was in plaats van de voortgang.
  let voltooid = 0;
  const uitCacheVooraf = ids.length - netIds.length;
  statusT(ids.length === 1 ? "gen.start.1" : "gen.start.n", {
    aantal: ids.length, net: netIds.length,
    cache: uitCacheVooraf ? T("gen.cache-uit", { n: uitCacheVooraf }) : "",
  });
  // Gebundeld ophalen: de nummers die het netwerk opgaan, verdwijnen in
  // chunks van NVD_BATCH_MAX in één NVD-verzoek (parameter cveIds) in plaats
  // van één verzoek per nummer. Acht nummers kosten daarmee één verzoek in
  // plaats van acht: de beurt wordt korter en het 5-per-30s-venster gespaard.
  // Chunks worden onderling wél vertraagd (chunkindex × stap), zodat de
  // ratelimit-correctheid van nvdStapMs behouden blijft. Wat de bundelrespons
  // niet teruggeeft — bijvoorbeeld een pas gemeld nummer dat NVD nog niet
  // kent — en een compleet mislukte bundelcall, krijgt de oude route-per-CVE
  // inclusief de CVE-Program-backstop; cachede nummers doen niet mee.
  const chunks = [];
  for (let i = 0; i < netIds.length; i += NVD_BATCH_MAX) chunks.push(netIds.slice(i, i + NVD_BATCH_MAX));
  const chunkBelofte = chunks.map((chunk, k) => {
    const p = (async () => {
      if (k > 0) await new Promise((r) => setTimeout(r, k * stap));
      return await fetchNvdBatch(chunk);
    })().catch((e) => {
      // Verbeterpunt 4: een mislukte bundelcall valt terug op de route per
      // nummer, maar liet daarvoor geen spoor na — in het veld was het
      // onderscheid tussen "NVD kende dit nummer niet" en "de hele bundel
      // faalde" dan raden. Eén console.warn per chunk, met het app-prefix
      // uit de andere foutpaden en de reden erbij (de route-per-nummer
      // meldt zijn uitval zelf al via de statusbalk).
      console.warn(`Advisory Writer: gebundelde NVD-call mislukt (${e.message}); de nummers van deze chunk worden per stuk opgehaald`);
      return new Map();
    });
    return p;
  });
  const chunkVanId = new Map();
  chunks.forEach((chunk, k) => { for (const id of chunk) chunkVanId.set(id, k); });
  const results = await Promise.allSettled(ids.map(async (id) => {
    try {
      const k = chunkVanId.get(id);
      if (k === undefined) return await fetchCve(id); // cache-hit: direct teruggeven
      const cve = (await chunkBelofte[k]).get(id);
      if (cve) {
        cve._source = "NVD";
        delete cve._cached;
        cveCacheSet(id, cve); // volgende beurt is ook per nummer cache-raak
        return cve;
      }
      return await fetchCve(id); // ontbreekt in de bundel: route-per-nummer
    } finally {
      voltooid += 1;
      statusT("gen.voortgang", { id, i: voltooid, n: ids.length });
    }
  }));

  // Een mislukt CVE verdwijnt niet meer stilzwijgend uit de advisory: er komt
  // een stub ({ id, _fetchFailed }) in plaats, zodat het nummer in de tekst
  // terugkomt met de melding "gegevens niet opgehaald" — en níet als
  // "geen patch gevonden", wat een oordeel over de patch inhoudt.
  const failed = [];
  results.forEach((r, i) => {
    if (r.status === "fulfilled") advisories.push(r.value);
    else { advisories.push({ id: ids[i], _fetchFailed: true }); failed.push(ids[i]); }
  });

  if (advisories.every((c) => c._fetchFailed)) {
    advisories = [];
    setStatus(T("gen.mislukt", { lijst: failed.join(", ") }) +
      (genegeerd.length ? T("gen.niet-herkend", { lijst: genegeerd.join(", ") }) : ""), true);
    toonRetryKnop(true); // volledige mislukking: bij uitstek een-opnieuwwaardig
    return; // de finally in generate() maakt alle knoppen weer bedienbaar
  }

  // KEV-feed is terugval: alleen ophalen als de NVD-respons voor een CVE
  // geen misbruikinfo (cisaExploitAdd/SSVC) bevat. Pas ná het ophalen te
  // beoordelen, want dan zijn de CVE-gegevens pas bekend. Niet-opgehaalde
  // CVE's (stubs) slaan we over: daarvoor is de feed alsnog ophalen zonde.
  // EPSS (exploitkans): één gebundeld verzoek voor alle wél opgehaalde
  // CVE's; de 24-u-cache maakt een tweede beurt netwerkloos (zie de
  // EPSS-sectie). Niet-opgehaalde CVE's (stubs) slaan we over.
  // De twee loaders lopen parallel (fix, verbeterpunt 2): ze zijn onafhankelijk
  // (andere API, andere cache, eigen uitvalafhandeling) en voorheen telde
  // de wachttijd van de trage KEV-feed (meerdere MB) bij die van EPSS op.
  // Nu is het einde van de fase het langzaamste van de twee verzoeken in
  // plaats van de som. Beide loaders slikken hun fouten zelf in (Promise.all
  // kan hier dus niet verwerpen), en renderen/bouwen gebeurt pas ná beide.
  const nodigKev = advisories.some((c) => !c._fetchFailed && kevInfo(c) === null);
  const epssOpen = advisories.filter((c) => !c._fetchFailed).map((c) => c.id);
  const achtergrond = [];
  if (nodigKev) achtergrond.push(loadKev());
  if (epssOpen.length) achtergrond.push(laadEpss(epssOpen));
  await Promise.all(achtergrond);

  renderCveCards();
  dataPanel.classList.remove("hidden");
  refreshOutput();
  outputPanel.classList.remove("hidden");

  // De knoppen worden hier niet meer hersteld (fix 2): de finally van
  // generate() doet dat voor élke uitkomst, en vangt daarmee ook de
  // vroegtijdige return hieronder (volledige ophaalmislukking) op.
  historyPush(); // resultaat bewaren in de geschiedenis (dedup vooraf)

  const ok = advisories.filter((c) => !c._fetchFailed).length;
  const uitCache = advisories.filter((c) => c._cached).length;
  const cacheDeel = uitCache ? T("gen.cache-deel", { n: uitCache }) : "";
  const basis = failed.length
    ? T("gen.klaar-deel", { ok, cache: cacheDeel, mis: failed.length, lijst: failed.join(", ") })
    : T("gen.klaar", { ok, cache: cacheDeel });
  const epssDeel = epssFailed ? T("gen.epss-uit") : "";
  // Evaluatieronde punt 5: de afsluitende melding is bij een generatiebeurt
  // het tekststuk dat leesbaar achterblijft - refreshOutput erboven toonde
  // de stroomschema-weigering al direct, maar wordt hier overschreven.
  const stroomDeel = stroomWaarschuwing();
  setStatus(`${basis}${epssDeel}` + (genegeerd.length
    ? T("gen.niet-herkend", { lijst: genegeerd.join(", ") })
    : "") + (stroomDeel ? ` ${stroomDeel}` : ""));
  // Retry-knop (optie 7): alles wat in deze beurt is afgehaakt, is opnieuw
  // op te halen: mislukte nummers (niet gecachet), KEV/EPSS (klik heft de
  // cooldown op) en het stroomschema (veld repareren en opnieuw bouwen).
  toonRetryKnop(failed.length > 0 || kevFailed || epssFailed || !!stroomDeel);
}

// ---------- Events ----------

fetchBtn.addEventListener("click", generate);

copyBtn.addEventListener("click", async () => {
  // De Clipboard-API bestaat alleen in beveiligde context (https of
  // localhost): op http:// of in een oude browser is navigator.clipboard
  // undefined en gooit writeText ter plekke. Zonder deze guard gaf een klik
  // dan alleen een ongevangen rejection in de console zonder enige status-
  // feedback; de deellink-knop ving dat al af, nu doet de kopieerknop dat
  // ook. De tekst is in dat geval nog steeds bereikbaar via downloaden en
  // de PDF-routes.
  try {
    await navigator.clipboard.writeText(lastMarkdown);
    statusT("kopieer.gelukt");
    historyPush(); // handmatige correcties bij het kopiëren vastleggen
  } catch {
    statusT("kopieer.mislukt", null, true);
  }
});

// Deellink: kopieert een URL met de huidige CVE-lijst (?cve=...); de app
// pakt die parameter bij het openen op en haalt de gegevens direct op.
$("#share-btn").addEventListener("click", async () => {
  const ids = parseCveList(cveInput.value);
  // Deellink-basis (evaluatieronde punt 6): op een bestand-URL (file://,
  // dubbelklikken op index.html) is location.origin het letterlijke "null",
  // waardoor elke gedeelde link met "null/" begon. In dat geval is het eigen
  // adres (zonder oude query of hash) de basis; op http(s) blijft het de
  // vertrouwde origin+pathname-vorm.
  const basis = !location.origin || location.origin === "null"
    ? location.href.split(/[?#]/)[0]
    : `${location.origin}${location.pathname}`;
  const url = `${basis}?cve=${encodeURIComponent(ids.join(","))}`;
  try {
    await navigator.clipboard.writeText(url);
    statusT("share.gelukt", { url });
  } catch {
    statusT("share.url", { url });
  }
});

downloadBtn.addEventListener("click", () => {
  const blob = new Blob([lastMarkdown], { type: "text/markdown" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `${(refInput.value.trim() || "advisory").replace(/[^\w-]/g, "_")}.md`;
  a.click();
  URL.revokeObjectURL(a.href);
  historyPush(); // handmatige correcties na het exporteren vastleggen
});

// Geschiedenis: Kies een eerdere regel uit de dropdown om die advisory
// (tekst + gegevens + CVE-lijst) terug te zetten.
historySelect.addEventListener("change", () => {
  if (histDelBtn) histDelBtn.disabled = !historySelect.value;
  if (historySelect.value) historyRestore(historySelect.value);
});
if (histDelBtn) {
  histDelBtn.addEventListener("click", () => {
    if (!historySelect.value) return;
    historyDelete(historySelect.value);
    statusT("hist.verwijderd");
  });
}
if (histClearBtn) {
  histClearBtn.addEventListener("click", () => {
    historyClearAll();
    statusT("hist.gewist");
  });
}

// Eigen naam: het labelveld is gekoppeld aan de geselecteerde regel. Wijze
// op change (Enter of blur), niet op elke toets: tiken is nog geen bewaren.
if (histLabelInput) {
  histLabelInput.addEventListener("change", () => {
    const key = historySelect.value;
    if (!key) {
      histLabelInput.value = "";
      statusT("hist.kies-eerst", null, true);
      return;
    }
    const naam = historyRename(key, histLabelInput.value);
    if (naam == null) { statusT("hist.niet-vinden", null, true); return; }
    statusT(naam ? "hist.hernoemd" : "hist.naamloos", naam ? { naam } : null);
  });
}

// ---------- PDF export (jsPDF-download, printdialoog als terugval) ----------

const PRINT_CSS = `
/* Printstijl voor de printdialoog-terugval. Paginanummers via @page-margebox
   (CSS Paged Media): Chrome/Edge 131+ en Safari tonen "pagina / totaal"
   onderaan elke printpagina; Firefox negeert margeboxen nog en print dan
   geen paginanummer (wel het eigen browser-voetteks). De jsPDF-route doet
   paginanummers en lopende kop zelf in code, onafhankelijk van de browser. */
@page { size: A4; margin: 20mm 18mm 22mm 18mm;
  @bottom-center { content: counter(page) " / " counter(pages); font-size: 9pt; color: #555; } }
body { font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; color: #111; font-size: 11pt; line-height: 1.55; margin: 0; }
h1 { font-size: 16pt; border-bottom: 2.5px solid #0369a1; padding-bottom: 6px; margin: 0 0 14px; }
h2 { font-size: 12.5pt; margin: 18px 0 6px; color: #0c4a6e; page-break-after: avoid; }
h3 { font-size: 11pt; margin: 12px 0 4px; page-break-after: avoid; }
table { border-collapse: collapse; width: 100%; font-size: 9.5pt; margin: 8px 0; page-break-inside: avoid; }
th, td { border: 1px solid #999; padding: 4px 7px; text-align: left; vertical-align: top; }
th { background: #e0f2fe; }
td code { word-break: break-all; }
img { max-width: 100%; }
code { font-family: Consolas, "Courier New", monospace; font-size: 0.85em; background: #eee; padding: 0 3px; border-radius: 3px; }
blockquote { border-left: 3px solid #f59e0b; margin: 8px 0; padding: 4px 12px; background: #fffbeb; color: #333; }
a { color: #0369a1; text-decoration: none; }
hr { border: none; border-top: 1px solid #bbb; margin: 12px 0; }
ul { margin: 4px 0 8px; padding-left: 20px; }
li { margin: 2px 0; }
`;

// Zet de advisory-markdown om naar kale tekstregels met een rol per regel
// (h1 t/m h4, bul, tabel, tekst) voor de jsPDF-export: jsPDF zet zelf tekst
// en geen HTML op, dus de opmaak moet eruit en de rol bepaalt het lettertype
// in exportPdfJsPdf(). Markdown-koppelingen worden "tekst (url)", tabelrijen
// worden "cel | cel", scheidsrijen, lege regels en hr vallen weg.
function pdfRegels(md) {
  const kaal = (s) => s
    .replace(/`([^`]+)`/g, "$1")
    .replace(/\*\*([^*]+)\*\*/g, "$1")
    .replace(/\*([^*]+)\*/g, "$1")
    // Afbeelding vóór de koppeling: de tekstexport kan geen extern plaatje
    // laden, dus "![bijschrift](url)" wordt "bijschrift: url" (kaal bijschrift
    // laat alleen de URL over).
    .replace(/!\[([^\]]*)\]\(([^)]+)\)/g, (mm, a, u) => (a ? `${a}: ${u}` : u))
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, "$1 ($2)")
    .replace(/<br\s*\/?>/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  const out = [];
  for (const row of String(md).split("\n")) {
    const t = row.trim();
    if (!t || /^---+$/.test(t) || (/^\|/.test(t) && /^[\s:|-]+$/.test(t))) continue;
    let m;
    if ((m = t.match(/^(#{1,4})\s+(.*)/))) { out.push({ tekst: kaal(m[2]), stijl: `h${m[1].length}` }); continue; }
    if (/^\|/.test(t)) { out.push({ tekst: t.split("|").slice(1, -1).map(kaal).join("   |   "), stijl: "tabel" }); continue; }
    if (/^- /.test(t)) { out.push({ tekst: kaal(t.slice(2)), stijl: "bul" }); continue; }
    if (/^>\s?/.test(t)) { out.push({ tekst: kaal(t.replace(/^>\s?/, "")), stijl: "tekst" }); continue; }
    out.push({ tekst: kaal(t), stijl: "tekst" });
  }
  return out;
}

// Lopende kop voor beide PDF-routes: advisorynummer of titel, kaal gemaakt
// (" ' \ < > en newlines breken een CSS-content-string in de printdialoog)
// en afgekapt op 90 tekens. Die kap is meetkunde, geen smaak: in 8,5 pt is
// 90 tekens ruimschoots binnen het tekstvlak van 174 mm (A4 min marges),
// terwijl de eerdere 120 tekens bij lange titels over de rechterrand van de
// kop liep — jsPDF wrapt de kop niet, en center-content in een margebox ook
// niet. De ellipsis tekent de afkapping aan; U+2026 zit in de WinAnsi-
// codering van de standaard-PDF-fonts en werkt in de CSS-margebox zonder meer.
function pdfKoptekst() {
  const rauw = (refInput.value.trim() || titleInput.value.trim() || "advisory")
    .replace(/["'\\<>\n\r]/g, "");
  return rauw.length > 90 ? `${rauw.slice(0, 90)}\u2026` : rauw;
}

// Gedeelde plaatjeswacht (fix 1 raster-route): zowel de printdialoog als de
// raster-PDF moeten wachten op afbeeldingen voordat ze aan het werk gaan. De
// printdialoog omdat een onafgemaakt stroomschemabeeld anders als lege vlek
// wordt afgedrukt; de raster-route omdat daarin de kopposities worden gemeten
// in een verborgen kopie: zolang een beeld laadt heeft het hoogte 0, dus alle
// koppen eronder staan te hoog gemeten en worden de repen op de verkeerde
// plekken afgesneden. Werkt op een document (.images) én op een element
// (querySelectorAll). De cap (standaard 3 s) voorkomt dat één onbereikbaar
// plaatje de export eindeloos ophoudt; een onafgemaakt beeld gaat dan zoals
// voorheen door.
function wachtOpPlaatjes(wortel, capMs = 3000) {
  return new Promise((resolve) => {
    // Een echte <img> heeft altijd addEventListener; de extra check houdt
    // de helper ook veilig voor nep-elementen zonder (zoals de
    // koppositie-stubs van de testharness, die dezelfde querySelectorAll
    // delen met de plaatjeszoek).
    const imgEls = [...(wortel.images || wortel.querySelectorAll("img"))]
      .filter((i) => i && !i.complete && typeof i.addEventListener === "function");
    if (!imgEls.length) return resolve();
    let nog = imgEls.length;
    const klaar = () => { if (--nog <= 0) resolve(); };
    for (const i of imgEls) { i.addEventListener("load", klaar); i.addEventListener("error", klaar); }
    setTimeout(resolve, capMs);
  });
}

// Echte PDF-download via jsPDF (window.jspdf, UMD-build van de CDN): A4 met
// marges, rollen per regelsoort, paginanummers en lopende kop onderaan en
// bovenaan elke pagina. Tekstexport zonder HTML-opmaak: vetgedrukte
// CVSS-scores en tabellen worden kaal gezet, de inhoud blijft volledig.
function exportPdfJsPdf() {
  const { jsPDF } = window.jspdf;
  // Bewust geen extra opties meegegeven. De optie "useFileSaveAs" die hier
  // eerder stond, bestaat in géén enkele jsPDF-versie: de officiële type-
  // definitie van 4.x kent alleen orientation, unit, format, compress,
  // precision, filters, userUnit, encryption, putOnlyUsedFonts, hotfixes en
  // floatPrecision; onbekende opties worden door de constructor stil
  // genegeerd. Het oude Firefox-probleem waarbij een blob in het venster
  // werd geopend in plaats van gedownload (jsPDF-issue #3391) wordt
  // afgehandeld door FileSaver.js, dat jsPDF's save() zelf al gebruikt.
  const doc = new jsPDF({ unit: "mm", format: "a4" });
  const M = { l: 18, r: 18, t: 20, b: 20 }; // marges in mm
  const breed = 210 - M.l - M.r;
  const STIJLEN = {
    h1: { size: 14, weight: "bold", na: 3.2 },
    h2: { size: 11.5, weight: "bold", na: 2.6 },
    h3: { size: 10.5, weight: "bold", na: 2 },
    h4: { size: 10, weight: "bold", na: 1.8 },
    bul: { size: 10, weight: "normal", na: 1.1 },
    tabel: { size: 9, weight: "normal", na: 1.1 },
    tekst: { size: 10, weight: "normal", na: 2.6 },
  };
  const bronRegels = pdfRegels(lastMarkdown);
  let y = M.t;
  for (let i = 0; i < bronRegels.length; i++) {
    const r = bronRegels[i];
    const s = STIJLEN[r.stijl] || STIJLEN.tekst;
    doc.setFont("helvetica", s.weight);
    doc.setFontSize(s.size);
    doc.setTextColor(0);
    const indent = r.stijl === "bul" ? 5 : 0;
    const regels = doc.splitTextToSize((r.stijl === "bul" ? "\u2022 " : "") + r.tekst, breed - indent);
    const lijnH = s.size * 0.45; // pt naar mm, royaal regelinterval
    // Weeskopbescherming: een kop is nooit de laatste regel van een pagina
    // (het equivalent van page-break-after: avoid in de printstijl). Past er
    // onder hem geen enkele regel meer, dan schuift de kop door. Gemeten:
    // kop + tussenruimte + eerste regel van de opvolger.
    const isKop = /^h[1-4]$/.test(r.stijl);
    if (isKop && i + 1 < bronRegels.length) {
      const sVolg = STIJLEN[bronRegels[i + 1].stijl] || STIJLEN.tekst;
      if (y + regels.length * lijnH + s.na + sVolg.size * 0.45 > 297 - M.b) { doc.addPage(); y = M.t; }
    }
    for (const ln of regels) {
      if (y + lijnH > 297 - M.b) { doc.addPage(); y = M.t; }
      doc.text(ln, M.l + indent, y);
      y += lijnH;
    }
    y += s.na;
  }
  // Lopende kop en paginanummers op elke pagina (het equivalent van de
  // margeboxen van de printdialoog, nu browseronafhankelijk). De kop komt uit
  // pdfKoptekst(): dezelfde helper als de printdialoog, dus dezelfde
  // striping en dezelfde afkapping.
  const koptekst = pdfKoptekst();
  const nPages = doc.getNumberOfPages();
  doc.setFont("helvetica", "normal");
  doc.setFontSize(8.5);
  doc.setTextColor(110);
  for (let i = 1; i <= nPages; i++) {
    doc.setPage(i);
    doc.text(koptekst, M.l, 12);
    doc.text(`${i} / ${nPages}`, 105, 290, { align: "center" });
  }
  doc.save(`${(refInput.value.trim() || "advisory").replace(/[^\w-]/g, "_")}.pdf`);
}

// Welke route de PDF-export kiest: "jspdf" (echte download) of "printen"
// (browserprintdialoog). jsPDF wint alleen als de CDN-bibliotheek daad-
// werkelijk geladen is (window.jspdf) én het vink "PDF via printdialoog"
// uit staat; offline, CDN geblokkeerd, vink aan of een exportfout die door
// exportPdf wordt opgevangen: steeds de printdialoog. Aparte functie, zodat
// de route los testbaar is zonder een echte jsPDF te hoeven laden.
function pdfRoute() {
  const viaPrint = typeof pdfPrintInput !== "undefined" && pdfPrintInput && pdfPrintInput.checked;
  const pdfKlaar = typeof window !== "undefined" && window.jspdf && window.jspdf.jsPDF;
  return !viaPrint && pdfKlaar ? "jspdf" : "printen";
}

function exportPdf() {
  if (!lastMarkdown) return;
  if (pdfRoute() === "jspdf") {
    try {
      exportPdfJsPdf();
      statusT("pdf.jspdf-klaar");
      return;
    } catch (e) {
      // Bijv. een onverwacht markdown- of geheugenprobleem: de printdialoog
      // kan alsnog, dus de gebruiker krijgt geen dood spoor.
      console.error("Advisory Writer: jsPDF-export mislukt; printdialoog als terugval", e);
    }
  }
  exportPdfPrinten();
}

// --- paged.js in de printdialoog (optie 3) --------------------------------
// De browserprintdialoog printte het document tot nu toe met de eigen
// paginering van de browser: margeboxen (paginanummers, lopende kop) werkten
// daar niet in Firefox, en de papiere uitkomst week per browser iets af. Met
// de pagedjs-polyfill (CSS Paged Media in JS) paginéért de pagina ZELF het
// document: vaste A4-pagina-elementen met de margeboxen uit PRINT_CSS erin,
// broakbescherming op echte regelgeometrie (de 14-mm-benadering van de
// raster-snijder is dan verleden) en een identieke uitkomst in elke browser.
// De polyfill loadt in het print-iframe, niet op de app-pagina: hij
// herpagineert het document waarin hij laadt, en dat moet het afdrukdocument
// zijn met de printstijl erin. auto:false omdat de start van de paginering
// wacht tot de afbeeldingen binnen zijn (meting vóór die tijd geeft pagina's
// op de verkeerde plekken); de parent geeft het startschot.
// Tekst blijft selecteerbaar — dit is HTML, geen raster.
// SRI: pagedjs staat niet op cdnjs (zocht 27-11-2026), dus jsDelivr met de
// sha256-integrity uit de jsDelivr-pakkette-API voor exact dit bestand.
const PAGED_CDN_URL = "https://cdn.jsdelivr.net/npm/pagedjs@0.4.3/dist/paged.polyfill.min.js";
const PAGED_SRI = "sha256-9E41ptUQbYGcNBX9OFkd4E04NDQ8FOUKViuEJX4gRpI=";
// Watchdog: de paged-seinen (script klaar/mislukt) worden alleen afwacht
// zolang de afdrukbeurt nog niet uit eigen beweging print. Een CDN die noch
// laadt noch faalt (trage intranetproxy) mag de printdialoog niet
// vastzetten: na deze cap gaat de dialoog open zoals voorheen, kaal.
const PAGED_WATCHDOG_MS = 4000;

// Het kopje HTML dat de polyfill en het startknopje in het printdocument
// zet. pdfStartPaged wordt door de parent aangeroepen (na de plaatjeswacht);
// de onload/onerror-attributen melden het script terug aan de parent via de
// callbackvensters die exportPdfPrinten op het iframe-window zet.
const PAGED_HTML =
  `<script>` +
  `window.PagedConfig = { auto: false };` +
  `window.pdfStartPaged = function () {` +
  `  try {` +
  `    var p = new window.Paged.Previewer();` +
  // Na het herpagineren worden de browsermarges op 0 gezet: de polyfill
  // maakt pagina's van exact 210x297 mm, en de browser mag er bij het
  // afdrukken geen eigen marges (en dus extra pagina's) omheen zetten.
  `    p.preview().then(function () {` +
  `      var s = document.createElement("style");` +
  `      s.textContent = "@page { margin: 0; }";` +
  `      document.head.appendChild(s);` +
  `      window.pdfPagedAf();` +
  `    }, window.pdfPagedAf);` +
  `  } catch (e) { window.pdfPagedAf(); }` +
  `};` +
  `<\/script>` +
  `<script async crossorigin="anonymous" src="${PAGED_CDN_URL}" integrity="${PAGED_SRI}"` +
  ` onload="window.pdfPagedScriptKlaar && window.pdfPagedScriptKlaar()"` +
  ` onerror="window.pdfPagedScriptMislukt && window.pdfPagedScriptMislukt()"><\/script>`;

function exportPdfPrinten() {
  if (!lastMarkdown) return;
  const iframe = document.createElement("iframe");
  iframe.setAttribute("aria-hidden", "true");
  Object.assign(iframe.style, { position: "fixed", right: "0", bottom: "0", width: "0", height: "0", border: "0", visibility: "hidden" });
  document.body.appendChild(iframe);

  const docTitle = (refInput.value.trim() || titleInput.value.trim() || "advisory")
    .replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const doc = iframe.contentWindow.document;
  // Opruimen gebeurt via het afterprint-event van het print-iframe zelf, niet
  // meer na een vaste 1 s: print() geeft in Firefox/Safari níet blokkerend
  // terug, dus het iframe kon worden verwijderd terwijl de printdialoog nog
  // open was. afterprint vuurt pas als de printactie echt is afgerond; de
  // timeout is alleen een vangnet voor browsers zonder dat event (de vlag
  // voorkomt dubbel opruimen als beidebronnen afgaan).
  let verwijderd = false;
  const cleanup = () => {
    if (verwijderd) return;
    verwijderd = true;
    iframe.contentWindow.removeEventListener("afterprint", cleanup);
    iframe.remove();
  };
  iframe.contentWindow.addEventListener("afterprint", cleanup);
  setTimeout(cleanup, 120000); // vangnet: ná 2 min is élke afdrukbeurt klaar
  // Wacht na het load-event expliciet op de afbeeldingen in het geschreven
  // document: een stroomschema-afbeelding vanaf een trage URL (bijv. intranet)
  // was bij het afdrukken nog niet geladen en gaf dan een leeg vlek in de
  // print. Het window-load-event wacht in moderne browsers weliswaar op
  // subresources, maar de toewijzing van onload kan ook een about:blank-load
  // vangen waarop nog geen plaatjes in het document zaten — dus worden ze
  // hier zelf nagelopen (gedeelde helper met de raster-PDF, zie
  // wachtOpPlaatjes: één bron, dezelfde cap van 3 s).
  // Eén load-event kan van de about:blank-documentslag komen en één van het
  // geschreven document: print dus maximaal één keer per exportbeurt.
  let afgedrukt = false;
  const printNu = () => {
    if (afgedrukt) return;
    afgedrukt = true;
    setTimeout(() => {
      try {
        iframe.contentWindow.focus(); // nodig in sommige browsers
        iframe.contentWindow.print();
      } catch (e) {
        statusT("pdf.print-open-fout", null, true);
        cleanup(); // print ging niet open: geen afterprint om op te wachten
      }
    }, 250); // korte vertraging zodat styling is toegepast
  };
  // paged-machine (optie 3): de print gaat pas af als ZOWEL de
  // plaatjeswacht als het paged-script zich hebben gemeld. Het script kan
  // twee kanten op eerder klaar zijn dan de plaatjes of later; beide
  // volgorde-folden hier samen in pagedProbeer. Een gemeld maar afwezig
  // Paged-object (SRI-verwerpeling zonder error-event) telt als kaal.
  const w = iframe.contentWindow;
  let plaatjesKlaar = false;
  let pagedGemeld = false; // script heeft zich gemeld (klaar óf mislukt)
  let pagedModus = "kaal"; // "paged" als de polyfill er werkelijk is
  let pagedGestart = false;
  const pagedProbeer = () => {
    if (afgedrukt || !plaatjesKlaar || !pagedGemeld) return;
    if (pagedModus === "paged" && typeof w.pdfStartPaged === "function") {
      if (pagedGestart) return;
      pagedGestart = true;
      clearTimeout(pagedWatchdog); // paginering loopt: die mag duren
      try { w.pdfStartPaged(); } catch { printNu(); } // pdfPagedAf print daarna
      return;
    }
    printNu(); // kaal: de browser paginéért zelf, zoals altijd
  };
  w.pdfPagedScriptKlaar = () => {
    if (!pagedGemeld) { pagedGemeld = true; pagedModus = w.Paged ? "paged" : "kaal"; }
    pagedProbeer();
  };
  w.pdfPagedScriptMislukt = () => {
    if (!pagedGemeld) { pagedGemeld = true; pagedModus = "kaal"; }
    pagedProbeer();
  };
  w.pdfPagedAf = () => printNu(); // na de paginering (succes of fout) printen
  // Vangnet: een CDN die zich noch meldt noch faalt (trage proxy), mag de
  // dialoog niet vastzetten. De watchdog dekt alleen de scriptfase; zodra
  // de paginering zelf loopt, is die overbodig en wordt hij afgelast (die
  // kan bij een lange advisory gerust langer dan de cap duren).
  const pagedWatchdog = setTimeout(printNu, PAGED_WATCHDOG_MS);
  // onload VÓÓR het schrijven toewijzen: bij document.write/close kan het
  // load-event al vóór de toewijzing afvuren, waardoor print() nooit draaide.
  iframe.onload = () => {
    wachtOpPlaatjes(doc).then(() => { plaatjesKlaar = true; pagedProbeer(); });
  };
  doc.open();
  // Lopende kop op elke printpagina: advisorynummer/titel via een margebox,
  // zodat pagina 2 en verder herleidbaar blijven. Striping (CSS-content-
  // string breekt op " ' \) en afkapping komen uit pdfKoptekst(), dezelfde
  // helper als de jsPDF-route.
  const koptekst = pdfKoptekst();
  doc.write(
    `<!DOCTYPE html><html lang="nl"><head><meta charset="utf-8"><title>${docTitle}</title>` +
    `<style>${PRINT_CSS}</style>` +
    `<style>@page { @top-center { content: "${koptekst}"; font-size: 8.5pt; color: #777; } }</style>` +
    PAGED_HTML + // paged.js-polyfill + startknopje (zie PAGED_HTML hierboven)
    `</head><body>${previewEl.innerHTML}</body></html>`
  );
  doc.close();
  statusT("pdf.print-geopend");
}

// --- html2canvas: PDF "met opmaak" (tweede externe bron) ------------------
// De jsPDF-download tekent kale tekst: tabelkaders, badge-kleuren en het
// stroomschema-beeld vallen daar weg. html2canvas (CDN, async + SRI, zoals
// jsPDF) fotografeert de opgemaakte preview als raster en legt die per
// A4-pagina op een PDF: wél opmaak, maar de tekst is niet selecteerbaar en
// externe plaatjes (stroomschema vanaf een intranet zonder CORS-header)
// kunnen in de foto ontbreken. Twee terugvallen, net als bij de andere
// knoppen: de CDN-bibliotheken zijn er niet, of de run faalt →
// printdialoog. Tekenen kost seconden: vandaar de knop-op-slot tijdens de
// run (onder de PDF-knoppen is dit de trage route).
function html2canvasKlaar() {
  return typeof window !== "undefined" && typeof window.html2canvas === "function";
}

async function exportPdfMetOpmaak() {
  if (!lastMarkdown) return;
  if (!html2canvasKlaar() || !window.jspdf || !window.jspdf.jsPDF) {
    statusT("pdf.h2c-ontbreekt");
    exportPdfPrinten();
    return;
  }
  statusT("pdf.h2c-run");
  try {
    // Verborgen kopie van de preview op vaste breedte fotograferen
    // (174 mm ≈ 658 px bij 96 dpi, dezelfde marges als de jsPDF-tekstroute),
    // zodat het beeld niet meebeweegt met het browservenster.
    const bron = document.createElement("div");
    bron.style.cssText = "position:fixed;left:-9999px;top:0;width:658px;background:#fff;padding:0 6px";
    const binnen = document.createElement("div");
    binnen.className = "preview";
    binnen.innerHTML = previewEl.innerHTML;
    bron.appendChild(binnen);
    document.body.appendChild(bron);
    // De kopposities worden gelezen terwijl de kopie nog in het document
    // staat: losgemaakt is offsetTop overal 0. De kopie staat vast op top:0
    // en heeft geen verticale padding, zodat de offsetTop van de koppen
    // (ten opzichte van de kopie) één-op-één de foto ingaat, vermenigvuldigd
    // met de schaalfactor van html2canvas.
    const schaal = 2;
    let canvas;
    let kopPxs = [];
    try {
      // Eerst wachten op de beelden, dan pas tekenen en meten (fix 1,
      // raster-route): een lui stroomschemabeeld in de off-screen kopie
      // laden niet vanzelf en heeft tijdens het laden hoogte 0. html2canvas
      // zou het beeld wél tekenen (eigen imagelader), maar de offsetTop van
      // de koppen eronder was te laag gemeten en de repen snijden dan op de
      // verkeerde plekken. Dus: eager laden forceren en wachten met
      // dezelfde helper als de printdialoog (incl. diens cap van 3 s).
      for (const img of binnen.querySelectorAll("img")) img.loading = "eager";
      await wachtOpPlaatjes(binnen);
      canvas = await window.html2canvas(bron, { scale: schaal, useCORS: true, backgroundColor: "#ffffff" });
      kopPxs = [...binnen.querySelectorAll("h1, h2, h3, h4")].map((el) => el.offsetTop * schaal);
    } finally {
      bron.remove(); // ook bij een mislukte tekening netjes opruimen
    }
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF({ unit: "mm", format: "a4" }); // dezelfde kale opties als exportPdfJsPdf
    const M = { l: 18, r: 18, t: 20, b: 22 }; // marges; b ruimer voor het paginanummer
    const breed = 210 - M.l - M.r;
    const hoogte = 297 - M.t - M.b;
    // De foto wordt in repen van exact één paginahoogte gesneden; per reep
    // één losse afbeelding (één lange reep op één pagina zou uitrekken).
    // JPEG houdt de download binnen de perken; PNG kost per pagina MB's.
    const mmPerPx = breed / canvas.width;
    const pxPerPagina = Math.floor(hoogte / mmPerPx);
    // Weeskopbescherming op de repengrens: een kop die binnen KOP_HOUD mm
    // van de onderkant van een reep valt, schuift met zijn eerste
    // inhoudsregel door naar de volgende pagina; de reep wordt korter.
    // Zonder deze bescherming kon een kop eenzaam onderaan een pagina
    // eindigen terwijl de tekst eronder al op de volgende pagina stond -
    // de tekstexport en de printdialoog hadden deze bescherming al.
    const KOP_HOUD = 14; // mm: kop plus ruwweg één inhoudsregel
    const kopHoudPx = KOP_HOUD / mmPerPx;
    let yPx = 0;
    for (let pagina = 0; yPx < canvas.height; pagina++) {
      if (pagina) doc.addPage();
      let reepPx = Math.min(pxPerPagina, canvas.height - yPx);
      const isRest = canvas.height - yPx <= pxPerPagina; // laatste reep: geen grens meer te beschermen
      if (!isRest) {
        const einde = yPx + reepPx;
        let snij = Infinity;
        for (const h of kopPxs) {
          if (h > yPx + 1 && h < einde && einde - h < kopHoudPx && h < snij) snij = h;
        }
        if (snij < Infinity) reepPx = snij - yPx - 1; // kop wordt eerste regel van de volgende reep
      }
      const reep = document.createElement("canvas");
      reep.width = canvas.width;
      reep.height = reepPx;
      reep.getContext("2d").drawImage(canvas, 0, yPx, canvas.width, reepPx, 0, 0, canvas.width, reepPx);
      doc.addImage(reep.toDataURL("image/jpeg", 0.92), "JPEG", M.l, M.t, breed, reepPx * mmPerPx);
      yPx += reepPx;
    }
    // Lopende kop en paginanummers op elke pagina, zoals in de jsPDF- en
    // printdialoog-route: de foto zelf draagt de titel alleen op pagina 1,
    // dus pagina 2 en verder zijn zonder deze margevulling minder herleidbaar.
    const nPages = doc.getNumberOfPages();
    const koptekst = pdfKoptekst();
    doc.setFont("helvetica", "normal");
    doc.setFontSize(8.5);
    doc.setTextColor(110);
    for (let i = 1; i <= nPages; i++) {
      doc.setPage(i);
      doc.text(koptekst, M.l, 12);
      doc.text(`${i} / ${nPages}`, 105, 290, { align: "center" });
    }
    doc.save(`${(refInput.value.trim() || "advisory").replace(/[^\w-]/g, "_")}-opmaak.pdf`);
    statusT("pdf.h2c-klaar");
  } catch (e) {
    // Meestal een door CORS geblokkeerd extern plaatje in de preview of een
    // html2canvas-interne fout; de printdialoog kan in beide gevallen altijd.
    console.error("Advisory Writer: html2canvas-export mislukt; printdialoog als terugval", e);
    statusT("pdf.h2c-fout");
    exportPdfPrinten();
  }
}

pdfBtn.addEventListener("click", () => {
  exportPdf();
  historyPush(); // handmatige correcties bij het exporteren vastleggen
});

// De "PDF met opmaak"-knop: async (tekenen duurt), dus de knop gaat tijdens
// de run op slot — dubbelklikken gaf anders twee downloads naast elkaar.
if (pdfOpmaakBtn) {
  pdfOpmaakBtn.addEventListener("click", async () => {
    pdfOpmaakBtn.disabled = true;
    try {
      await exportPdfMetOpmaak();
      historyPush(); // ook een opgemaakte export telt als gegenereerde versie
    } finally {
      pdfOpmaakBtn.disabled = false;
    }
  });
}

// De tabs zijn toggle-knoppen: naast de class wordt ook aria-pressed gezet,
// zodat een schermlezer meldt welke weergave actief is (A11y, punt 6).
$("#tab-preview").addEventListener("click", () => {
  $("#tab-preview").classList.add("active"); $("#tab-raw").classList.remove("active");
  $("#tab-preview").setAttribute("aria-pressed", "true"); $("#tab-raw").setAttribute("aria-pressed", "false");
  previewEl.classList.remove("hidden"); rawEl.classList.add("hidden");
});
$("#tab-raw").addEventListener("click", () => {
  $("#tab-raw").classList.add("active"); $("#tab-preview").classList.remove("active");
  $("#tab-raw").setAttribute("aria-pressed", "true"); $("#tab-preview").setAttribute("aria-pressed", "false");
  rawEl.classList.remove("hidden"); previewEl.classList.add("hidden");
});

// defaults: eerst opgeslagen velden herstellen, daarna alleen nog lege
// velden voorzien van een automatische standaardwaarde.
initFieldMemory();
vertaalUi(); // bediening in de (herstelde of automatische) interface-taal
const urlCve = new URLSearchParams(location.search).get("cve");
if (urlCve) {
  // Via de deellink geplakte rommel (puntjes, losse komma's) netjes opschonen;
  // onbruikbare stukjes laten we achter, want de rest van de app leest de
  // ruwe invoer en moet dezelfde nummers zien als de URL.
  const ids = parseCveList(urlCve);
  cveInput.value = ids.length ? ids.join("\n") : urlCve.trim();
}
if (!cveInput.value.trim()) cveInput.value = "CVE-2026-123158";
if (!dateInput.value.trim()) dateInput.value = nowNl();
if (!versieInput.value.trim()) versieInput.value = "1.0";
loadDisclaimer(); // statusmelding bij openen van de pagina
renderHistory(); // geschiedenisdropdown vullen (indien aanwezig)

if (urlCve) {
  generate(); // gedeelde link: direct ophalen
} else {
  restoreState(); // laatste resultaat terugzetten (indien aanwezig)
}
