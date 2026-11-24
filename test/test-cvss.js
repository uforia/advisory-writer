/* Test harness: verifies CVSS-parsing tegen echte NVD API 2.0 payloadvormen.
   Run: node test/test-cvss.js  (offline — payloads ingebed) */
"use strict";

// ---- copy of the logic in app.js (kept in sync) ----
function collectCvss(cve) {
  const out = [];
  const push = (arr, version) => { for (const d of arr || []) out.push({ ...d, _version: version }); };
  const m = cve.metrics;
  if (Array.isArray(m)) {
    for (const entry of m) {
      push(entry.cvssMetricV40, "4.0"); push(entry.cvssMetricV31, "3.1");
      push(entry.cvssMetricV30, "3.0"); push(entry.cvssMetricV2, "2.0");
    }
  } else if (m && typeof m === "object") {
    push(m.cvssMetricV40, "4.0"); push(m.cvssMetricV31, "3.1");
    push(m.cvssMetricV30, "3.0"); push(m.cvssMetricV2, "2.0");
  }
  return out;
}
function overallSeverity(cve) {
  const metrics = collectCvss(cve).filter((d) => d.cvssData?.baseScore != null);
  const chosen = metrics.find((d) => d.type === "Primary") || metrics[0];
  if (chosen) {
    return {
      severity: chosen.cvssData.baseSeverity || chosen.severity || "UNKNOWN",
      score: chosen.cvssData.baseScore, vector: chosen.cvssData.vectorString,
      version: chosen._version, type: chosen.type, source: chosen.source,
    };
  }
  return { severity: "UNKNOWN" };
}
function pickMetric(cve, version) {
  const metrics = collectCvss(cve).filter((d) => d._version === version && d.cvssData?.baseScore != null);
  const chosen = metrics.find((d) => d.type === "Primary") || metrics[0];
  if (!chosen) return null;
  return {
    score: chosen.cvssData.baseScore,
    severity: chosen.cvssData.baseSeverity || chosen.severity || "UNKNOWN",
    vector: chosen.cvssData.vectorString,
    version, type: chosen.type, source: chosen.source,
  };
}
function cvssByFamily(cve) { return { v4: pickMetric(cve, "4.0"), v31: pickMetric(cve, "3.1") }; }
const SEVERITY_MAP = {
  LOW: { prioriteit: "Laag" }, MEDIUM: { prioriteit: "Middel" },
  HIGH: { prioriteit: "Hoog" }, CRITICAL: { prioriteit: "Kritiek" },
};
function mapSeverity(sev) { return SEVERITY_MAP[(sev || "").toUpperCase()] || { prioriteit: "Onbekend" }; }
function cvssCell(m) {
  if (!m || m.score == null) return "*Niet beschikbaar*";
  let s = `**${m.score} (${mapSeverity(m.severity).prioriteit})**`;
  if (m.type) s += ` \u2014 ${m.type}`;
  if (m.vector) s += `<br>Vector: \`${m.vector}\``;
  return s;
}
function normalizeCnaMetrics(cna) {
  const out = {};
  const KEYMAP = {
    cvssV4_0: "cvssMetricV40", cvssV40: "cvssMetricV40",
    cvssV3_1: "cvssMetricV31", cvssV31: "cvssMetricV31",
    cvssV3_0: "cvssMetricV30", cvssV30: "cvssMetricV30",
    cvssV2_0: "cvssMetricV2", cvssV20: "cvssMetricV2",
  };
  const entries = Array.isArray(cna.metrics) ? cna.metrics : [cna.metrics].filter(Boolean);
  for (const entry of entries)
    for (const [key, target] of Object.entries(KEYMAP))
      if (entry[key]) (out[target] ||= []).push({ type: "Primary", source: "CNA", cvssData: entry[key] });
  return out;
}

// ---- test cases (real payload shapes) ----
let pass = 0, fail = 0;
function check(name, actual, expected) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}  ->  ${JSON.stringify(actual)}${ok ? "" : "  (verwacht: " + JSON.stringify(expected) + ")"}`);
  ok ? pass++ : fail++;
}

// 1. CVE-2026-99999 (live NVD payload): only a *Secondary* (CNA) metric,
//    baseSeverity lives inside cvssData — the old code read d.severity and found nothing.
const cve99999 = { metrics: { cvssMetricV31: [{
  source: "416baaa9-...", type: "Secondary",
  cvssData: { version: "3.1", vectorString: "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", baseScore: 9.3, baseSeverity: "CRITICAL" },
}], ssvcV203: [{}] } };
const s1 = overallSeverity(cve99999);
check("99999: Secondary CNA-score wordt gevonden", [s1.score, s1.severity, s1.version], [9.3, "CRITICAL", "3.1"]);
check("99999: vectorstring aanwezig", typeof s1.vector === "string" && s1.vector.startsWith("CVSS:3.1/"), true);

// 2. Primary (NVD analysis) wint van Secondary (CNA)
const both = { metrics: { cvssMetricV31: [
  { type: "Secondary", cvssData: { baseScore: 9.3, baseSeverity: "CRITICAL", vectorString: "CVSS:3.1/X" } },
  { type: "Primary",   cvssData: { baseScore: 8.1, baseSeverity: "HIGH", vectorString: "CVSS:3.1/Y" } },
] } };
const s2 = overallSeverity(both);
check("Primary kiest boven Secondary", [s2.score, s2.type], [8.1, "Primary"]);

// 3. Legacy-shape metric met alleen top-level "severity" (geen baseSeverity)
const legacy = { metrics: { cvssMetricV31: [{ type: "Primary", severity: "HIGH", cvssData: { baseScore: 8.1, vectorString: "CVSS:3.1/Z" } }] } };
check("Legacy severity-veld werkt nog", overallSeverity(legacy).severity, "HIGH");

// 4. CVSS 4.0 heeft voorrang (overallSeverity) én cvssByFamily levert beide apart
const v40 = { metrics: {
  cvssMetricV40: [{ type: "Primary", cvssData: { baseScore: 7.0, baseSeverity: "HIGH", vectorString: "CVSS:4.0/..." } }],
  cvssMetricV31: [{ type: "Primary", cvssData: { baseScore: 8.1, baseSeverity: "HIGH", vectorString: "CVSS:3.1/..." } }],
} };
check("CVSS 4.0 heeft voorrang (overallSeverity)", overallSeverity(v40).version, "4.0");

const families = cvssByFamily(v40);
check("cvssByFamily: v4.0 en v3.1 naast elkaar (twee vakken)",
  [[families.v4.score, families.v4.version], [families.v31.score, families.v31.version]],
  [[7.0, "4.0"], [8.1, "3.1"]]);

// 5. CVE Program API (JSON 5.x) normalisatie: metrics = array met cvssV3_1-sleutel
const cna = normalizeCnaMetrics({ metrics: [{ cvssV3_1: { vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", baseScore: 8.1, baseSeverity: "HIGH" } }] });
check("CNA cvssV3_1 -> cvssMetricV31", overallSeverity({ metrics: cna }).score, 8.1);
check("CNA: cvssByFamily vindt v3.1, v4.0 ontbreekt",
  [cvssByFamily({ metrics: cna }).v4, cvssByFamily({ metrics: cna }).v31.score], [null, 8.1]);

// 6. Geen metrics
check("Geen metrics -> UNKNOWN", overallSeverity({}).severity, "UNKNOWN");

// 7. Ontbrekende familie -> null -> celtekst 'Niet beschikbaar'
const onlyV31 = cvssByFamily(cve99999);
check("cvssByFamily: alleen v3.1, v4.0 is null", [onlyV31.v4, onlyV31.v31.score], [null, 9.3]);
check("cvssCell: ontbrekend -> Niet beschikbaar", cvssCell(onlyV31.v4), "*Niet beschikbaar*");
check("cvssCell: aanwezig -> score + ernst + vector",
  cvssCell(onlyV31.v31),
  "**9.3 (Kritiek)** \u2014 Secondary<br>Vector: `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`");

// 8. cvssByFamily kiest binnen een familie Primary boven Secondary
const mixed = { metrics: {
  cvssMetricV40: [{ type: "Secondary", cvssData: { baseScore: 6.0, baseSeverity: "MEDIUM", vectorString: "CVSS:4.0/S" } }],
  cvssMetricV31: [
    { type: "Secondary", cvssData: { baseScore: 9.3, baseSeverity: "CRITICAL", vectorString: "CVSS:3.1/S" } },
    { type: "Primary",   cvssData: { baseScore: 8.1, baseSeverity: "HIGH", vectorString: "CVSS:3.1/P" } },
  ],
} };
const fam2 = cvssByFamily(mixed);
check("cvssByFamily: per familie Primary boven Secondary",
  [[fam2.v4.score, fam2.v4.type], [fam2.v31.score, fam2.v31.type]],
  [[6.0, "Secondary"], [8.1, "Primary"]]);

console.log(`\n${pass} passed, ${fail} failed`);
if (typeof process !== "undefined") process.exit(fail ? 1 : 0);
