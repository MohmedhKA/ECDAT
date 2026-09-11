const pptxgen = require("pptxgenjs");
let pres = new pptxgen();
pres.layout = "LAYOUT_WIDE"; // 13.33 x 7.5 inches

// ─── Design Tokens ───────────────────────────────────────────────────────────
const NAVY       = "1E2761";
const TEAL       = "028090";
const ACCENT_BLUE= "2F3C7E";
const BLACK      = "1A1A1A";
const GRAY       = "5A5A5A";
const LGRAY      = "E5E7EB";
const WHITE      = "FFFFFF";
const LBLUE      = "EEF2FF";   // Light blue container fill
const LCYAN      = "E6F7F9";   // Light teal container fill
const CARD_BG    = "F8FAFC";
const FONT       = "Calibri";

// Slide safe-area constants (inches)
const MW = 13.33;          // slide width
const MH = 7.5;            // slide height
const ML = 0.5;            // left margin
const CW = MW - ML * 2;    // 12.33 content width
const COL1W = 5.95;        // left column width
const COL2W = 6.15;        // right column width
const COL2X = ML + COL1W + 0.23; // right column x (6.68)

// ─── Shared UI Helpers ────────────────────────────────────────────────────────

function hline(slide, y) {
  slide.addShape(pres.ShapeType.rect, {
    x: ML, y, w: CW, h: 0.02,
    fill: { color: NAVY }, line: { color: NAVY, width: 0 },
  });
}

function slideTitle(slide, text, sub) {
  slide.addText(text, {
    x: ML, y: 0.2, w: CW, h: 0.5,
    fontFace: FONT, fontSize: 25, bold: true, color: NAVY,
    align: "left", isTextBox: true, margin: 0,
  });
  hline(slide, 0.72);
  if (sub) {
    slide.addText(sub, {
      x: ML, y: 0.77, w: CW, h: 0.25,
      fontFace: FONT, fontSize: 10.5, italic: true, color: GRAY,
      align: "left", isTextBox: true, margin: 0,
    });
  }
}

function sectionHdr(slide, text, x, y, w, bg = LBLUE, border = NAVY, textColor = NAVY) {
  slide.addShape(pres.ShapeType.roundRect, {
    x, y, w, h: 0.3,
    fill: { color: bg }, line: { color: border, width: 1 }, rectRadius: 0.04,
  });
  slide.addText(text, {
    x: x + 0.1, y: y + 0.02, w: w - 0.2, h: 0.26,
    fontFace: FONT, fontSize: 11, bold: true, color: textColor,
    align: "left", isTextBox: true, margin: 0,
  });
}

function blist(slide, items, x, y, w, h, size = 10.5, color = BLACK) {
  const paras = items.map((t, i) => ({
    text: t,
    options: {
      bullet: { code: "25B8" },   // ▸ bullet symbol
      breakLine: i < items.length - 1,
      paraSpaceAfter: 4.5,
      indentLevel: 0,
    },
  }));
  slide.addText(paras, {
    x, y, w, h,
    fontFace: FONT, fontSize: size, color: color,
    align: "left", isTextBox: true, margin: 0, valign: "top",
  });
}

function footer(slide) {
  slide.addText("Team [Your Team Name]  |  Smart India Hackathon 2026", {
    x: 0, y: 7.18, w: MW, h: 0.24,
    fontFace: FONT, fontSize: 9, color: GRAY, align: "center",
    isTextBox: true, margin: 0,
  });
}

// ─── SLIDE 1 ─ TITLE PAGE ────────────────────────────────────────────────────
let s1 = pres.addSlide();
s1.background = { color: WHITE };

// Top accent bar
s1.addShape(pres.ShapeType.rect, {
  x: 0, y: 0, w: MW, h: 0.12, fill: { color: NAVY }, line: { color: NAVY, width: 0 },
});

// Hackathon label
s1.addText("SMART INDIA HACKATHON 2026", {
  x: 0, y: 0.55, w: MW, h: 0.36,
  fontFace: FONT, fontSize: 13, color: GRAY, align: "center",
  isTextBox: true, margin: 0, letterSpacingPt: 1.5,
});

// Big ECDAT logotype
s1.addText("ECDAT", {
  x: 0, y: 1.05, w: MW, h: 1.15,
  fontFace: FONT, fontSize: 62, bold: true, color: NAVY, align: "center",
  isTextBox: true, margin: 0,
});

// Full name
s1.addText("ENTERPRISE CRYPTOGRAPHIC DISCOVERY & ANALYSIS TOOL", {
  x: 0, y: 2.28, w: MW, h: 0.44,
  fontFace: FONT, fontSize: 18, bold: true, color: BLACK, align: "center",
  isTextBox: true, margin: 0,
});

// Tagline
s1.addText("Automated Post-Quantum Readiness, Temporal Risk Modeling & Tamper-Evident CBOM", {
  x: 0, y: 2.8, w: MW, h: 0.36,
  fontFace: FONT, fontSize: 12.5, italic: true, color: TEAL, align: "center",
  isTextBox: true, margin: 0,
});

// Divider
s1.addShape(pres.ShapeType.rect, {
  x: 3.0, y: 3.32, w: 7.33, h: 0.02,
  fill: { color: LGRAY }, line: { color: LGRAY, width: 0 },
});

// Details table container
s1.addShape(pres.ShapeType.roundRect, {
  x: 2.6, y: 3.55, w: 8.13, h: 2.9,
  fill: { color: CARD_BG }, line: { color: LGRAY, width: 1 }, rectRadius: 0.08,
});

const details = [
  ["Problem Statement ID",       "SIH26164"],
  ["Problem Statement Title",    "Enterprise Cryptographic Discovery & Analysis Tool"],
  ["Theme",                      "Blockchain & Cybersecurity"],
  ["PS Category",                "Software"],
  ["Team ID",                    "[Your Team ID]"],
  ["Team Name",                  "[Your Team Name]"],
];
let dY = 3.75;
details.forEach(([k, v]) => {
  s1.addText(k + " :", {
    x: 2.8, y: dY, w: 3.3, h: 0.32,
    fontFace: FONT, fontSize: 12.5, bold: true, color: NAVY, align: "right",
    isTextBox: true, margin: 0,
  });
  s1.addText(v, {
    x: 6.25, y: dY, w: 4.3, h: 0.32,
    fontFace: FONT, fontSize: 12.5, color: BLACK, align: "left",
    isTextBox: true, margin: 0,
  });
  dY += 0.42;
});

// Bottom bar
s1.addShape(pres.ShapeType.rect, {
  x: 0, y: 7.3, w: MW, h: 0.2, fill: { color: NAVY }, line: { color: NAVY, width: 0 },
});

s1.addNotes(
  "Opening: State team name, problem statement ID (SIH26164), title, and theme. " +
  "Keep under 15 seconds. End with: 'Here is the problem and our proposed solution.'"
);

// ─── SLIDE 2 ─ IDEA TITLE ────────────────────────────────────────────────────
let s2 = pres.addSlide();
s2.background = { color: WHITE };
slideTitle(s2, "IDEA TITLE: ECDAT", "SIH26164 — Proposed Solution, Problem Analysis, and Core Innovations");
footer(s2);

// ── 4 Top Infographic Stat Badges ──
const stats = [
  { val: "50.7%", label: "Internet Domains Classically Vulnerable", sub: "2026 Measurement Study" },
  { val: "2030 / 2035", label: "NIST IR 8547 & OMB M-26-15", sub: "Deprecation & Disallowance Dates" },
  { val: "4-Tier", label: "Automated X-Inference Classification", sub: "EPHEMERAL · OPERATIONAL · ARCHIVAL · REVIEW" },
  { val: "32 Bytes", label: "Merkle Commitment Root", sub: "Privacy-Preserving Audit Verification" },
];
const statW = 2.92;
const statGap = 0.21;
stats.forEach((st, i) => {
  const sx = ML + i * (statW + statGap);
  s2.addShape(pres.ShapeType.roundRect, {
    x: sx, y: 1.08, w: statW, h: 0.82,
    fill: { color: CARD_BG }, line: { color: TEAL, width: 1 }, rectRadius: 0.05,
  });
  s2.addText(st.val, {
    x: sx, y: 1.12, w: statW, h: 0.36,
    fontFace: FONT, fontSize: 16, bold: true, color: NAVY, align: "center",
    isTextBox: true, margin: 0,
  });
  s2.addText(st.label, {
    x: sx + 0.05, y: 1.48, w: statW - 0.1, h: 0.22,
    fontFace: FONT, fontSize: 9.5, bold: true, color: BLACK, align: "center",
    isTextBox: true, margin: 0,
  });
  s2.addText(st.sub, {
    x: sx + 0.05, y: 1.68, w: statW - 0.1, h: 0.18,
    fontFace: FONT, fontSize: 8, italic: true, color: GRAY, align: "center",
    isTextBox: true, margin: 0,
  });
});

// ── 4 Quadrant Content Cards ──
const qY1 = 2.05;
const qH1 = 2.35;
const qY2 = 4.55;
const qH2 = 2.45;

// Q1: Problem Statement
sectionHdr(s2, "PROBLEM STATEMENT", ML, qY1, COL1W, LBLUE, NAVY);
blist(s2, [
  "NIST IR 8547 mandate: RSA, ECDSA, ECDH deprecated by 2030, disallowed by 2035; OMB M-26-15 mandates automated PQC discovery plans by Oct 2026",
  "Enterprises possess thousands of uncataloged crypto assets across source code, legacy certs, microservices, and containers with zero visibility",
  "Harvest-Now-Decrypt-Later (HNDL) threat: adversaries archive today's encrypted data to crack with future Cryptanalytically Relevant Quantum Computers (CRQC)",
  "Conventional discovery tools export complete plaintext inventories, inadvertently exposing sensitive internal architecture and cryptographic call sites in audit reports",
], ML, qY1 + 0.35, COL1W, qH1 - 0.35, 10);

// Q2: Proposed Solution
sectionHdr(s2, "PROPOSED SOLUTION (ECDAT)", COL2X, qY1, COL2W, LCYAN, TEAL, TEAL);
blist(s2, [
  "End-to-end 5-Layer Cryptographic Discovery, Temporal Risk Scoring, and PQC Migration Platform",
  "Multi-surface discovery: parses source code ASTs, X.509 keystores, container images, and cloud TLS configurations",
  "Planning-centric Mosca Engine: computes Y_max = Z − X (available migration window) instead of a naive binary compliance flag",
  "Standards-compliant CBOM generation (CycloneDX 1.6 / ECMA-424) with hybrid-first FIPS 203/204/205 recommendations",
  "Interactive CISO risk dashboard with dependency contagion modeling and drill-down to exact code sites",
], COL2X, qY1 + 0.35, COL2W, qH1 - 0.35, 10);

// Q3: How It Addresses The Problem
sectionHdr(s2, "HOW IT ADDRESSES THE PROBLEM", ML, qY2, COL1W, LBLUE, NAVY);
blist(s2, [
  "Eliminates manual tagging: automated taint & dataflow analysis classifies each crypto asset's data lifespan X into four tiers — EPHEMERAL, OPERATIONAL, ARCHIVAL, or HUMAN_REVIEW — based on persistence sink analysis",
  "Anchors risk to regulatory truth: maps directly to OMB M-26-15 5-phase timeline and Global Risk Institute quantum arrival distributions",
  "Secures the inventory itself: Merkle tree commitment scheme publishes only a 32-byte root; auditors verify compliance via selective proofs without accessing internal code paths",
  "Crypto-shredding guidance: flags cases where destroying the encryption key reduces X classification from ARCHIVAL to effectively EPHEMERAL, dramatically improving migration priority",
], ML, qY2 + 0.35, COL1W, qH2 - 0.35, 10);

// Q4: Innovation & Uniqueness
sectionHdr(s2, "INNOVATION & UNIQUENESS", COL2X, qY2, COL2W, LCYAN, TEAL, TEAL);
blist(s2, [
  "Privacy-Preserving CBOM via Merkle Commitments: enables external compliance auditing via selective inclusion proofs without exposing internal code paths",
  "Actionable Mosca Metric (Y_max = Z − X): treats migration time as an engineering budget per asset; identifies crypto-shredding levers to shrink X",
  "Multi-tier X-inference: four data-lifespan tiers (EPHEMERAL / OPERATIONAL / ARCHIVAL / HUMAN_REVIEW) with call-graph-aware taint tracing across module boundaries",
  "Regulatory-physical dual-Z model: evaluates both the OMB M-26-15 compliance deadline and the GRI 2025 probabilistic CRQC arrival distribution separately",
], COL2X, qY2 + 0.35, COL2W, qH2 - 0.35, 10);

s2.addNotes(
  "Highlight the 4 stats at the top first: 50.7% vulnerable, 2030/2035 mandate, 4-tier X-inference classification, 32-byte Merkle root. " +
  "Under Innovation: highlight privacy-preserving CBOM verification — auditing without exposing internal codebase structure. " +
  "Explain Y_max = Z - X as an engineering deadline per asset. Mention the 4-tier X model: EPHEMERAL, OPERATIONAL, ARCHIVAL, HUMAN_REVIEW. " +
  "Bridge: 'Now let us look at our Technical Approach and complete Implementation Flowchart.'"
);

// ─── SLIDE 3 ─ TECHNICAL APPROACH (WITH COMPLETE FLOWCHART) ──────────────────
let s3 = pres.addSlide();
s3.background = { color: WHITE };
slideTitle(s3, "TECHNICAL APPROACH", "SIH26164 — Methodology & Implementation Process (Flow Chart), Tech Stack & Working Prototype");
footer(s3);

// ── Section 1: Methodology & Implementation Process Flowchart ──
sectionHdr(s3, "METHODOLOGY & IMPLEMENTATION PROCESS (FLOW CHART)", ML, 1.05, CW, LBLUE, NAVY);

// Flowchart geometry
const fcY = 1.42;
const fcH = 3.08;
const numStages = 5;
const fcolW = 2.18;
const farrW = 0.28;
const fgap  = (CW - (numStages * fcolW) - ((numStages - 1) * farrW)) / (numStages - 1); // dynamic spacing

const stages = [
  {
    step: "INPUTS",
    title: "SCAN SURFACES",
    color: NAVY,
    items: [
      { h: "Source Repositories", d: "Java, Go, Python, C/C++ ASTs" },
      { h: "X.509 Certificates", d: "ASN.1 parsers, TLS Keystores" },
      { h: "Container Images", d: "OCI / Docker filesystem layers" },
      { h: "Cloud & TLS Configs", d: "K8s Secrets, Ingress configs" },
    ],
  },
  {
    step: "PHASE 1",
    title: "DISCOVERY ENGINE",
    color: TEAL,
    items: [
      { h: "PQCA CBOMkit Hyperion", d: "Static AST crypto API extraction" },
      { h: "CBOMkit Theia", d: "Binary library & container scan" },
      { h: "Symbol Linkage Parser", d: "ELF/PE dynamic import analysis" },
      { h: "Raw Asset Graph", d: "Normalized crypto invocation map" },
    ],
  },
  {
    step: "PHASE 2",
    title: "DUAL RISK ENGINE",
    color: ACCENT_BLUE,
    items: [
      { h: "Taint Dataflow (X)", d: "Infers RAM (ephemeral) vs DB/Disk" },
      { h: "Dual-Z Temporal Engine", d: "Y_max = Z - X (OMB & GRI 2025)" },
      { h: "Crypto-Shredding Check", d: "Flags key destruction levers" },
      { h: "R0 Contagion Graph", d: "Finds superspreader libraries" },
    ],
  },
  {
    step: "PHASE 3 & 4",
    title: "PQC & ATTESTATION",
    color: TEAL,
    items: [
      { h: "FIPS 203/204/205", d: "ML-KEM, ML-DSA, SLH-DSA mapping" },
      { h: "Hybrid-First Guidance", d: "X25519+ML-KEM / ECDSA+ML-DSA pairing" },
      { h: "SHA-256 Merkle Tree", d: "Hashes asset records into leaves" },
      { h: "32B Root Commitment", d: "Cryptographic root publication" },
    ],
  },
  {
    step: "OUTPUTS",
    title: "DELIVERABLES",
    color: NAVY,
    items: [
      { h: "ECMA-424 CBOM JSON", d: "CycloneDX 1.6 standard export" },
      { h: "Selective Proofs", d: "Privacy-preserving verification" },
      { h: "CISO Risk Dashboard", d: "Interactive Y_max timeline & Gantt" },
      { h: "CBOM Diff Report", d: "Before/after migration delta tracking" },
    ],
  },
];

stages.forEach((stg, i) => {
  const colX = ML + i * (fcolW + farrW);

  // Column background card
  s3.addShape(pres.ShapeType.roundRect, {
    x: colX, y: fcY, w: fcolW, h: fcH,
    fill: { color: CARD_BG }, line: { color: stg.color, width: 1.2 }, rectRadius: 0.05,
  });

  // Stage header pill
  s3.addShape(pres.ShapeType.rect, {
    x: colX, y: fcY, w: fcolW, h: 0.44,
    fill: { color: stg.color }, line: { color: stg.color, width: 0 },
  });
  s3.addText(stg.step + ": " + stg.title, {
    x: colX + 0.05, y: fcY + 0.02, w: fcolW - 0.1, h: 0.4,
    fontFace: FONT, fontSize: 9.5, bold: true, color: WHITE, align: "center",
    isTextBox: true, margin: 0,
  });

  // Flow items inside stage
  stg.items.forEach((it, j) => {
    const itemY = fcY + 0.52 + j * 0.62;
    // Sub-item box
    s3.addShape(pres.ShapeType.roundRect, {
      x: colX + 0.08, y: itemY, w: fcolW - 0.16, h: 0.54,
      fill: { color: WHITE }, line: { color: LGRAY, width: 0.75 }, rectRadius: 0.03,
    });
    s3.addText(it.h, {
      x: colX + 0.12, y: itemY + 0.03, w: fcolW - 0.24, h: 0.24,
      fontFace: FONT, fontSize: 9.5, bold: true, color: NAVY, align: "left",
      isTextBox: true, margin: 0,
    });
    s3.addText(it.d, {
      x: colX + 0.12, y: itemY + 0.27, w: fcolW - 0.24, h: 0.24,
      fontFace: FONT, fontSize: 8, color: GRAY, align: "left",
      isTextBox: true, margin: 0,
    });
  });

  // Connecting arrow to next column
  if (i < stages.length - 1) {
    const arrX = colX + fcolW + 0.04;
    s3.addShape(pres.ShapeType.rightArrow, {
      x: arrX, y: fcY + 1.35, w: farrW - 0.08, h: 0.24,
      fill: { color: TEAL }, line: { color: TEAL, width: 0 },
    });
  }
});

// ── Section 2: Bottom Dual Panels ──
const botY = 4.62;
const botH = 2.45;

// Panel A: Technologies to be Used
sectionHdr(s3, "TECHNOLOGIES TO BE USED", ML, botY, COL1W, LBLUE, NAVY);
blist(s3, [
  "Languages & Engine: Python 3.11 (Risk Engine, Taint Tracer), Go & Java (CBOMkit AST Analyzers), React 18 / TypeScript (Dashboard)",
  "Core Scanners: PQCA CBOMkit (Hyperion for SonarQube AST, Theia for OCI containers), OpenSSL / Cryptography.io parser",
  "Specifications & Standards: NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), NIST IR 8547, ECMA-424 (CycloneDX CBOM 1.6)",
  "Security & Auditing: SHA-256 Merkle Trees, selective inclusion proof verification, IBM diffprivlib (risk-tiered aggregation)",
], ML, botY + 0.35, COL1W, botH - 0.35, 10);

// Panel B: Implementation Scope & Validation Plan
sectionHdr(s3, "IMPLEMENTATION SCOPE & VALIDATION PLAN", COL2X, botY, COL2W, LCYAN, TEAL, TEAL);
blist(s3, [
  "Phase 1 (MVP): Source-code AST scanner (Python + Go), taint-based X-classifier with 4-tier output, Mosca dual-Z engine, and CycloneDX 1.6 CBOM export",
  "Phase 2: CBOMkit Hyperion/Theia integration for container and X.509 scanning; SHA-256 Merkle commitment module; CISO risk dashboard (React 18)",
  "Phase 3: Inter-procedural call-graph taint analysis for cross-function persistence detection; known persistence API stubs for JDBC, SQLAlchemy, AWS SDK",
  "Planned Validation: open-source enterprise Java/Python codebases with known cryptographic estates (e.g. open-source microservice benchmarks) used as ground truth",
], COL2X, botY + 0.35, COL2W, botH - 0.35, 10);

s3.addNotes(
  "This is the core Technical Approach slide with the complete Implementation Flowchart. " +
  "Walk the 5 stages left to right: " +
  "(1) Inputs across 4 enterprise surfaces. " +
  "(2) Phase 1 discovery via open-source PQCA CBOMkit. " +
  "(3) Phase 2 dual risk engine: automated taint dataflow for 4-tier X, and dual-Z for Y_max. " +
  "(4) Phase 3/4 FIPS 203/204/205 recommendation, hybrid-first pairing, and SHA-256 Merkle tree commitment. " +
  "(5) Deliverables: ECMA-424 CBOM, selective inclusion proofs, CISO dashboard, and CBOM diff report. " +
  "Then highlight the bottom panels: standard tech stack and phased implementation plan with planned validation approach."
);

// ─── SLIDE 4 ─ FEASIBILITY AND VIABILITY ─────────────────────────────────────
let s4 = pres.addSlide();
s4.background = { color: WHITE };
slideTitle(s4, "FEASIBILITY AND VIABILITY", "SIH26164 — Operational Feasibility, Risk Analysis, and Mitigation Strategies");
footer(s4);

sectionHdr(s4, "FEASIBILITY ANALYSIS", ML, 1.08, CW, LBLUE, NAVY);
blist(s4, [
  "Technical Feasibility: Built on Linux Foundation's PQCA CBOMkit — builds upon industry-standard AST engines rather than reinventing crypto scanning from zero",
  "Operational Feasibility: Generates CycloneDX 1.6 / ECMA-424 JSON — natively interoperable with existing enterprise SBOM and CI/CD pipelines (e.g. SonarQube, GitHub Actions)",
  "Security & Privacy Feasibility: Completely local execution (zero cloud leakage of CBOM data); Merkle root proofs satisfy external audits without exposing codebase paths",
  "Economic Feasibility: Portfolio optimization (Markowitz efficient frontier) enables CISOs to allocate migration budget for maximum risk reduction per dollar",
], ML, 1.42, CW, 1.42, 10.5);

sectionHdr(s4, "POTENTIAL CHALLENGES & MITIGATION STRATEGIES", ML, 2.98, CW, LCYAN, TEAL, TEAL);

const tableRows = [
  [
    { text: "Identified Challenge & Risk", options: { bold: true, color: WHITE, fill: { color: NAVY }, fontSize: 11 } },
    { text: "Engineered Strategy & Mitigation", options: { bold: true, color: WHITE, fill: { color: NAVY }, fontSize: 11 } },
  ],
  [
    { text: "Detailed Inventory Exposure: Standard plaintext CBOM reports expose sensitive internal file paths, module names, and key configurations during external audits.", options: { fontSize: 9.8 } },
    { text: "Cryptographic Merkle Commitment: Publishes a 32-byte root. Auditors verify specific compliance claims via selective inclusion proofs without accessing full internal inventories.", options: { fontSize: 9.8 } },
  ],
  [
    { text: "Ambiguous Data Lifespan (X): Static code analysis cannot inherently determine how long encrypted records will be retained.", options: { fontSize: 9.8 } },
    { text: "Taint & Dataflow Persistence Tracing: Automatically checks whether ciphertexts reach persistent storage (DB/Disk/S3) vs ephemeral memory; flags low confidence for human review.", options: { fontSize: 9.8 } },
  ],
  [
    { text: "Inter-procedural Persistence Detection: When a ciphertext is passed into a third-party function or external library call, static taint analysis cannot determine whether that function writes to persistent storage.", options: { fontSize: 9.8 } },
    { text: "Call-Graph API Stubs + HUMAN_REVIEW Tier: ECDAT ships pre-annotated stubs for common persistence APIs (JDBC, SQLAlchemy, S3 SDK). For unresolved external sinks, assets are automatically escalated to the HUMAN_REVIEW X-tier with a confidence score.", options: { fontSize: 9.8 } },
  ],
  [
    { text: "Binary Stripped Cryptography: Compiled binaries without symbols or source code are computationally expensive to decompile.", options: { fontSize: 9.8 } },
    { text: "Tiered Ingestion Triage: Fast symbol/import table scanning for MVP; automated Ghidra headless decompilation scheduled as an explicit enterprise roadmap tier.", options: { fontSize: 9.8 } },
  ],
];

s4.addTable(tableRows, {
  x: ML, y: 3.32, w: CW, h: 3.55,
  fontFace: FONT, color: BLACK, valign: "middle",
  border: { type: "solid", color: "D9D9D9", pt: 0.75 },
  autoPage: false,
  colW: [5.4, 6.93],
  margin: [4, 7, 4, 7],
});

s4.addNotes(
  "Feasibility: read through the 4 dimensions quickly (technical, operational, security, economic). " +
  "Focus on the Challenges table: highlight Row 1 (CBOM confidentiality via Merkle commitments), " +
  "Row 2 (ambiguous data lifespan: taint-based 4-tier X classification), " +
  "Row 3 (inter-procedural taint limitation: call-graph API stubs + HUMAN_REVIEW escalation), " +
  "and Row 4 (binary stripped cryptography: Ghidra headless decompilation roadmap). " +
  "Emphasize: 'A team that acknowledges and solves real technical bottlenecks is ready for production.'"
);

// ─── SLIDE 5 ─ IMPACT AND BENEFITS ───────────────────────────────────────────
let s5 = pres.addSlide();
s5.background = { color: WHITE };
slideTitle(s5, "IMPACT AND BENEFITS", "SIH26164 — Multi-Stakeholder Value Proposition & Strategic National Impact");
footer(s5);

sectionHdr(s5, "TARGET AUDIENCE IMPACT (WHO BENEFITS & HOW)", ML, 1.08, CW, LBLUE, NAVY);
blist(s5, [
  "Chief Information Security Officers (CISOs): Replaces subjective audit checklists with a quantifiable, ranked migration backlog; portfolio optimization maximizes risk reduction per budget dollar",
  "Compliance & Internal Audit Teams: Automated CBOM generation natively satisfies NIST IR 8547, OMB M-26-15, and CNSA 2.0 requirements without manual questionnaire audits",
  "Software Engineering Teams: Taint-based X-inference filters out thousands of ephemeral low-risk keys, pinpointing the critical persistent-data call sites that truly require migration",
  "Critical Infrastructure & Regulated Sectors: Banking, healthcare, defense, and government agencies secure long-lived data against HNDL attacks well ahead of the 2030/2035 mandates",
  "DevSecOps & Open-Source Communities: CBOM export pipeline integrates natively with CI/CD workflows (GitHub Actions, SonarQube), automating PQC compliance checks on every code merge",
], ML, 1.44, CW, 2.55, 10.5);

sectionHdr(s5, "BROADER BENEFITS (SECURITY, ECONOMIC & NATIONAL IMPACT)", ML, 4.14, CW, LCYAN, TEAL, TEAL);
blist(s5, [
  "Strategic National Cybersecurity: Directly neutralizes 'Harvest Now, Decrypt Later' (HNDL) intelligence gathering against national sensitive data and citizen registries",
  "Economic Efficiency: Avoids costly, reactive blanket replacements; targeted Mosca planning (Y_max = Z − X) prioritizes high-yield remediation and crypto-shredding levers first",
  "Tamper-Evident Accountability: Merkle commitment history provides an immutable audit trail, preventing retroactive compliance claims in post-incident forensic investigations",
  "Open Ecosystem Interoperability: Adopting ECMA-424 / CycloneDX CBOM standards prevents vendor lock-in and enables seamless integration with existing SIEM/SOAR infrastructure",
  "National Infrastructure Resilience: Establishes a verifiable, proactive post-quantum migration framework across critical enterprise systems",
], ML, 4.5, CW, 2.55, 10.5);

s5.addNotes(
  "Directly address Who Benefits: CISOs, Compliance teams, Software Engineers, Critical Infrastructure sectors, and DevSecOps communities. " +
  "Under Broader Benefits: emphasize HNDL protection and tamper-evident auditability. " +
  "Frame this not just as an IT tool, but as strategic national security infrastructure for post-quantum resilience."
);

// ─── SLIDE 6 ─ RESEARCH AND REFERENCES ───────────────────────────────────────
let s6 = pres.addSlide();
s6.background = { color: WHITE };
slideTitle(s6, "RESEARCH AND REFERENCES", "SIH26164 — Standards Grounding, Peer-Reviewed Prior Art & Experimental Validation");
footer(s6);

sectionHdr(s6, "PRIMARY STANDARDS & REGULATORY MANDATES", ML, 1.08, CW, LBLUE, NAVY);
blist(s6, [
  "NIST IR 8547 (Nov 2024): 'Transition to Post-Quantum Cryptography Standards' — Sets official deprecation (2030) and disallowance (2035) dates for classical public-key cryptography",
  "NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA) (Aug 2024): Official post-quantum standards defining lattice-based and hash-based cryptographic primitives",
  "Executive Order 14412 & OMB M-26-15 (June 24, 2026): Mandates 5-phase federal PQC migration; requires automated discovery tooling inventory plans by October 2026",
  "OWASP CycloneDX / ECMA-424 v1.6: International Cryptography Bill of Materials (CBOM) specification; establishes standard schema for cryptographic asset reporting",
], ML, 1.42, CW, 1.95, 10.2);

sectionHdr(s6, "PEER-REVIEWED LITERATURE & COMPETITIVE BENCHMARKS", ML, 3.48, CW, LCYAN, TEAL, TEAL);
blist(s6, [
  "IBM Research, 'Cryptoscope: Analyzing Cryptographic Usages in Modern Software' (arXiv:2503.19531, March 2025): CamBench benchmark (92% recall, 97% precision) for static crypto AST analysis",
  "Blanco-Romero et al., 'On the Practical Feasibility of Harvest-Now, Decrypt-Later Attacks' (arXiv:2603.01091, March 2026): Empirical HNDL economics & TLS 1.3 KeyUpdate cascade analysis",
  "Global Risk Institute, 'Quantum Threat Timeline Report 2025': Annual survey tracking quantum computing hardware milestones; empirical source for physical-Z distribution (28–49% 10-year CRQC probability)",
  "Linux Foundation Post-Quantum Cryptography Alliance (PQCA): Open-source CBOMkit project (github.com/PQCA/cbomkit) providing community AST extraction modules",
  "IETF RFC 9180 / draft-ietf-tls-ecdhe-mlkem: Standards track for hybrid post-quantum key exchange (X25519MLKEM768) in TLS 1.3",
], ML, 3.82, CW, 2.3, 10.2);

// Bottom Validation Callout
sectionHdr(s6, "VALIDATION APPROACH", ML, 6.22, CW, CARD_BG, NAVY);
s6.addText(
  "Planned validation uses open-source enterprise codebases with known cryptographic profiles as ground truth " +
  "(e.g., open-source Java microservice frameworks and Python web services). ECDAT's risk classifications and " +
  "X-tier assignments will be compared against manually audited inventories to measure recall, precision, and " +
  "HUMAN_REVIEW escalation rates for the inter-procedural taint analysis module.",
  {
    x: ML + 0.1, y: 6.54, w: CW - 0.2, h: 0.55,
    fontFace: FONT, fontSize: 9.5, italic: true, color: BLACK,
    isTextBox: true, margin: 0, valign: "top",
  }
);

s6.addNotes(
  "Closing slide: Do not read every reference word-for-word. " +
  "State: 'Our entire solution is grounded in NIST's finalized FIPS standards, OMB M-26-15's federal mandate, " +
  "and two recent March 2026 peer-reviewed papers by IBM Research and Blanco-Romero et al. " +
  "Our validation approach uses open-source codebases with known crypto estates so we can measure detection accuracy honestly.' " +
  "Thank the judges and invite questions."
);

// ─── Write Presentation File ──────────────────────────────────────────────────
pres
  .writeFile({ fileName: "/home/mohmedh/personal/Research-writeup/SIH26164_ECDAT_Deck.pptx" })
  .then(() => {
    console.log("SUCCESS — SIH26164_ECDAT_Deck.pptx generated successfully.");
  })
  .catch((err) => {
    console.error("ERROR generating PPTX:", err);
    process.exit(1);
  });
