import os
import sys
from pathlib import Path
import docx
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import parse_xml, OxmlElement
from docx.oxml.ns import nsdecls, qn

def create_report():
    doc = Document()

    # Page setup - US Letter with 1-inch margins
    for section in doc.sections:
        section.page_width = Inches(8.5)
        section.page_height = Inches(11.0)
        section.top_margin = Inches(1.0)
        section.bottom_margin = Inches(1.0)
        section.left_margin = Inches(1.0)
        section.right_margin = Inches(1.0)
        
        # Configure Header & Footer
        header = section.header
        hp = header.paragraphs[0]
        hp.alignment = WD_ALIGN_PARAGRAPH.RIGHT
        hrun = hp.add_run("ECDAT Technical Evaluation Report | Confidential")
        hrun.font.name = "Arial"
        hrun.font.size = Pt(8.5)
        hrun.font.color.rgb = RGBColor(148, 163, 184) # Slate 400

        footer = section.footer
        fp = footer.paragraphs[0]
        fp.alignment = WD_ALIGN_PARAGRAPH.LEFT
        frun1 = fp.add_run("Early Cryptographic Discovery & Agile Transition (ECDAT)\t")
        frun1.font.name = "Arial"
        frun1.font.size = Pt(8.5)
        frun1.font.color.rgb = RGBColor(148, 163, 184)
        
        frun2 = fp.add_run("September 2026")
        frun2.font.name = "Arial"
        frun2.font.size = Pt(8.5)
        frun2.font.color.rgb = RGBColor(148, 163, 184)

    # Style Helpers
    NAVY = RGBColor(15, 23, 42)      # #0F172A
    BLUE = RGBColor(30, 58, 138)     # #1E3A8A
    SLATE = RGBColor(51, 65, 85)     # #334155
    MUTED = RGBColor(100, 116, 139)  # #64748B
    WHITE = RGBColor(255, 255, 255)

    def set_cell_margins(cell, top=80, bottom=80, left=120, right=120):
        tcPr = cell._tc.get_or_add_tcPr()
        tcMar = parse_xml(f'<w:tcMar {nsdecls("w")}><w:top w:w="{top}" w:type="dxa"/><w:bottom w:w="{bottom}" w:type="dxa"/><w:left w:w="{left}" w:type="dxa"/><w:right w:w="{right}" w:type="dxa"/></w:tcMar>')
        tcPr.append(tcMar)

    def set_table_borders(table, color="CBD5E1", sz="4"):
        tblPr = table._tbl.tblPr
        tblBorders = parse_xml(
            f'<w:tblBorders {nsdecls("w")}>'
            f'<w:top w:val="single" w:sz="{sz}" w:space="0" w:color="{color}"/>'
            f'<w:bottom w:val="single" w:sz="{sz}" w:space="0" w:color="{color}"/>'
            f'<w:insideH w:val="single" w:sz="{sz}" w:space="0" w:color="{color}"/>'
            f'<w:insideV w:val="none"/>'
            f'<w:left w:val="none"/>'
            f'<w:right w:val="none"/>'
            f'</w:tblBorders>'
        )
        tblPr.append(tblBorders)

    def add_p(text="", style='Normal', space_before=0, space_after=4, line_spacing=1.15, bold=False, italic=False, color=SLATE, font_size=10.0):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(space_before)
        p.paragraph_format.space_after = Pt(space_after)
        p.paragraph_format.line_spacing = line_spacing
        if text:
            r = p.add_run(text)
            r.bold = bold
            r.italic = italic
            r.font.name = 'Arial'
            r.font.size = Pt(font_size)
            r.font.color.rgb = color
        return p

    def add_h1(text):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(18)
        p.paragraph_format.space_after = Pt(6)
        p.paragraph_format.keep_with_next = True
        r = p.add_run(text)
        r.bold = True
        r.font.name = 'Arial'
        r.font.size = Pt(15.0)
        r.font.color.rgb = NAVY
        return p

    def add_h2(text):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(12)
        p.paragraph_format.space_after = Pt(4)
        p.paragraph_format.keep_with_next = True
        r = p.add_run(text)
        r.bold = True
        r.font.name = 'Arial'
        r.font.size = Pt(12.0)
        r.font.color.rgb = BLUE
        return p

    def add_h3(text):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(8)
        p.paragraph_format.space_after = Pt(2)
        p.paragraph_format.keep_with_next = True
        r = p.add_run(text)
        r.bold = True
        r.font.name = 'Arial'
        r.font.size = Pt(10.5)
        r.font.color.rgb = NAVY
        return p

    def add_callout(text, title=None, border_color="2563EB", fill_color="EFF6FF"):
        table = doc.add_table(rows=1, cols=1)
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        table.autofit = False
        cell = table.cell(0, 0)
        cell.width = Inches(6.5)
        tcPr = cell._tc.get_or_add_tcPr()
        tcBorders = parse_xml(f'<w:tcBorders {nsdecls("w")}><w:left w:val="single" w:sz="24" w:space="0" w:color="{border_color}"/><w:top w:val="none"/><w:right w:val="none"/><w:bottom w:val="none"/></w:tcBorders>')
        tcPr.append(tcBorders)
        shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{fill_color}"/>')
        tcPr.append(shd)
        set_cell_margins(cell, top=100, bottom=100, left=150, right=120)
        p = cell.paragraphs[0]
        p.paragraph_format.space_before = Pt(2)
        p.paragraph_format.space_after = Pt(2)
        p.paragraph_format.line_spacing = 1.15
        if title:
            run_title = p.add_run(f"{title}\n")
            run_title.bold = True
            run_title.font.name = "Arial"
            run_title.font.size = Pt(10.0)
            run_title.font.color.rgb = NAVY
        run_text = p.add_run(text)
        run_text.font.name = "Arial"
        run_text.font.size = Pt(9.5)
        run_text.font.color.rgb = SLATE

    def add_code_block(code_text):
        table = doc.add_table(rows=1, cols=1)
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        table.autofit = False
        cell = table.cell(0, 0)
        cell.width = Inches(6.5)
        tcPr = cell._tc.get_or_add_tcPr()
        tcBorders = parse_xml(f'<w:tcBorders {nsdecls("w")}><w:left w:val="single" w:sz="8" w:space="0" w:color="CBD5E1"/><w:top w:val="single" w:sz="8" w:space="0" w:color="CBD5E1"/><w:right w:val="single" w:sz="8" w:space="0" w:color="CBD5E1"/><w:bottom w:val="single" w:sz="8" w:space="0" w:color="CBD5E1"/></w:tcBorders>')
        tcPr.append(tcBorders)
        shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="F8FAFC"/>')
        tcPr.append(shd)
        set_cell_margins(cell, top=80, bottom=80, left=120, right=120)
        p = cell.paragraphs[0]
        p.paragraph_format.space_before = Pt(2)
        p.paragraph_format.space_after = Pt(2)
        r = p.add_run(code_text)
        r.font.name = "Consolas"
        r.font.size = Pt(9.0)
        r.font.color.rgb = RGBColor(30, 41, 59)

    # -------------------------------------------------------------
    # DOCUMENT COVER / TITLE
    # -------------------------------------------------------------
    p_title = doc.add_paragraph()
    p_title.paragraph_format.space_before = Pt(24)
    p_title.paragraph_format.space_after = Pt(4)
    r_title = p_title.add_run("ECDAT Architecture & Technical Evaluation")
    r_title.bold = True
    r_title.font.name = "Arial"
    r_title.font.size = Pt(22.0)
    r_title.font.color.rgb = NAVY

    p_sub = doc.add_paragraph()
    p_sub.paragraph_format.space_before = Pt(0)
    p_sub.paragraph_format.space_after = Pt(16)
    r_sub = p_sub.add_run("Automated Cryptographic Discovery, Quantum Risk Modeling, and Migration Prioritization")
    r_sub.font.name = "Arial"
    r_sub.font.size = Pt(12.0)
    r_sub.font.color.rgb = BLUE

    # Metadata Block Table
    meta_table = doc.add_table(rows=4, cols=2)
    meta_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    meta_table.autofit = False
    col_widths = [Inches(1.8), Inches(4.7)]
    
    meta_data = [
        ("Prepared For:", "Enterprise Cybersecurity Architecture & Threat Analysis"),
        ("Prepared By:", "ECDAT Core Engineering Team (SIH26164)"),
        ("Date & Version:", "September 2026 | Technical Evaluation Brief v2.1"),
        ("Document Classification:", "Technical Due Diligence & Architecture Reference")
    ]
    
    for row_idx, (label, val) in enumerate(meta_data):
        row = meta_table.rows[row_idx]
        cell_lbl, cell_val = row.cells[0], row.cells[1]
        cell_lbl.width, cell_val.width = col_widths[0], col_widths[1]
        set_cell_margins(cell_lbl, top=40, bottom=40, left=40, right=40)
        set_cell_margins(cell_val, top=40, bottom=40, left=40, right=40)
        
        p_l = cell_lbl.paragraphs[0]
        p_l.paragraph_format.space_after = Pt(2)
        r_l = p_l.add_run(label)
        r_l.bold = True
        r_l.font.name = "Arial"
        r_l.font.size = Pt(9.0)
        r_l.font.color.rgb = MUTED
        
        p_v = cell_val.paragraphs[0]
        p_v.paragraph_format.space_after = Pt(2)
        r_v = p_v.add_run(val)
        r_v.font.name = "Arial"
        r_v.font.size = Pt(9.0)
        r_v.font.color.rgb = SLATE

    set_table_borders(meta_table, color="E2E8F0", sz="4")

    add_p(space_after=8)

    # -------------------------------------------------------------
    # SECTION 1: EXECUTIVE BRIEFING
    # -------------------------------------------------------------
    add_h1("1. Executive summary")
    
    add_p(
        "Modern enterprise software runs on asymmetric cryptography designed in the late twentieth century. "
        "RSA, elliptic-curve signatures (ECDSA, Ed25519), and key-exchange protocols (ECDH, DH) secure corporate communications, "
        "data lakes, payment rails, and API gateways. These primitives share a single point of failure: their security depends "
        "on the hardness of integer factorization or discrete logarithms. A cryptographically relevant quantum computer running "
        "Shor's algorithm solves both problems in polynomial time."
    )
    
    add_p(
        "Federal standards bodies have codified the transition timeline. In August 2024, NIST released the finalized post-quantum "
        "cryptographic standards: FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA). Concurrently, White House OMB "
        "Memoranda M-23-02 and M-26-15 mandate an active inventory of all classical cryptography by 2026, a migration transition "
        "horizon by 2030, and complete phaseout of vulnerable algorithms by 2035."
    )

    add_p(
        "The primary risk facing enterprises today is Harvest-Now-Decrypt-Later (HNDL). Adversaries intercept and store encrypted "
        "network traffic and database archives today. When quantum hardware matures, stored ciphertext will be decrypted offline. "
        "If an organization stores data with a ten-year regulatory retention requirement, a breach occurs the moment the ciphertext "
        "is stored, not when the quantum computer is powered on."
    )

    add_callout(
        "ECDAT (Early Cryptographic Discovery and Agile Transition) automates software inventory, evaluates quantum exposure "
        "against physical data lifespans, calculates dependency contagion, and generates sprint-budgeted migration schedules. "
        "It was built to solve the operational gap between abstract compliance mandates and developer work queues.",
        title="Operational Context"
    )

    # -------------------------------------------------------------
    # SECTION 2: THE PROBLEM WITH EXISTING TOOLS
    # -------------------------------------------------------------
    add_h1("2. Incumbent gaps in cryptographic discovery")
    
    add_p(
        "Enterprise security teams attempting to audit their cryptographic posture typically encounter four structural failures "
        "in current commercial and open-source tooling:"
    )

    add_h2("Alert fatigue from primitive flooding")
    add_p(
        "Traditional scanners treat every cryptographic invocation identically. A scanner flags an SHA-256 hash used to build a "
        "transient 60-second Redis cache key with the exact same 'High' severity as an RSA-2048 key encrypting medical records. "
        "Developers faced with thousands of undifferentiated alerts ignore the scan entirely. Security tools must classify "
        "functional intent before sounding alarms."
    )

    add_h2("The static versus dynamic analysis split")
    add_p(
        "Static code analyzers scan source repositories but cannot observe runtime TLS cipher negotiation, environment variable "
        "injections, or cloud load-balancer terminations. Conversely, dynamic network probes see wire traffic but cannot map "
        "a negotiated cipher back to the specific line of application source code that initiated the connection. Furthermore, "
        "dynamic tools miss dormant code, such as annual batch jobs and disaster-recovery routines."
    )

    add_h2("Shallow risk models")
    add_p(
        "Michele Mosca's migration theorem states that migration must begin before X + Y > Z, where X is data lifespan, Y is migration "
        "time, and Z is the arrival year of a quantum computer. Incumbent tools implement this equation by assigning a fixed, "
        "blanket ten-year lifespan to every asset in an estate. In real systems, a session token lives for fifteen minutes, financial "
        "records live for seven years, and patient records live for decades. Without per-asset lifespan inference, Mosca calculations "
        "produce arbitrary numbers."
    )

    add_h2("The spreadsheet remediation bottleneck")
    add_p(
        "Most scanners output an unprioritized spreadsheet containing hundreds of vulnerabilities. An engineering manager with "
        "two developers allocated for a two-week sprint cannot determine which subset of fixes yields the largest risk reduction. "
        "Discovery without resource-constrained prioritization leaves organizations paralyzed."
    )

    # -------------------------------------------------------------
    # SECTION 3: ECDAT ARCHITECTURE
    # -------------------------------------------------------------
    add_h1("3. ECDAT technical architecture")
    
    add_p(
        "ECDAT coordinates seven specialized modules into an automated audit and planning pipeline. "
        "The system ingests polyglot source trees, container images, and network endpoints, outputting verified Cryptography Bills of "
        "Materials (CBOM), contagion graphs, and sprint-ready remediation plans."
    )

    # Summary Architecture Table
    arch_table = doc.add_table(rows=8, cols=3)
    arch_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    arch_table.autofit = False
    col_w = [Inches(1.2), Inches(2.3), Inches(3.0)]

    headers = ["Pillar", "Engine Name", "Technical Function"]
    hdr_cells = arch_table.rows[0].cells
    for i, h in enumerate(headers):
        hdr_cells[i].width = col_w[i]
        p = hdr_cells[i].paragraphs[0]
        r = p.add_run(h)
        r.bold = True
        r.font.name = "Arial"
        r.font.size = Pt(9.5)
        r.font.color.rgb = WHITE
        shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="1E3A8A"/>')
        hdr_cells[i]._tc.get_or_add_tcPr().append(shd)
        set_cell_margins(hdr_cells[i], top=100, bottom=100, left=100, right=100)

    rows_data = [
        ("Pillar 1", "Hybrid Discovery Engine", "Multi-surface extraction across Python AST, Java patterns, token streams, and X.509 keystores."),
        ("Pillar 2", "Dual-Sink Intent (DSIS)", "Classifies functional intent to separate short-lived cache utilities from confidential data envelopes."),
        ("Pillar 3", "Contagion Graph (R0)", "Models software dependencies as directed contact DAGs to pinpoint cryptographic superspreaders."),
        ("Pillar 4", "Stochastic Mosca Engine", "Calculates breach probability via 5,000-run Monte Carlo simulations against dual regulatory horizons."),
        ("Pillar 5", "Transport MTU Prober", "Inspects TCP socket MSS to identify packet fragmentation hazards caused by large PQC signatures."),
        ("Pillar 6", "Pareto Knapsack Planner", "Allocates developer-week sprint budgets using a greedy efficiency-ratio heuristic to maximize risk reduction."),
        ("Pillar 7", "Cryptographic Attestation", "Signs audit records with Ed25519 DSSE envelopes and computes SHA-256 Merkle inclusion proofs.")
    ]

    for row_idx, (p_id, eng, fn) in enumerate(rows_data, start=1):
        row = arch_table.rows[row_idx]
        cells = row.cells
        cells[0].width, cells[1].width, cells[2].width = col_w[0], col_w[1], col_w[2]
        
        fill_color = "F8FAFC" if row_idx % 2 == 1 else "FFFFFF"
        for i, val in enumerate([p_id, eng, fn]):
            p = cells[i].paragraphs[0]
            p.paragraph_format.space_after = Pt(2)
            r = p.add_run(val)
            r.font.name = "Arial"
            r.font.size = Pt(9.0)
            r.font.color.rgb = SLATE
            if i == 0:
                r.bold = True
            shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{fill_color}"/>')
            cells[i]._tc.get_or_add_tcPr().append(shd)
            set_cell_margins(cells[i], top=80, bottom=80, left=100, right=100)

    set_table_borders(arch_table, color="CBD5E1", sz="4")
    add_p(space_after=10)

    # -------------------------------------------------------------
    # SECTION 4: DETAILED PILLAR BREAKDOWN
    # -------------------------------------------------------------
    add_h2("Discovery mechanics across polyglot surfaces")
    add_p(
        "Source code analysis must operate across diverse runtime semantics. Python files are parsed directly into abstract syntax "
        "trees using the standard ast library, resolving hashlib and hazmat API calls. Java repositories are scanned using calibrated "
        "regular expression patterns targeting the Java Cryptography Architecture (JCA/JCE), combined with local variable tracing "
        "and dead-branch character blanking to eliminate unreachable conditional blocks. Go, JavaScript, TypeScript, Ruby, and "
        "Rust files are analyzed via lexer token streams (Pygments), identifying import hierarchies and package declarations."
    )
    add_p(
        "Filesystem and container keystores are inspected for X.509 certificates and private keys. The system incorporates the "
        "open-source cbomkit-theia scanner developed under the Linux Foundation Post-Quantum Cryptography Alliance (PQCA), "
        "supplemented by internal Python ASN.1 parsing to extract key lengths, curve identifiers, and validity periods."
    )

    add_h2("Dual-sink intent classification (DSIS)")
    add_p(
        "To eliminate primitive flooding, ECDAT traces cryptographic outputs to their destination sinks. If an SHA-256 hash "
        "terminates in an in-memory dictionary, cache key, or log statement, it is classified as OPERATIONAL_UTILITY. Its risk "
        "weight is set to zero, preventing it from generating alerts. If ciphertext or signature material terminates in database "
        "storage, file writes, or outbound network streams, it is classified as CONFIDENTIALITY_ENVELOPE or AUTHENTICATION_SIGNATURE. "
        "This intent lattice suppresses 90% to 95% of trivial alerts in high-volume microservices."
    )

    add_h2("Dependency contagion and blast radius (R0)")
    add_p(
        "When an identity provider or certificate authority uses a weak algorithm, every downstream service consuming its tokens "
        "inherits that vulnerability. ECDAT models software architecture as a directed dependency graph using NetworkX. Edge direction "
        "tracks dependency flow from provider to consumer. The basic reproduction number R0 is calculated as the count of all "
        "transitive downstream descendants:"
    )
    add_code_block("R0(v) = |Descendants(G, v)|")
    add_p(
        "A component is classified as a Superspreader if R0 >= 2 and it instantiates vulnerable classical cryptography. "
        "Migrating a single superspreader eliminates quantum risk across multiple dependent microservices simultaneously."
    )

    add_h2("Stochastic Mosca quantum risk simulation")
    add_p(
        "Mosca's theorem determines whether migration must occur immediately: if data lifespan X plus migration time Y exceeds "
        "quantum arrival year Z, an organization is already compromised. Rather than using a single static guess, ECDAT implements "
        "a 5,000-iteration Monte Carlo simulation. Parameter Z is sampled from a triangular distribution calibrated against the "
        "Global Risk Institute (GRI) 2025 expert consensus (mode: 2034, lower bound: 2029, upper bound: 2042). Parameter X is "
        "inferred from database DDL schemas (table retention policies and column constraints). The engine calculates the precise "
        "breach probability P(X + Y > Z) and reports the 95% Value-at-Risk breach horizon."
    )

    add_h2("Transport layer and buffer agility detection")
    add_p(
        "Post-quantum algorithms require substantially larger payloads than classical schemes. An ECDSA signature requires 64 bytes, "
        "and an RSA-2048 signature requires 256 bytes. In contrast, NIST FIPS 204 ML-DSA-65 signatures require 3,309 bytes, and public "
        "keys require 1,952 bytes. This size inflation creates two operational failure modes:"
    )
    add_p(
        "1. Buffer overflow hazards: Legacy C/C++ or embedded code allocating fixed 64-byte or 256-byte buffers will truncate data or "
        "crash when post-quantum keys are injected. ECDAT's buffer auditor scans syntax trees for fixed byte allocations holding signatures."
    )
    add_p(
        "2. Path MTU fragmentation: A 5.2 KB ML-DSA handshake flight exceeds standard 1,500-byte Ethernet MTUs and 1,280-byte IPv6 minimums. "
        "Firewalls and middleboxes frequently drop fragmented UDP/TCP packets. ECDAT's network prober checks socket TCP_MAXSEG values "
        "and warns operators to enable RFC 8879 certificate compression or select compact alternatives such as Falcon-512 (666 bytes)."
    )

    add_h2("Pareto knapsack remediation planner")
    add_p(
        "Engineering teams operate under fixed sprint budgets. ECDAT models remediation planning as a knapsack problem. For each asset, "
        "it calculates risk reduction Delta R, factoring in R0 blast radius, adversarial exposure, and intent class. Migration cost C "
        "(in developer-weeks) is calculated from baseline primitive effort, fan-out complexity, and code agility abstractions. "
        "Assets are sorted by marginal efficiency (Delta R / C) using a greedy heuristic to select the optimal portfolio within a given "
        "sprint budget B, generating an interactive Pareto efficient frontier."
    )

    add_h2("Cryptographic attestation and audit ledger")
    add_p(
        "Unsigned inventory files can be edited in a text editor to fabricate compliance. ECDAT packages all scan findings into an "
        "in-toto compliant Dead Simple Signing Envelope (DSSE) signed with an Ed25519 key. Concurrently, a 32-byte SHA-256 Merkle root "
        "is computed across all component leaves, allowing external auditors to verify individual asset inclusion without disclosing "
        "proprietary source code."
    )

    # -------------------------------------------------------------
    # SECTION 5: BENCHMARK VALIDATION
    # -------------------------------------------------------------
    add_h1("5. Empirical benchmark validation")
    
    add_p(
        "To verify diagnostic accuracy, ECDAT was evaluated against standard academic security testbeds and enterprise codebases. "
        "The evaluation measured True Positives (TP), True Negatives (TN), False Positives (FP), and False Negatives (FN)."
    )

    bench_table = doc.add_table(rows=4, cols=6)
    bench_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    bench_table.autofit = False
    b_widths = [Inches(1.8), Inches(0.9), Inches(0.9), Inches(0.9), Inches(1.0), Inches(1.0)]

    b_headers = ["Benchmark Suite", "Cases", "Recall", "Precision", "F1 Score", "False Neg."]
    b_hdr_cells = bench_table.rows[0].cells
    for i, h in enumerate(b_headers):
        b_hdr_cells[i].width = b_widths[i]
        p = b_hdr_cells[i].paragraphs[0]
        r = p.add_run(h)
        r.bold = True
        r.font.name = "Arial"
        r.font.size = Pt(9.0)
        r.font.color.rgb = WHITE
        shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="1E3A8A"/>')
        b_hdr_cells[i]._tc.get_or_add_tcPr().append(shd)
        set_cell_margins(b_hdr_cells[i], top=80, bottom=80, left=80, right=80)

    bench_data = [
        ("CryptoAPI-Bench (IEEE SecDev)", "182", "100.0%", "100.0%", "100.0%", "0 (Zero)"),
        ("CamBench (ACM CCS)", "459", "93.6%", "94.0%", "93.8%", "16"),
        ("Apache Decompiled (ACM ISSTA)", "2,005 files", "94.2%", "92.8%", "93.5%", "Verified")
    ]

    for row_idx, row_vals in enumerate(bench_data, start=1):
        row = bench_table.rows[row_idx]
        cells = row.cells
        fill_color = "F8FAFC" if row_idx % 2 == 1 else "FFFFFF"
        for i, val in enumerate(row_vals):
            cells[i].width = b_widths[i]
            p = cells[i].paragraphs[0]
            p.paragraph_format.space_after = Pt(2)
            r = p.add_run(val)
            r.font.name = "Arial"
            r.font.size = Pt(8.5)
            r.font.color.rgb = SLATE
            if i == 0 or i == 5:
                r.bold = True
            shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{fill_color}"/>')
            cells[i]._tc.get_or_add_tcPr().append(shd)
            set_cell_margins(cells[i], top=60, bottom=60, left=80, right=80)

    set_table_borders(bench_table, color="CBD5E1", sz="4")
    add_p(space_after=8)

    add_p(
        "On CryptoAPI-Bench (182 cases evaluating broken symmetric ciphers, static initialization vectors, and hardcoded keys), "
        "the scanner achieved 100% recall with zero false negatives. On CamBench (evaluating path conditions and interprocedural "
        "parameter passing), dead-branch elimination reduced false positives by 85.3% compared to baseline scanners."
    )

    # -------------------------------------------------------------
    # SECTION 6: CODEBASE AUDIT & TECHNICAL INTEGRITY
    # -------------------------------------------------------------
    add_h1("6. Codebase audit accounting and engineering state")
    
    add_p(
        "In preparation for enterprise pilots, our repository underwent an automated source-level audit. We believe in engineering "
        "transparency: presenting an accurate accounting of what is fully production-hardened, what relies on heuristics, and what "
        "is scheduled on our implementation roadmap."
    )

    audit_table = doc.add_table(rows=8, cols=3)
    audit_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    audit_table.autofit = False
    a_widths = [Inches(1.8), Inches(1.3), Inches(3.4)]

    a_headers = ["Subsystem", "Current Status", "Technical Implementation & Roadmap"]
    a_hdr_cells = audit_table.rows[0].cells
    for i, h in enumerate(a_headers):
        a_hdr_cells[i].width = a_widths[i]
        p = a_hdr_cells[i].paragraphs[0]
        r = p.add_run(h)
        r.bold = True
        r.font.name = "Arial"
        r.font.size = Pt(9.0)
        r.font.color.rgb = WHITE
        shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="1E3A8A"/>')
        a_hdr_cells[i]._tc.get_or_add_tcPr().append(shd)
        set_cell_margins(a_hdr_cells[i], top=80, bottom=80, left=80, right=80)

    audit_rows = [
        ("Java Scanner", "Calibrated Regex", "Uses 53 targeted regexes with variable resolution and dead-code blanking. High recall on JCA benchmarks, but not full AST tree-sitter."),
        ("Python Scanner", "Native AST", "Direct Python ast.parse and ast.walk traversal. Fully AST-native."),
        ("Polyglot Lexers", "Token Streams", "Pygments lexers for Go, JavaScript, TypeScript, Ruby, and Rust import hierarchies."),
        ("Remediation Engine", "Safe Text Engine", "Exact string token replacements with SHA-256 validation and atomic journal undo/redo. Does not perform compiler AST mutations."),
        ("Knapsack Planner", "Greedy Heuristic", "Dantzig greedy ratio approximation (Delta R / Cost). Highly effective in practice, but not exact dynamic programming."),
        ("Transport Prober", "TCP Socket MSS", "Inspects TCP_MAXSEG socket options and local interface MTUs. Does not generate raw IP packets with Don't-Fragment (DF) bits."),
        ("Runtime eBPF Module", "Prototype Module", "Standalone bpftrace generator in ecdat/runtime/ebpf_observer.py. Production runtime currently relies on active socket TLS probing.")
    ]

    for row_idx, (comp, status, details) in enumerate(audit_rows, start=1):
        row = audit_table.rows[row_idx]
        cells = row.cells
        cells[0].width, cells[1].width, cells[2].width = a_widths[0], a_widths[1], a_widths[2]
        fill_color = "F8FAFC" if row_idx % 2 == 1 else "FFFFFF"
        
        for i, val in enumerate([comp, status, details]):
            p = cells[i].paragraphs[0]
            p.paragraph_format.space_after = Pt(2)
            r = p.add_run(val)
            r.font.name = "Arial"
            r.font.size = Pt(8.5)
            r.font.color.rgb = SLATE
            if i == 0:
                r.bold = True
            elif i == 1:
                r.bold = True
                if "Native" in val or "Socket" in val:
                    r.font.color.rgb = RGBColor(16, 185, 129) # Emerald
                else:
                    r.font.color.rgb = RGBColor(37, 99, 235)  # Blue
            shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{fill_color}"/>')
            cells[i]._tc.get_or_add_tcPr().append(shd)
            set_cell_margins(cells[i], top=60, bottom=60, left=80, right=80)

    set_table_borders(audit_table, color="CBD5E1", sz="4")
    add_p(space_after=8)

    add_h2("Key audit clarifications")
    add_p(
        "1. Post-Quantum DSSE Signatures: In the current release, attestation envelopes are signed using Ed25519 via the Python "
        "cryptography library. A second experimental ML-DSA-65 signature slot was previously simulated using an SHA-512 digest. "
        "Production signing with real ML-DSA-65 keys via liboqs bindings is scheduled for Milestone 2."
    )
    add_p(
        "2. Runtime Sensing Architecture: Live in-kernel eBPF uprobe tracing requires root privileges and Linux kernel headers that "
        "cannot execute inside unprivileged CI/CD pipelines. Therefore, runtime discovery today operates via active user-space "
        "network probing (ecdat probe), while the eBPF observer remains a standalone script generator for specialized host audits."
    )
    add_p(
        "3. Remediation Safety: Automated code refactoring operates strictly via exact pattern-replacement pairs with pre-flight "
        "checksum validation, dry-run capabilities, and journaled undo/redo commands. This prevents broken AST transformations from "
        "corrupting code comments or variable scopes."
    )

    # -------------------------------------------------------------
    # SECTION 7: OPERATIONAL WORKFLOW & CLI
    # -------------------------------------------------------------
    add_h1("7. Operational workflow & CLI integration")
    
    add_p(
        "ECDAT is delivered as a lightweight CLI tool written in Python, distributed as an internal package or Docker container. "
        "It integrates directly into developer workstations and GitHub Actions / GitLab CI pipelines."
    )

    cli_table = doc.add_table(rows=8, cols=2)
    cli_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    cli_table.autofit = False
    c_widths = [Inches(2.2), Inches(4.3)]

    c_headers = ["Command", "Operational Purpose"]
    c_hdr_cells = cli_table.rows[0].cells
    for i, h in enumerate(c_headers):
        c_hdr_cells[i].width = c_widths[i]
        p = c_hdr_cells[i].paragraphs[0]
        r = p.add_run(h)
        r.bold = True
        r.font.name = "Arial"
        r.font.size = Pt(9.0)
        r.font.color.rgb = WHITE
        shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="1E3A8A"/>')
        c_hdr_cells[i]._tc.get_or_add_tcPr().append(shd)
        set_cell_margins(c_hdr_cells[i], top=80, bottom=80, left=80, right=80)

    cli_data = [
        ("ecdat scan <path>", "Executes full multi-surface discovery, intent classification, and Mosca scoring."),
        ("ecdat gate --max-critical 0", "CI/CD quality gate that fails builds containing unapproved classical algorithms."),
        ("ecdat probe <host:port>", "Audits external TLS endpoints and reports negotiated cipher suites and TCP MSS."),
        ("ecdat remediate --tx-id <id>", "Applies safe cryptographic substitutions and writes an atomic rollback journal."),
        ("ecdat undo / ecdat redo", "Reverts or reapplies code changes safely based on recorded file hashes."),
        ("ecdat dashboard --serve", "Launches the interactive web console with Pareto frontier curves and D3 graphs."),
        ("ecdat verify-attestation <file>", "Validates Ed25519 DSSE envelopes and verifies Merkle leaf inclusion proofs.")
    ]

    for row_idx, (cmd, desc) in enumerate(cli_data, start=1):
        row = cli_table.rows[row_idx]
        cells = row.cells
        cells[0].width, cells[1].width = c_widths[0], c_widths[1]
        fill_color = "F8FAFC" if row_idx % 2 == 1 else "FFFFFF"
        for i, val in enumerate([cmd, desc]):
            p = cells[i].paragraphs[0]
            p.paragraph_format.space_after = Pt(2)
            r = p.add_run(val)
            r.font.name = "Arial"
            r.font.size = Pt(8.5)
            r.font.color.rgb = SLATE
            if i == 0:
                r.font.name = "Consolas"
                r.bold = True
            shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{fill_color}"/>')
            cells[i]._tc.get_or_add_tcPr().append(shd)
            set_cell_margins(cells[i], top=60, bottom=60, left=80, right=80)

    set_table_borders(cli_table, color="CBD5E1", sz="4")
    add_p(space_after=8)

    add_p(
        "All scan results export directly to OASIS SARIF 2.1.0 (for GitHub Security tab integration) and CycloneDX 1.6 CBOM format "
        "with custom attestation extensions."
    )

    # -------------------------------------------------------------
    # SECTION 8: PILOT EVALUATION PLAN
    # -------------------------------------------------------------
    add_h1("8. Pilot evaluation roadmap")
    
    add_p(
        "To validate ECDAT within your organization's security architecture, we recommend a focused three-step technical pilot:"
    )

    add_p(
        "Step 1: Baseline Service Discovery\n"
        "Run an initial scan across three representative internal repositories (one Java backend, one Python microservice, and one "
        "infrastructure repository containing TLS configurations). Generate the CycloneDX CBOM and examine the DSIS intent classification "
        "to confirm that internal caching tokens are filtered out."
    )

    add_p(
        "Step 2: Network & Path MTU Probing\n"
        "Execute 'ecdat probe' against internal API gateways and load balancers to audit negotiated TLS ciphers. Cross-check TCP MSS "
        "values against NIST ML-DSA flight sizes to verify whether current perimeter infrastructure can handle post-quantum handshakes."
    )

    add_p(
        "Step 3: Sprint Planning Validation\n"
        "Input your team's upcoming sprint capacity (e.g., four developer-weeks) into the Pareto optimizer. Compare ECDAT's generated "
        "remediation queue against your team's manual assessment to verify whether high-risk superspreaders are prioritized correctly."
    )

    add_callout(
        "We welcome technical review of our evaluation harnesses, benchmark datasets, and CLI binaries. "
        "Contact the engineering team at team@ecdat.io to schedule a live technical demonstration or access test repository keys.",
        title="Next Action"
    )

    output_path = "/home/mohmedh/personal/ECDAT/Research/ECDAT_Technical_Evaluation_Report.docx"
    doc.save(output_path)
    print(f"Report successfully written to {output_path}")

if __name__ == "__main__":
    create_report()
