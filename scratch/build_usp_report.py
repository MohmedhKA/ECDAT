import os
import sys
from pathlib import Path
import docx
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml import parse_xml
from docx.oxml.ns import nsdecls

def create_usp_report():
    doc = Document()

    # Page setup - US Letter with 0.85-inch margins for a balanced 3 to 4 page layout
    for section in doc.sections:
        section.page_width = Inches(8.5)
        section.page_height = Inches(11.0)
        section.top_margin = Inches(0.85)
        section.bottom_margin = Inches(0.85)
        section.left_margin = Inches(0.85)
        section.right_margin = Inches(0.85)
        
        # Header & Footer
        header = section.header
        hp = header.paragraphs[0]
        hp.alignment = WD_ALIGN_PARAGRAPH.RIGHT
        hrun = hp.add_run("ECDAT: Unique Value & Architecture Brief | Confidential")
        hrun.font.name = "Arial"
        hrun.font.size = Pt(8.5)
        hrun.font.color.rgb = RGBColor(148, 163, 184)

        footer = section.footer
        fp = footer.paragraphs[0]
        fp.alignment = WD_ALIGN_PARAGRAPH.LEFT
        frun1 = fp.add_run("ECDAT Platform Overview\tConfidential Briefing for Security Teams")
        frun1.font.name = "Arial"
        frun1.font.size = Pt(8.5)
        frun1.font.color.rgb = RGBColor(148, 163, 184)

    # Palette
    NAVY = RGBColor(15, 23, 42)      # #0F172A
    BLUE = RGBColor(30, 58, 138)     # #1E3A8A
    SLATE = RGBColor(51, 65, 85)     # #334155
    MUTED = RGBColor(100, 116, 139)  # #64748B
    WHITE = RGBColor(255, 255, 255)

    def set_cell_margins(cell, top=60, bottom=60, left=90, right=90):
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

    def add_p(text="", space_before=0, space_after=3, line_spacing=1.12, bold=False, italic=False, color=SLATE, font_size=9.5):
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
        p.paragraph_format.space_before = Pt(13)
        p.paragraph_format.space_after = Pt(3)
        p.paragraph_format.keep_with_next = True
        r = p.add_run(text)
        r.bold = True
        r.font.name = 'Arial'
        r.font.size = Pt(13.0)
        r.font.color.rgb = NAVY
        return p

    def add_h2(text):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(8)
        p.paragraph_format.space_after = Pt(2)
        p.paragraph_format.keep_with_next = True
        r = p.add_run(text)
        r.bold = True
        r.font.name = 'Arial'
        r.font.size = Pt(10.5)
        r.font.color.rgb = BLUE
        return p

    def add_callout(text, title=None):
        table = doc.add_table(rows=1, cols=1)
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        table.autofit = False
        cell = table.cell(0, 0)
        cell.width = Inches(6.8)
        tcPr = cell._tc.get_or_add_tcPr()
        tcBorders = parse_xml(f'<w:tcBorders {nsdecls("w")}><w:left w:val="single" w:sz="20" w:space="0" w:color="2563EB"/><w:top w:val="none"/><w:right w:val="none"/><w:bottom w:val="none"/></w:tcBorders>')
        tcPr.append(tcBorders)
        shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="EFF6FF"/>')
        tcPr.append(shd)
        set_cell_margins(cell, top=70, bottom=70, left=110, right=90)
        p = cell.paragraphs[0]
        p.paragraph_format.space_before = Pt(1)
        p.paragraph_format.space_after = Pt(1)
        p.paragraph_format.line_spacing = 1.12
        if title:
            run_title = p.add_run(f"{title}: ")
            run_title.bold = True
            run_title.font.name = "Arial"
            run_title.font.size = Pt(9.5)
            run_title.font.color.rgb = NAVY
        run_text = p.add_run(text)
        run_text.font.name = "Arial"
        run_text.font.size = Pt(9.0)
        run_text.font.color.rgb = SLATE

    # -------------------------------------------------------------
    # DOCUMENT HEADER
    # -------------------------------------------------------------
    p_title = doc.add_paragraph()
    p_title.paragraph_format.space_before = Pt(4)
    p_title.paragraph_format.space_after = Pt(2)
    r_title = p_title.add_run("ECDAT: Unique Value & Technical Differentiators")
    r_title.bold = True
    r_title.font.name = "Arial"
    r_title.font.size = Pt(17.0)
    r_title.font.color.rgb = NAVY

    p_sub = doc.add_paragraph()
    p_sub.paragraph_format.space_before = Pt(0)
    p_sub.paragraph_format.space_after = Pt(6)
    r_sub = p_sub.add_run("What makes our cryptographic transition platform different from existing tools")
    r_sub.font.name = "Arial"
    r_sub.font.size = Pt(10.5)
    r_sub.font.color.rgb = BLUE

    add_p("Document ID: ECDAT-USP-2026 | Audience: Security Architecture & Engineering Teams | Classification: Confidential", color=MUTED, font_size=8.5, space_after=8)

    # -------------------------------------------------------------
    # SECTION 1: EXECUTIVE CONTEXT
    # -------------------------------------------------------------
    add_h1("1. Executive summary")
    
    add_p(
        "Most security tools built for cryptographic inventory operate as passive scanners. They search for known algorithm names, "
        "dump hundreds of findings into a spreadsheet, and leave security teams with the impossible task of triaging them manually. "
        "They treat cryptography as a static compliance checklist rather than an interconnected operational system."
    )
    
    add_p(
        "ECDAT is designed around how software engineering teams actually work. It connects code analysis with database lifespans, "
        "service dependency mapping, network transport checks, and developer sprint budgets. Instead of handing you a list of 500 "
        "unprioritized problems, it identifies the most effective fixes that eliminate the most risk within a given development window."
    )

    # -------------------------------------------------------------
    # SECTION 2: THE 6 CORE USPs (THE MOATS)
    # -------------------------------------------------------------
    add_h1("2. Our core unique selling propositions")
    
    add_p(
        "Six specific architectural capabilities separate ECDAT from both commodity code scanners and legacy enterprise tools:"
    )

    # --- USP 1 ---
    add_h2("USP 1: Intent-aware noise elimination (DSIS)")
    add_p(
        "The primary reason developers ignore security scanners is alert fatigue. Traditional scanners cannot tell the difference "
        "between an SHA-256 hash used to build a 60-second Redis cache key and an RSA key encrypting customer records. "
        "Both get flagged as high-priority findings."
    )
    add_p(
        "ECDAT traces data flow to its terminal destination. Cryptographic operations that terminate in local memory, cache lookups, "
        "or internal logging are classified as operational utilities. Their risk score is set to zero, automatically suppressing alerts. "
        "Only operations that protect persistent databases, credentials, or network egress trigger migration warnings. In testbeds, "
        "this cuts out 90% to 95% of false alerts, leaving developers with only actionable security issues."
    )

    # --- USP 2 ---
    add_h2("USP 2: Dependency contagion & superspreader detection")
    add_p(
        "Traditional tools look at files in isolation. If a central authentication service issues tokens using RSA-2048, and twenty "
        "microservices verify those tokens, a standard scanner flags all twenty-one services as twenty-one separate, equal vulnerabilities."
    )
    add_p(
        "ECDAT builds a directed dependency graph across your repositories and services. It identifies the provider-consumer relationship "
        "and calculates a blast radius for every cryptographic component. Components that supply tokens, certificates, or session keys "
        "to multiple downstream applications are tagged as 'superspreaders'. Migrating a single superspreader automatically protects "
        "all downstream consumer services. This allows security leads to target the root cause rather than wasting time fixing symptoms."
    )

    # --- USP 3 ---
    add_h2("USP 3: Real lifespan modeling from database schemas")
    add_p(
        "Michele Mosca's migration theorem requires knowing the data lifespan (X). Existing platforms plug in a flat, arbitrary "
        "ten-year guess for every asset in an organization. This produces misleading risk timelines."
    )
    add_p(
        "ECDAT inspects actual database schemas, table retention rules, and column constraints to estimate how long data will stay "
        "in storage. An authentication cookie is recognized as short-lived, while an encrypted tax or medical column receives a multi-year "
        "retention profile. It then runs a 5,000-iteration stochastic simulation to calculate an empirical breach probability curve, "
        "showing security leaders exactly when their data retention crosses into the quantum risk window."
    )

    # --- USP 4 ---
    add_h2("USP 4: Transport MTU & memory buffer safety checks")
    add_p(
        "This is a major blindspot across existing commercial tools. Post-quantum cryptographic keys and signatures are massive "
        "compared to classical cryptography. An ECDSA signature is 64 bytes; an ML-DSA-65 signature is 3,309 bytes. An RSA public key "
        "is 256 bytes; an ML-KEM-768 public key is 1,184 bytes."
    )
    add_p(
        "Blindly telling developers to upgrade their algorithms causes two severe outages in production:"
    )
    add_p(
        "• Network packet fragmentation: A 5 KB post-quantum handshake flight exceeds standard 1,500-byte Ethernet MTUs. Middleboxes, "
        "firewalls, and cloud load balancers frequently drop fragmented handshake packets, silently breaking API connections. "
        "ECDAT tests network socket segment limits (MSS) and warns teams to configure certificate compression before deploying."
    )
    add_p(
        "• Memory buffer truncation: Legacy applications and embedded systems often allocate fixed 64-byte or 256-byte buffers to hold "
        "signatures. Injecting an ML-DSA signature causes buffer overflows or silent truncation. ECDAT scans syntax trees for fixed-size "
        "allocations and flags memory hazards before code hits production."
    )

    # --- USP 5 ---
    add_h2("USP 5: Sprint-budgeted remediation planning (Pareto knapsack)")
    add_p(
        "No engineering organization has unlimited time to fix every cryptographic flaw at once. A scan report with 500 'Critical' items "
        "creates analysis paralysis."
    )
    add_p(
        "ECDAT translates abstract risk into concrete developer-weeks. Security managers input their team's available sprint budget "
        "(for example, four developer-weeks). ECDAT calculates the migration effort for each asset and ranks the backlog using an "
        "efficiency-ratio algorithm (risk reduction divided by development effort). It outputs an optimal remediation queue and an "
        "interactive Pareto frontier curve, showing management the exact subset of work that yields the maximum risk reduction "
        "for that specific sprint."
    )

    # --- USP 6 ---
    add_h2("USP 6: Tamper-evident attestation & audit ledger")
    add_p(
        "Most scanners export plain JSON or CSV files. Anyone with text-editor access can delete vulnerable rows or alter algorithm "
        "names to fake audit compliance."
    )
    add_p(
        "ECDAT wraps all inventory results in an in-toto compliant Dead Simple Signing Envelope (DSSE) signed with an Ed25519 key. "
        "Concurrently, it computes a 32-byte SHA-256 Merkle root across all findings. External compliance auditors can mathematically "
        "verify whether a specific component was part of an approved scan, or prove that an unapproved algorithm is absent, without "
        "requiring access to the underlying proprietary source code."
    )

    # -------------------------------------------------------------
    # SECTION 3: COMPETITIVE COMPARISON MATRIX
    # -------------------------------------------------------------
    add_h1("3. How ECDAT compares against the market")
    
    add_p(
        "The table below highlights how ECDAT's architecture addresses the gaps found in current market alternatives:"
    )

    comp_table = doc.add_table(rows=7, cols=4)
    comp_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    comp_table.autofit = False
    c_widths = [Inches(1.8), Inches(1.6), Inches(1.6), Inches(1.8)]

    c_headers = ["Capability", "Commodity SAST", "Enterprise Scanners", "ECDAT Approach"]
    for i, h in enumerate(c_headers):
        comp_table.rows[0].cells[i].width = c_widths[i]
        p = comp_table.rows[0].cells[i].paragraphs[0]
        r = p.add_run(h)
        r.bold = True
        r.font.name = "Arial"
        r.font.size = Pt(8.5)
        r.font.color.rgb = WHITE
        shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="1E3A8A"/>')
        comp_table.rows[0].cells[i]._tc.get_or_add_tcPr().append(shd)
        set_cell_margins(comp_table.rows[0].cells[i], top=50, bottom=50, left=60, right=60)

    comp_data = [
        ("Noise Filtering", "None (flags all crypto)", "Basic rule suppression", "Intent classification (DSIS) suppresses 90%+ noise"),
        ("Service Blast Radius", "Isolated files only", "Basic asset catalog", "Dependency contagion graph (R0) pinpoints superspreaders"),
        ("Lifespan Estimation", "None", "Static 10-year guess", "Derived from database schemas + 5,000-run Monte Carlo"),
        ("PQC Size & MTU Checks", "None", "None", "Checks socket MSS & code buffers against NIST PQC byte sizes"),
        ("Fix Prioritization", "Flat severity list", "Ticketing sync only", "Pareto knapsack planner fits fixes into sprint budgets"),
        ("Audit Integrity", "Plain text/JSON", "Proprietary database", "Cryptographically signed DSSE envelopes + Merkle proofs")
    ]

    for row_idx, row_vals in enumerate(comp_data, start=1):
        row = comp_table.rows[row_idx]
        cells = row.cells
        fill_color = "F8FAFC" if row_idx % 2 == 1 else "FFFFFF"
        for i, val in enumerate(row_vals):
            cells[i].width = c_widths[i]
            p = cells[i].paragraphs[0]
            p.paragraph_format.space_after = Pt(1)
            r = p.add_run(val)
            r.font.name = "Arial"
            r.font.size = Pt(8.0)
            r.font.color.rgb = SLATE
            if i == 0:
                r.bold = True
            elif i == 3:
                r.bold = True
                r.font.color.rgb = BLUE
            shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{fill_color}"/>')
            cells[i]._tc.get_or_add_tcPr().append(shd)
            set_cell_margins(cells[i], top=40, bottom=40, left=60, right=60)

    set_table_borders(comp_table, color="CBD5E1", sz="4")
    add_p(space_after=6)

    # -------------------------------------------------------------
    # SECTION 4: CODEBASE HARDENING & REAL ACCURACY
    # -------------------------------------------------------------
    add_h1("4. Measured accuracy & engineering integrity")
    
    add_p(
        "We hold our code to strict empirical standards. When tested against standard academic security benchmarks, ECDAT delivered:"
    )
    add_p(
        "• CryptoAPI-Bench (182 Java test cases covering broken ciphers, static IVs, and hardcoded keys): 100% recall with zero false negatives."
    )
    add_p(
        "• CamBench (459 cases with complex control flow and dead branches): 93.6% recall and 94.0% precision. Our dead-branch "
        "pruning reduced false alarms by 85.3% compared to baseline scanners."
    )
    add_p(
        "• Apache Production Code (2,005 Java source files from Camel, CXF, and Santuario): 94.2% verified detection accuracy."
    )

    add_h2("Engineering transparency on current implementation")
    add_p(
        "We are clear about what runs in production today versus what is in active development on our roadmap:"
    )
    add_p(
        "1. Code analysis: Python is parsed via native syntax trees (ast.parse). Java uses a 53-pattern regular expression engine "
        "with backward variable tracing and dead-code blanking. Other polyglot languages (Go, Rust, JS) are mapped via lexer token streams."
    )
    add_p(
        "2. Safe remediation: Our remediation engine operates via exact, verified string token substitutions backed by file checksums "
        "and rollback journals. It avoids compiler AST mutations that could corrupt code formatting or alter unrelated lines."
    )
    add_p(
        "3. Runtime sensing: Live checks currently run via active network socket inspection (ecdat probe). An experimental in-kernel eBPF "
        "tracing script exists in the repository, but is maintained as a standalone tool because live kernel probes require root access."
    )
    add_p(
        "4. Signing infrastructure: Audit envelopes are signed using Ed25519. Full post-quantum signing (ML-DSA-65) is scheduled for our next release."
    )

    # -------------------------------------------------------------
    # SECTION 5: RECOMMENDED PILOT WORKFLOW
    # -------------------------------------------------------------
    add_h1("5. Suggested technical pilot")
    
    add_p(
        "To evaluate how ECDAT performs in your environment, we suggest a simple two-phase pilot on non-sensitive infrastructure:"
    )

    add_callout(
        "Phase 1: Run 'ecdat scan' against a sample internal repository to review the generated inventory and verify that cache/utility "
        "hashes are automatically silenced.\n"
        "Phase 2: Run 'ecdat probe' against an internal API gateway to inspect cipher suites and check whether packet segment sizes (MSS) "
        "can support post-quantum key exchanges.",
        title="Pilot Execution"
    )

    add_p(
        "The CLI installs locally in seconds, runs completely offline, and sends zero telemetry outside your corporate perimeter.",
        space_before=4
    )

    output_path = "/home/mohmedh/personal/ECDAT/Research/ECDAT_Technical_Evaluation_Report.docx"
    doc.save(output_path)
    print(f"USP report successfully written to {output_path}")

if __name__ == "__main__":
    create_usp_report()
