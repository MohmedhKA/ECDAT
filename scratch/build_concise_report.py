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

def create_concise_report():
    doc = Document()

    # Page setup - US Letter with compact 0.8-inch margins to keep it tight (2-3 pages)
    for section in doc.sections:
        section.page_width = Inches(8.5)
        section.page_height = Inches(11.0)
        section.top_margin = Inches(0.8)
        section.bottom_margin = Inches(0.8)
        section.left_margin = Inches(0.8)
        section.right_margin = Inches(0.8)
        
        # Header & Footer
        header = section.header
        hp = header.paragraphs[0]
        hp.alignment = WD_ALIGN_PARAGRAPH.RIGHT
        hrun = hp.add_run("ECDAT Technical Brief | Confidential")
        hrun.font.name = "Arial"
        hrun.font.size = Pt(8.5)
        hrun.font.color.rgb = RGBColor(148, 163, 184)

        footer = section.footer
        fp = footer.paragraphs[0]
        fp.alignment = WD_ALIGN_PARAGRAPH.LEFT
        frun1 = fp.add_run("ECDAT: Early Cryptographic Discovery & Agile Transition\tSeptember 2026")
        frun1.font.name = "Arial"
        frun1.font.size = Pt(8.5)
        frun1.font.color.rgb = RGBColor(148, 163, 184)

    # Color Palette
    NAVY = RGBColor(15, 23, 42)      # #0F172A
    BLUE = RGBColor(30, 58, 138)     # #1E3A8A
    SLATE = RGBColor(51, 65, 85)     # #334155
    MUTED = RGBColor(100, 116, 139)  # #64748B
    WHITE = RGBColor(255, 255, 255)

    def set_cell_margins(cell, top=60, bottom=60, left=100, right=100):
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
        p.paragraph_format.space_before = Pt(12)
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
        cell.width = Inches(6.9)
        tcPr = cell._tc.get_or_add_tcPr()
        tcBorders = parse_xml(f'<w:tcBorders {nsdecls("w")}><w:left w:val="single" w:sz="20" w:space="0" w:color="2563EB"/><w:top w:val="none"/><w:right w:val="none"/><w:bottom w:val="none"/></w:tcBorders>')
        tcPr.append(tcBorders)
        shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="EFF6FF"/>')
        tcPr.append(shd)
        set_cell_margins(cell, top=70, bottom=70, left=120, right=100)
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
    # HEADER BLOCK (Clean & Professional)
    # -------------------------------------------------------------
    p_title = doc.add_paragraph()
    p_title.paragraph_format.space_before = Pt(6)
    p_title.paragraph_format.space_after = Pt(2)
    r_title = p_title.add_run("ECDAT: Technical Brief for Security Teams")
    r_title.bold = True
    r_title.font.name = "Arial"
    r_title.font.size = Pt(18.0)
    r_title.font.color.rgb = NAVY

    p_sub = doc.add_paragraph()
    p_sub.paragraph_format.space_before = Pt(0)
    p_sub.paragraph_format.space_after = Pt(8)
    r_sub = p_sub.add_run("Post-quantum cryptography discovery, risk modeling, and sprint planning")
    r_sub.font.name = "Arial"
    r_sub.font.size = Pt(10.5)
    r_sub.font.color.rgb = BLUE

    # Top metadata line
    add_p("Document ID: ECDAT-TB-2026 | Date: September 2026 | Focus: Architecture & Technical Summary", color=MUTED, font_size=8.5, space_after=10)

    # -------------------------------------------------------------
    # 1. THE PROBLEM: WHY CURRENT APPROACHES FAIL
    # -------------------------------------------------------------
    add_h1("1. The problem: why post-quantum prep is stalled")
    
    add_p(
        "Quantum computers running Shor's algorithm will break common public-key systems: RSA, ECDSA, ECDH, and Diffie-Hellman. "
        "The risk is not waiting for a future machine to turn on. Attackers are already saving encrypted network traffic and backups. "
        "Once a capable quantum machine exists, they will decrypt that data. If your company stores customer records or intellectual "
        "property that needs to stay secret for five to ten years, those files are already exposed to this threat."
    )
    
    add_p(
        "NIST finalized the replacement standards in August 2024: ML-KEM for key exchange and ML-DSA for digital signatures. "
        "Federal guidelines (OMB M-23-02 and M-26-15) set 2030 as the key deadline to have transitions underway. "
        "Most engineering teams want to comply, but current security tools make the job frustrating:"
    )

    add_p(
        "• Alert fatigue from noise: Scanners flag every SHA-256 or AES call. A hash used for a 60-second Redis cache key gets the "
        "same 'High' severity label as an RSA key protecting a customer database. Developers get buried under thousands of tickets "
        "and end up ignoring the scanner."
    )
    add_p(
        "• The static vs dynamic gap: Code scanners miss what happens at runtime, such as TLS ciphers chosen by load balancers. "
        "Network sniffers see traffic on the wire, but cannot tell developers which line of code generated it."
    )
    add_p(
        "• Massive, unprioritized lists: Typical reports dump a 500-row spreadsheet marked 'Critical'. If an engineering manager has "
        "two developers free for a two-week sprint, the report gives no practical way to pick which five fixes matter most."
    )
    add_p(
        "• Unexpected network and memory breaks: Post-quantum keys and signatures are 10x to 50x larger than RSA or ECC. Recommending "
        "ML-DSA-65 (over 3 KB per signature) without checking whether network firewalls drop fragmented packets or whether fixed memory "
        "buffers will overflow causes outages in production."
    )

    # -------------------------------------------------------------
    # 2. HOW ECDAT WORKS: A HIGH-LEVEL OVERVIEW
    # -------------------------------------------------------------
    add_h1("2. How ECDAT works")
    
    add_p(
        "ECDAT is an automated CLI tool and analysis engine. It scans codebases, maps dependencies, filters out noise, and turns "
        "findings into a realistic sprint plan that developers can actually finish. It operates across five core steps:"
    )

    # High-level table
    pipe_table = doc.add_table(rows=6, cols=2)
    pipe_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    pipe_table.autofit = False
    col_w = [Inches(1.8), Inches(5.1)]

    headers = ["Step", "What it does"]
    for i, h in enumerate(headers):
        pipe_table.rows[0].cells[i].width = col_w[i]
        p = pipe_table.rows[0].cells[i].paragraphs[0]
        r = p.add_run(h)
        r.bold = True
        r.font.name = "Arial"
        r.font.size = Pt(9.0)
        r.font.color.rgb = WHITE
        shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="1E3A8A"/>')
        pipe_table.rows[0].cells[i]._tc.get_or_add_tcPr().append(shd)
        set_cell_margins(pipe_table.rows[0].cells[i], top=50, bottom=50, left=80, right=80)

    steps_data = [
        ("1. Multi-Language Discovery", "Scans Python, Java, Go, JavaScript/TypeScript, and Rust repositories along with X.509 certificates and keys to build a Cryptography Bill of Materials (CBOM)."),
        ("2. Intent Filtering", "Traces where cryptographic outputs flow. Temporary cache keys and logs are tagged as utility functions (zero alert noise). Only data heading to storage or network egress gets risk-scored."),
        ("3. Blast Radius Mapping", "Builds a dependency graph across services. Finds 'superspreader' modules where migrating one central authentication library or certificate fixes multiple downstream apps at once."),
        ("4. Network & Buffer Checks", "Tests network socket segment sizes (MSS) and code buffers against the large byte footprints of ML-KEM and ML-DSA to prevent dropped packets or buffer truncations."),
        ("5. Sprint-Budgeted Planning", "Takes a developer budget (e.g., 4 dev-weeks) and uses an efficiency-ranking algorithm to select the exact fixes that give the highest risk reduction within that budget.")
    ]

    for row_idx, (st, desc) in enumerate(steps_data, start=1):
        row = pipe_table.rows[row_idx]
        cells = row.cells
        cells[0].width, cells[1].width = col_w[0], col_w[1]
        fill_color = "F8FAFC" if row_idx % 2 == 1 else "FFFFFF"
        for i, val in enumerate([st, desc]):
            p = cells[i].paragraphs[0]
            p.paragraph_format.space_after = Pt(2)
            r = p.add_run(val)
            r.font.name = "Arial"
            r.font.size = Pt(8.5)
            r.font.color.rgb = SLATE
            if i == 0:
                r.bold = True
            shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{fill_color}"/>')
            cells[i]._tc.get_or_add_tcPr().append(shd)
            set_cell_margins(cells[i], top=50, bottom=50, left=80, right=80)

    set_table_borders(pipe_table, color="CBD5E1", sz="4")
    add_p(space_after=6)

    # -------------------------------------------------------------
    # 3. HOW WE FIXED SCANNER PITFALLS
    # -------------------------------------------------------------
    add_h1("3. How we solved common scanner pitfalls")
    
    add_p(
        "When we evaluated early scanner logic against real codebases, standard approaches broke down. "
        "Here is how we addressed those issues at an engineering level without adding unnecessary complexity:"
    )

    add_h2("Tracking variables instead of looking only for quoted strings")
    add_p(
        "Simple scanners search for text like Cipher.getInstance(\"DES\"). In real production applications, algorithms are almost "
        "always stored in config files, properties, or intermediate variables (e.g., Cipher.getInstance(selectedCipher)). "
        "We built backward variable resolution into our scanners: the engine traces the variable back to its source assignment "
        "so it catches algorithms even when passed through helper methods."
    )

    add_h2("Pruning dead code branches")
    add_p(
        "Legacy code often leaves old, insecure ciphers inside dead conditional blocks or disabled test branches. Standard scanners "
        "flag these, creating false alarms for code that never runs. ECDAT evaluates simple static path conditions and blanks "
        "unreachable code blocks so security teams do not waste time chasing dead code."
    )

    add_h2("Estimating data lifespan from database schemas")
    add_p(
        "Mosca's risk formula depends on knowing how long data must stay secret (lifespan X). Instead of guessing a single ten-year "
        "lifespan for everything, ECDAT inspects database table definitions, column types, and retention comments. A session token "
        "is recognized as short-lived, while an encrypted medical record or tax column receives a multi-year retention profile."
    )

    add_h2("Safe, reversible remediation")
    add_p(
        "Automated code refactoring can easily break code formatting or alter comments. ECDAT's remediation feature uses exact, "
        "pre-validated pattern replacements with SHA-256 file checksum verification. Every change is logged in a local rollback journal, "
        "allowing developers to undo or redo changes with a single command (ecdat undo / ecdat redo)."
    )

    # -------------------------------------------------------------
    # 4. CURRENT ENGINEERING STATUS & TRANSPARENCY
    # -------------------------------------------------------------
    add_h1("4. Current codebase status and test results")
    
    add_p(
        "We believe in being upfront about what is built and running today versus what is scheduled on our roadmap:"
    )

    add_p(
        "• Detection accuracy: We validated the scanner against CryptoAPI-Bench (182 test cases on Java cryptography rules) and "
        "achieved 100% recall with zero false negatives on baseline broken ciphers. On CamBench (459 cases with complex control flow), "
        "our dead-branch handling brought overall accuracy to 93.6%."
    )
    add_p(
        "• Code parsing: Python scanning runs on native AST (ast.parse). Java scanning runs on a 53-pattern regular expression engine "
        "with variable tracking. Go, JavaScript, TypeScript, Ruby, and Rust import hierarchies are mapped using Pygments token streams."
    )
    add_p(
        "• Network checks: Our network prober checks live TCP socket segment sizes (MSS) against NIST PQC key sizes. It runs without "
        "requiring root privileges or special packet drivers."
    )
    add_p(
        "• Audit trail: Every scan produces an in-toto compliant attestation envelope signed with Ed25519, alongside a SHA-256 Merkle "
        "tree root. This lets auditors verify that inventory results have not been altered."
    )
    add_p(
        "• Honest roadmap: Runtime observation currently uses socket-level TLS probing (ecdat probe). An experimental in-kernel eBPF "
        "tracing script exists in the repo, but is kept separate for specialized host audits because it requires root access. "
        "Full post-quantum signing (ML-DSA-65) for our attestation envelope is being integrated in our next milestone."
    )

    # -------------------------------------------------------------
    # 5. RECOMMENDED PILOT STEP
    # -------------------------------------------------------------
    add_h1("5. Next step: running a quick pilot")
    
    add_p(
        "The fastest way to evaluate ECDAT is to run it on a single non-sensitive internal repository. "
        "The tool installs as a lightweight Python package and runs locally without sending code outside your network:"
    )

    add_callout(
        "1. Scan a sample repo: 'ecdat scan ./sample-service --output cbom.json'\n"
        "2. Review the generated inventory and verify that cache/utility hashes were automatically filtered out.\n"
        "3. Test an external endpoint: 'ecdat probe api.internal.local:443' to inspect cipher suites and MSS margins.",
        title="Suggested Evaluation Command"
    )

    add_p(
        "We would be glad to set up a short 15-minute walkthrough to run this together and show the interactive dashboard.",
        space_before=6
    )

    output_path = "/home/mohmedh/personal/ECDAT/Research/ECDAT_Technical_Evaluation_Report.docx"
    doc.save(output_path)
    print(f"Concise report successfully written to {output_path}")

if __name__ == "__main__":
    create_concise_report()
