#!/usr/bin/env python3
"""
Generate standalone TAM SAM SOM charts (Graphic Alone, without right-side paragraphs)
1. Nested Concentric Circles (alone)
2. Cascading Funnel (alone)
"""

from pathlib import Path
import plotly.graph_objects as go

OUTPUT_DIR = Path("/home/mohmedh/personal/ECDAT/Research")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

BG_COLOR = "#0A0F1D"

TAM_COLOR = "rgba(59, 130, 246, 0.16)"
TAM_BORDER = "#3B82F6"
SAM_COLOR = "rgba(14, 165, 233, 0.24)"
SAM_BORDER = "#0EA5E9"
SOM_COLOR = "rgba(16, 185, 129, 0.36)"
SOM_BORDER = "#10B981"

FONT_FAMILY = "Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif"


def create_nested_circles_alone(output_png: Path, output_html: Path):
    """Generates standalone centered Nested Circles for TAM, SAM, SOM."""
    fig = go.Figure()

    cx, cy = 0.0, 0.0
    r_tam = 1.00
    r_sam = 0.65
    r_som = 0.34

    # 1. TAM Outer Ring
    fig.add_shape(
        type="circle", xref="x", yref="y",
        x0=cx - r_tam, y0=cy - r_tam,
        x1=cx + r_tam, y1=cy + r_tam,
        fillcolor=TAM_COLOR,
        line=dict(color=TAM_BORDER, width=3.0),
        layer="below"
    )

    # 2. SAM Middle Ring
    fig.add_shape(
        type="circle", xref="x", yref="y",
        x0=cx - r_sam, y0=cy - r_sam,
        x1=cx + r_sam, y1=cy + r_sam,
        fillcolor=SAM_COLOR,
        line=dict(color=SAM_BORDER, width=3.0),
        layer="below"
    )

    # 3. SOM Core Ring
    fig.add_shape(
        type="circle", xref="x", yref="y",
        x0=cx - r_som, y0=cy - r_som,
        x1=cx + r_som, y1=cy + r_som,
        fillcolor=SOM_COLOR,
        line=dict(color=SOM_BORDER, width=3.5),
        layer="below"
    )

    # TAM Annotation (Upper Tier)
    fig.add_annotation(
        x=cx, y=cy + 0.81, xref="x", yref="y",
        text="<b>TAM</b><br>"
             "<span style='font-size:24px; color:#FFFFFF;'><b>$2.84 Billion</b></span><br>"
             "<span style='font-size:13px; color:#93C5FD;'>Global PQC Market (2030)</span>",
        align="center", showarrow=False,
        font=dict(family=FONT_FAMILY, size=15, color="#60A5FA")
    )

    # SAM Annotation (Mid Tier)
    fig.add_annotation(
        x=cx, y=cy + 0.47, xref="x", yref="y",
        text="<b>SAM</b><br>"
             "<span style='font-size:22px; color:#FFFFFF;'><b>$40 Million</b></span><br>"
             "<span style='font-size:12px; color:#7DD3FC;'>India Addressable Slice (1.4%)</span>",
        align="center", showarrow=False,
        font=dict(family=FONT_FAMILY, size=14, color="#38BDF8")
    )

    # SOM Annotation (Core Center)
    fig.add_annotation(
        x=cx, y=cy, xref="x", yref="y",
        text="<b>SOM</b><br>"
             "<span style='font-size:24px; color:#FFFFFF;'><b>$2 Million</b></span><br>"
             "<span style='font-size:12px; color:#6EE7B7;'>Initial Pilot Target (5% of SAM)</span>",
        align="center", showarrow=False,
        font=dict(family=FONT_FAMILY, size=15, color="#34D399")
    )

    fig.update_layout(
        title=dict(
            text="<b>Market Opportunity Sizing: TAM • SAM • SOM (2025–2030)</b>",
            font=dict(family=FONT_FAMILY, size=22, color="#F8FAFC"),
            x=0.5, y=0.96, xanchor="center"
        ),
        paper_bgcolor=BG_COLOR,
        plot_bgcolor=BG_COLOR,
        width=1000,
        height=850,
        margin=dict(l=40, r=40, t=80, b=40),
        xaxis=dict(range=[-1.2, 1.2], showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(range=[-1.15, 1.15], showgrid=False, zeroline=False, showticklabels=False)
    )

    fig.write_html(str(output_html), include_plotlyjs="cdn")
    fig.write_image(str(output_png), scale=2)
    print(f"[+] Nested Circles Alone generated:\n    - {output_html}\n    - {output_png}")


def create_funnel_alone(output_png: Path, output_html: Path):
    """Generates standalone centered Funnel for TAM, SAM, SOM."""
    fig = go.Figure()

    fig.add_trace(go.Funnel(
        y=[
            "<b>TAM</b><br><span style='font-size:12px; color:#94A3B8;'>Global PQC Market</span>",
            "<b>SAM</b><br><span style='font-size:12px; color:#94A3B8;'>India Addressable</span>",
            "<b>SOM</b><br><span style='font-size:12px; color:#94A3B8;'>Pilot Target</span>"
        ],
        x=[100, 62, 34],
        textinfo="text",
        text=[
            "<b>TAM: $2.84 Billion</b> (2030)<br><span style='font-size:13px;'>Global Market • 46.2% CAGR from USD 0.42B (2025)</span>",
            "<b>SAM: $40 Million</b> (2030)<br><span style='font-size:13px;'>India Enterprise Slice (1.4% of Global TAM)</span>",
            "<b>SOM: $2 Million</b> (2030)<br><span style='font-size:13px;'>Initial Pilot Pipeline Capture (5% of SAM)</span>"
        ],
        textposition="inside",
        textfont=dict(family=FONT_FAMILY, size=15, color="#FFFFFF"),
        marker=dict(
            color=["#2563EB", "#0284C7", "#059669"],
            line=dict(color=["#60A5FA", "#38BDF8", "#34D399"], width=2.5)
        ),
        connector=dict(
            line=dict(color="#334155", width=2, dash="dot"),
            fillcolor="rgba(30, 41, 59, 0.4)"
        ),
        width=0.75
    ))

    fig.update_layout(
        title=dict(
            text="<b>Market Funnel: TAM • SAM • SOM (2025–2030)</b>",
            font=dict(family=FONT_FAMILY, size=22, color="#F8FAFC"),
            x=0.5, y=0.96, xanchor="center"
        ),
        paper_bgcolor=BG_COLOR,
        plot_bgcolor=BG_COLOR,
        width=1100,
        height=700,
        margin=dict(l=180, r=60, t=90, b=50),
        yaxis=dict(
            tickfont=dict(family=FONT_FAMILY, size=14, color="#E2E8F0")
        )
    )

    fig.write_html(str(output_html), include_plotlyjs="cdn")
    fig.write_image(str(output_png), scale=2)
    print(f"[+] Funnel Alone generated:\n    - {output_html}\n    - {output_png}")


if __name__ == "__main__":
    create_nested_circles_alone(
        OUTPUT_DIR / "tam_sam_som_nested_circles_alone.png",
        OUTPUT_DIR / "tam_sam_som_nested_circles_alone.html"
    )
    create_funnel_alone(
        OUTPUT_DIR / "tam_sam_som_funnel_alone.png",
        OUTPUT_DIR / "tam_sam_som_funnel_alone.html"
    )
