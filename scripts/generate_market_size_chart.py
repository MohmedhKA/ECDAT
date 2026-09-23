#!/usr/bin/env python3
"""
Generate publication-quality Plotly charts for TAM, SAM, SOM:
1. Nested Concentric Circles with 3 detailed KPI cards on the right
2. Geometric Funnel with 3 detailed KPI cards on the right
Outputs interactive HTML and high-resolution 2x PNGs.
"""

from pathlib import Path
import plotly.graph_objects as go

OUTPUT_DIR = Path("/home/mohmedh/personal/ECDAT/Research")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

BG_COLOR = "#0A0F1D"
PANEL_BG = "#111827"

TAM_COLOR = "rgba(59, 130, 246, 0.16)"
TAM_BORDER = "#3B82F6"
SAM_COLOR = "rgba(14, 165, 233, 0.22)"
SAM_BORDER = "#0EA5E9"
SOM_COLOR = "rgba(16, 185, 129, 0.32)"
SOM_BORDER = "#10B981"


def add_kpi_card_annotations(fig, card_x0, card_x1):
    """Adds cleanly spaced, non-overlapping annotations for the 3 KPI cards."""
    # Common font stack
    font_family = "Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif"

    # Card 1: TAM
    fig.add_shape(
        type="rect", xref="x", yref="y",
        x0=card_x0, y0=0.36, x1=card_x1, y1=0.98,
        fillcolor=PANEL_BG,
        line=dict(color=TAM_BORDER, width=1.5),
        layer="below"
    )
    fig.add_annotation(
        x=card_x0 + 0.05, y=0.90, xref="x", yref="y",
        text="<b>TOTAL ADDRESSABLE MARKET (TAM)</b>",
        font=dict(family=font_family, size=11, color="#3B82F6"),
        align="left", showarrow=False, xanchor="left", yanchor="top"
    )
    fig.add_annotation(
        x=card_x0 + 0.05, y=0.79, xref="x", yref="y",
        text="<b>$2.84 Billion</b> <span style='font-size:14px; color:#94A3B8;'>by 2030 (46.2% CAGR)</span>",
        font=dict(family=font_family, size=24, color="#FFFFFF"),
        align="left", showarrow=False, xanchor="left", yanchor="top"
    )
    fig.add_annotation(
        x=card_x0 + 0.05, y=0.62, xref="x", yref="y",
        text="• Global Post-Quantum Cryptography (PQC) market<br>"
             "• <b>MarketsandMarkets (Oct 2025):</b> USD 0.42B (2025) → USD 2.84B (2030)<br>"
             "• <b>Mordor Intelligence:</b> Projects upside market expansion to USD 4.60B",
        font=dict(family=font_family, size=11, color="#CBD5E1"),
        align="left", showarrow=False, xanchor="left", yanchor="top"
    )

    # Card 2: SAM
    fig.add_shape(
        type="rect", xref="x", yref="y",
        x0=card_x0, y0=-0.31, x1=card_x1, y1=0.31,
        fillcolor=PANEL_BG,
        line=dict(color=SAM_BORDER, width=1.5),
        layer="below"
    )
    fig.add_annotation(
        x=card_x0 + 0.05, y=0.23, xref="x", yref="y",
        text="<b>SERVICEABLE ADDRESSABLE MARKET (SAM)</b>",
        font=dict(family=font_family, size=11, color="#0EA5E9"),
        align="left", showarrow=False, xanchor="left", yanchor="top"
    )
    fig.add_annotation(
        x=card_x0 + 0.05, y=0.12, xref="x", yref="y",
        text="<b>$40 Million</b> <span style='font-size:14px; color:#94A3B8;'>by 2030 (India Enterprise Slice)</span>",
        font=dict(family=font_family, size=24, color="#FFFFFF"),
        align="left", showarrow=False, xanchor="left", yanchor="top"
    )
    fig.add_annotation(
        x=card_x0 + 0.05, y=-0.05, xref="x", yref="y",
        text="• India Addressable Market = <b>TAM × 1.4%</b> (Derived estimate)<br>"
             "• Based on India share of world security spend (Gartner 2026: USD 3.4B / 244.2B)<br>"
             "• Driven by RBI BFSI mandates, defense communications & digital governance",
        font=dict(family=font_family, size=11, color="#CBD5E1"),
        align="left", showarrow=False, xanchor="left", yanchor="top"
    )

    # Card 3: SOM
    fig.add_shape(
        type="rect", xref="x", yref="y",
        x0=card_x0, y0=-0.98, x1=card_x1, y1=-0.36,
        fillcolor=PANEL_BG,
        line=dict(color=SOM_BORDER, width=1.5),
        layer="below"
    )
    fig.add_annotation(
        x=card_x0 + 0.05, y=-0.44, xref="x", yref="y",
        text="<b>SERVICEABLE OBTAINABLE MARKET (SOM)</b>",
        font=dict(family=font_family, size=11, color="#10B981"),
        align="left", showarrow=False, xanchor="left", yanchor="top"
    )
    fig.add_annotation(
        x=card_x0 + 0.05, y=-0.55, xref="x", yref="y",
        text="<b>$2 Million</b> <span style='font-size:14px; color:#94A3B8;'>by 2030 (Pilot Pipeline Target)</span>",
        font=dict(family=font_family, size=24, color="#FFFFFF"),
        align="left", showarrow=False, xanchor="left", yanchor="top"
    )
    fig.add_annotation(
        x=card_x0 + 0.05, y=-0.72, xref="x", yref="y",
        text="• Realistic initial target: <b>5% capture of India SAM</b> (baseline assumption)<br>"
             "• Conservative initial assumption; to be replaced with pilot enterprise pipeline<br>"
             "• Direct beachhead: 15–20 high-assurance tier-1 banking, defense & cloud gateways",
        font=dict(family=font_family, size=11, color="#CBD5E1"),
        align="left", showarrow=False, xanchor="left", yanchor="top"
    )


def create_nested_circles_chart(output_png: Path, output_html: Path):
    """Creates the Nested Circles TAM-SAM-SOM visualization."""
    fig = go.Figure()

    cx, cy = -0.52, 0.0
    r_tam = 0.95
    r_sam = 0.63
    r_som = 0.33

    # Add Circle Shapes
    fig.add_shape(
        type="circle", xref="x", yref="y",
        x0=cx - r_tam, y0=cy - r_tam, x1=cx + r_tam, y1=cy + r_tam,
        fillcolor=TAM_COLOR, line=dict(color=TAM_BORDER, width=2.5),
        layer="below"
    )
    fig.add_shape(
        type="circle", xref="x", yref="y",
        x0=cx - r_sam, y0=cy - r_sam, x1=cx + r_sam, y1=cy + r_sam,
        fillcolor=SAM_COLOR, line=dict(color=SAM_BORDER, width=2.5),
        layer="below"
    )
    fig.add_shape(
        type="circle", xref="x", yref="y",
        x0=cx - r_som, y0=cy - r_som, x1=cx + r_som, y1=cy + r_som,
        fillcolor=SOM_COLOR, line=dict(color=SOM_BORDER, width=3.0),
        layer="below"
    )

    # In-circle labels
    fig.add_trace(go.Scatter(
        x=[cx, cx, cx],
        y=[cy + 0.76, cy + 0.44, cy],
        mode="text",
        text=[
            "<b>TAM</b><br><span style='font-size:11px; color:#93C5FD;'>Global Market</span>",
            "<b>SAM</b><br><span style='font-size:11px; color:#7DD3FC;'>India Share</span>",
            "<b>SOM</b><br><span style='font-size:12px; color:#6EE7B7;'>Pilot Pipeline</span>"
        ],
        textfont=dict(
            family="Inter, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif",
            size=[15, 14, 16],
            color=["#BFDBFE", "#BAE6FD", "#FFFFFF"]
        ),
        hoverinfo="none",
        showlegend=False
    ))

    # Connector Lines
    card_x0 = 0.68
    card_x1 = 2.40
    fig.add_shape(type="line", x0=cx + r_tam * 0.70, y0=0.67, x1=card_x0, y1=0.67,
                  line=dict(color=TAM_BORDER, width=1.5, dash="dot"))
    fig.add_shape(type="line", x0=cx + r_sam * 0.85, y0=0.0, x1=card_x0, y1=0.0,
                  line=dict(color=SAM_BORDER, width=1.5, dash="dot"))
    fig.add_shape(type="line", x0=cx + r_som * 0.95, y0=-0.67, x1=card_x0, y1=-0.67,
                  line=dict(color=SOM_BORDER, width=1.5, dash="dot"))

    # Add the 3 KPI cards on the right
    add_kpi_card_annotations(fig, card_x0, card_x1)

    fig.update_layout(
        title=dict(
            text="<b>ECDAT Market Opportunity: TAM • SAM • SOM (2025–2030)</b><br>"
                 "<span style='font-size:13px; color:#94A3B8;'>Top-Down Sizing with Source Citations & Derived Enterprise Capture</span>",
            font=dict(family="Inter, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif", size=20, color="#F8FAFC"),
            x=0.03, y=0.96
        ),
        paper_bgcolor=BG_COLOR,
        plot_bgcolor=BG_COLOR,
        width=1350,
        height=720,
        margin=dict(l=40, r=40, t=90, b=30),
        xaxis=dict(range=[-1.6, 2.50], showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(range=[-1.18, 1.18], showgrid=False, zeroline=False, showticklabels=False)
    )

    fig.write_html(str(output_html), include_plotlyjs="cdn")
    fig.write_image(str(output_png), scale=2)
    print(f"[+] Nested Circles Chart generated:\n    - {output_html}\n    - {output_png}")


def create_funnel_with_cards(output_png: Path, output_html: Path):
    """
    Creates a combined Funnel on the left + 3 KPI Cards on the right.
    """
    fig = go.Figure()

    # We draw the funnel using polygonal shapes on the left: x in [-1.5, 0.4]
    # TAM trapezoid: y in [0.36, 0.98]
    fig.add_shape(
        type="path",
        path="M -1.5 0.98 L 0.4 0.98 L 0.25 0.36 L -1.35 0.36 Z",
        fillcolor=TAM_COLOR, line=dict(color=TAM_BORDER, width=2)
    )
    # SAM trapezoid: y in [-0.31, 0.31]
    fig.add_shape(
        type="path",
        path="M -1.35 0.31 L 0.25 0.31 L 0.10 -0.31 L -1.20 -0.31 Z",
        fillcolor=SAM_COLOR, line=dict(color=SAM_BORDER, width=2)
    )
    # SOM trapezoid/box: y in [-0.98, -0.36]
    fig.add_shape(
        type="path",
        path="M -1.20 -0.36 L 0.10 -0.36 L -0.02 -0.98 L -1.08 -0.98 Z",
        fillcolor=SOM_COLOR, line=dict(color=SOM_BORDER, width=2)
    )

    # In-funnel text labels
    fig.add_trace(go.Scatter(
        x=[-0.55, -0.55, -0.55],
        y=[0.67, 0.0, -0.67],
        mode="text",
        text=[
            "<b>TAM: $2.84 B</b><br><span style='font-size:12px; color:#93C5FD;'>Global PQC Market</span>",
            "<b>SAM: $40 M</b><br><span style='font-size:12px; color:#7DD3FC;'>India Enterprise Share</span>",
            "<b>SOM: $2 M</b><br><span style='font-size:12px; color:#6EE7B7;'>Pilot Pipeline</span>"
        ],
        textfont=dict(
            family="Inter, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif",
            size=[15, 14, 15],
            color=["#FFFFFF", "#FFFFFF", "#FFFFFF"]
        ),
        hoverinfo="none",
        showlegend=False
    ))

    # Connector Lines
    card_x0 = 0.68
    card_x1 = 2.40
    fig.add_shape(type="line", x0=0.30, y0=0.67, x1=card_x0, y1=0.67,
                  line=dict(color=TAM_BORDER, width=1.5, dash="dot"))
    fig.add_shape(type="line", x0=0.17, y0=0.0, x1=card_x0, y1=0.0,
                  line=dict(color=SAM_BORDER, width=1.5, dash="dot"))
    fig.add_shape(type="line", x0=0.04, y0=-0.67, x1=card_x0, y1=-0.67,
                  line=dict(color=SOM_BORDER, width=1.5, dash="dot"))

    # Add the 3 KPI cards on the right
    add_kpi_card_annotations(fig, card_x0, card_x1)

    fig.update_layout(
        title=dict(
            text="<b>ECDAT Market Opportunity: TAM • SAM • SOM (Funnel Model)</b><br>"
                 "<span style='font-size:13px; color:#94A3B8;'>Cascading Conversion from Global Spend (USD 2.84B) to Initial Beachhead (USD 2M)</span>",
            font=dict(family="Inter, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif", size=20, color="#F8FAFC"),
            x=0.03, y=0.96
        ),
        paper_bgcolor=BG_COLOR,
        plot_bgcolor=BG_COLOR,
        width=1350,
        height=720,
        margin=dict(l=40, r=40, t=90, b=30),
        xaxis=dict(range=[-1.6, 2.50], showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(range=[-1.18, 1.18], showgrid=False, zeroline=False, showticklabels=False)
    )

    fig.write_html(str(output_html), include_plotlyjs="cdn")
    fig.write_image(str(output_png), scale=2)
    print(f"[+] Funnel Chart generated:\n    - {output_html}\n    - {output_png}")


if __name__ == "__main__":
    create_nested_circles_chart(
        OUTPUT_DIR / "tam_sam_som_nested_circles.png",
        OUTPUT_DIR / "tam_sam_som_nested_circles.html"
    )
    create_funnel_with_cards(
        OUTPUT_DIR / "tam_sam_som_funnel.png",
        OUTPUT_DIR / "tam_sam_som_funnel.html"
    )
