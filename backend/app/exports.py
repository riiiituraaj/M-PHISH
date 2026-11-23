"""Text-only PDF export. No HTML renderer, remote images, links or URL fetches."""

from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer


def report_pdf(report):
    buffer = BytesIO()
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="ReportBody",
            fontName="Helvetica",
            fontSize=10,
            leading=15,
            spaceAfter=9,
            textColor=colors.HexColor("#213047"),
        )
    )

    def p(value, style="ReportBody"):
        # Escape all report text before the limited ReportLab paragraph parser.
        return Paragraph(escape(str(value)), styles[style])

    content = [
        p("M-PHISH | Investigation report", "Title"),
        Spacer(1, 14),
        p(report["url"], "Heading2"),
        p("Assessment: " + report["classification"], "Heading2"),
        p(report["summary"]),
        p("Observed: " + report["created_at"]),
        p("Expires: " + report["expires_at"]),
        p("Contract " + report["contract_version"] + " | Policy " + report["policy_version"]),
        p("Coverage: " + str(report["coverage"])),
        p("Recommended action", "Heading2"),
        p(report["recommendation"]),
        p("Observed evidence", "Heading2"),
    ]
    if not report["evidence"]:
        content.append(
            p("No warning evidence was recorded. Incomplete checks do not establish safety.")
        )
    for evidence in report["evidence"][:100]:
        content.append(
            KeepTogether(
                [
                    p(evidence["title"], "Heading3"),
                    p(evidence["description"]),
                    p("Source: " + evidence["source"] + " | Observed: " + evidence["observed_at"]),
                    p("Evidence ID: " + evidence["id"]),
                ]
            )
        )
    content.append(p("Limitations", "Heading2"))
    for limitation in report["limitations"]:
        content.append(p(limitation))

    def footer(canvas, doc):
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#526176"))
        canvas.drawString(42, 25, "Private report | M-PHISH | " + report["id"])
        canvas.drawRightString(553, 25, str(doc.page))

    SimpleDocTemplate(
        buffer,
        pagesize=(595, 842),
        rightMargin=42,
        leftMargin=42,
        topMargin=42,
        bottomMargin=48,
        title="M-PHISH investigation report",
        author="M-PHISH",
    ).build(content, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()
