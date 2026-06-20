import datetime
import getpass
import os
import platform
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import LongTable, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


class PDFReportGenerator:
    def __init__(self, output_dir="reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.styles = getSampleStyleSheet()
        self._ensure_style(
            "ReportTitle",
            parent=self.styles["Title"],
            alignment=TA_CENTER,
            fontSize=20,
            leading=24,
            textColor=colors.HexColor("#0f2d52"),
            spaceAfter=10,
        )
        self._ensure_style(
            "ReportSubtitle",
            parent=self.styles["Normal"],
            alignment=TA_CENTER,
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#4f5d73"),
            spaceAfter=16,
        )
        self._ensure_style(
            "SectionHeader",
            parent=self.styles["Heading2"],
            fontSize=13,
            leading=16,
            textColor=colors.HexColor("#0f2d52"),
            spaceBefore=10,
            spaceAfter=8,
        )
        self._ensure_style(
            "BodyTextSmall",
            parent=self.styles["BodyText"],
            fontSize=9,
            leading=13,
            alignment=TA_LEFT,
        )
        self._ensure_style(
            "MonospaceSmall",
            parent=self.styles["BodyText"],
            fontName="Courier",
            fontSize=8,
            leading=10,
        )
        self._ensure_style(
            "Notice",
            parent=self.styles["Italic"],
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#5f6b7a"),
        )

    def _ensure_style(self, name, parent, **kwargs):
        if name not in self.styles:
            self.styles.add(ParagraphStyle(name=name, parent=parent, **kwargs))

    def _safe_paragraph(self, value, style_name):
        text = escape(str(value or "N/A")).replace("\n", "<br/>")
        return Paragraph(text, self.styles[style_name])

    def _as_int(self, value):
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

    def _build_table(self, data, col_widths, header_color=None, long_table=False):
        table_cls = LongTable if long_table else Table
        table = table_cls(data, colWidths=col_widths, repeatRows=1 if header_color else 0)
        style = [
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#c7ced8")),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
        ]

        if header_color:
            style.extend(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), header_color),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("ALIGN", (0, 0), (-1, 0), "CENTER"),
                ]
            )
            for row_index in range(1, len(data)):
                if row_index % 2 == 0:
                    style.append(("BACKGROUND", (0, row_index), (-1, row_index), colors.HexColor("#f5f7fa")))
        else:
            style.extend(
                [
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef1f5")),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ]
            )

        table.setStyle(TableStyle(style))
        return table

    def _read_hash_manifest(self, hash_manifest_path, preview_limit=20):
        preview_rows = []
        total_hashes = 0
        manifest_exists = bool(hash_manifest_path and os.path.exists(hash_manifest_path))
        if not manifest_exists:
            return preview_rows, total_hashes, False

        with open(hash_manifest_path, "r", encoding="utf-8") as handle:
            for line in handle:
                parts = line.strip().split("  ", 1)
                if len(parts) != 2:
                    continue
                total_hashes += 1
                if len(preview_rows) < preview_limit:
                    preview_rows.append(
                        [
                            self._safe_paragraph(parts[1], "BodyTextSmall"),
                            self._safe_paragraph(parts[0], "MonospaceSmall"),
                        ]
                    )

        return preview_rows, total_hashes, True

    def _decorate_page(self, canvas, doc, case_id, generated_at):
        canvas.saveState()
        page_width, page_height = letter

        canvas.setStrokeColor(colors.HexColor("#0f2d52"))
        canvas.setLineWidth(1)
        canvas.line(doc.leftMargin, page_height - 28, page_width - doc.rightMargin, page_height - 28)

        canvas.setFont("Helvetica-Bold", 9)
        canvas.setFillColor(colors.HexColor("#0f2d52"))
        canvas.drawString(doc.leftMargin, page_height - 22, "Browser Forensic Executive Summary")

        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#5f6b7a"))
        footer = f"Case {case_id} | Generated {generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}"
        canvas.drawString(doc.leftMargin, 18, footer)
        canvas.drawRightString(page_width - doc.rightMargin, 18, f"Page {canvas.getPageNumber()}")
        canvas.restoreState()

    def generate_executive_summary(
        self,
        filename,
        execution_start,
        stats,
        hash_manifest_path,
        case_id="N/A",
        investigator="Unknown",
        evidence_id="N/A",
        warrant_id="N/A",
        jurisdiction="N/A",
        audit_log_path=None,
        custody_log_path=None,
    ):
        """
        Generates a structured executive PDF suitable for case handoff.
        """
        filepath = self.output_dir / filename
        generated_at = datetime.datetime.now(datetime.timezone.utc)
        doc = SimpleDocTemplate(
            str(filepath),
            pagesize=letter,
            leftMargin=40,
            rightMargin=40,
            topMargin=46,
            bottomMargin=34,
            title="Browser Forensic Executive Summary",
            author=str(investigator or "Unknown"),
        )

        total_records = sum(self._as_int(value) for value in stats.values())
        nonzero_stats = [(name, self._as_int(value)) for name, value in stats.items() if self._as_int(value) > 0]
        hash_preview_rows, total_hashes, manifest_exists = self._read_hash_manifest(hash_manifest_path)
        top_categories = ", ".join(f"{name}: {value}" for name, value in nonzero_stats[:5]) or "No artifact records recovered."

        elements = [
            Paragraph("Browser Forensic Investigation Report", self.styles["ReportTitle"]),
            Paragraph(
                "Executive summary of browser artifact collection, evidence integrity, and case metadata.",
                self.styles["ReportSubtitle"],
            ),
            self._safe_paragraph(
                (
                    f"Collection started at {execution_start} and this report was generated at {generated_at}. "
                    f"A total of {total_records} parsed records were produced across {len(nonzero_stats)} non-zero artifact categories. "
                    f"Highest-volume categories: {top_categories}"
                ),
                "BodyTextSmall",
            ),
            Spacer(1, 12),
            Paragraph("Case Metadata", self.styles["SectionHeader"]),
        ]

        case_table = self._build_table(
            [
                ["Case ID", case_id],
                ["Investigator", investigator],
                ["Evidence ID", evidence_id],
                ["Warrant ID", warrant_id],
                ["Jurisdiction", jurisdiction],
                ["Execution Start (UTC)", execution_start],
                ["Report Generated (UTC)", generated_at],
                ["Executing Authorized User", getpass.getuser()],
                ["Target System OS", f"{platform.system()} {platform.release()}"],
            ],
            [155, 350],
        )
        elements.extend([case_table, Spacer(1, 14), Paragraph("Evidence Summary", self.styles["SectionHeader"])])

        stats_table_data = [["Artifact Category", "Recovered Records"]]
        for name, value in stats.items():
            stats_table_data.append([name, str(self._as_int(value))])
        stats_table_data.append(["Total Parsed Records", str(total_records)])
        stats_table = self._build_table(stats_table_data, [290, 120], header_color=colors.HexColor("#0f2d52"))
        elements.extend([stats_table, Spacer(1, 14), Paragraph("Integrity and Supporting Records", self.styles["SectionHeader"])])

        support_rows = [
            ["Hash Manifest Status", "Present" if manifest_exists else "Missing or unreadable"],
            ["Hashed Artifact Entries", str(total_hashes)],
            ["Hash Manifest File", Path(hash_manifest_path).name if hash_manifest_path else "N/A"],
            ["Audit Log File", Path(audit_log_path).name if audit_log_path else "N/A"],
            ["Custody Log File", Path(custody_log_path).name if custody_log_path else "N/A"],
        ]
        support_table = self._build_table(support_rows, [155, 350])
        elements.extend(
            [
                support_table,
                Spacer(1, 8),
                self._safe_paragraph(
                    "Full SHA-256 validation data is stored in the hash manifest. The PDF includes a capped preview to keep the executive report readable.",
                    "Notice",
                ),
            ]
        )

        if hash_preview_rows:
            elements.extend([PageBreak(), Paragraph("Hash Manifest Preview", self.styles["SectionHeader"])])
            preview_table = self._build_table(
                [["Filename", "SHA-256 Hash"]] + hash_preview_rows,
                [210, 285],
                header_color=colors.HexColor("#7a1f1f"),
                long_table=True,
            )
            elements.append(preview_table)
            if total_hashes > len(hash_preview_rows):
                elements.extend(
                    [
                        Spacer(1, 8),
                        self._safe_paragraph(
                            f"Preview truncated: {len(hash_preview_rows)} of {total_hashes} hash entries are shown here. Refer to hash_manifest.txt for the complete list.",
                            "Notice",
                        ),
                    ]
                )
        else:
            elements.extend(
                [
                    Spacer(1, 10),
                    self._safe_paragraph(
                        "No valid hash manifest entries were available when this report was generated.",
                        "Notice",
                    ),
                ]
            )

        elements.extend(
            [
                Spacer(1, 14),
                Paragraph("Investigator Notice", self.styles["SectionHeader"]),
                self._safe_paragraph(
                    "This executive summary is intended for case review and handoff. Analysts should correlate the reported record counts with the source CSV/XLSX outputs, the signed chain-of-custody log, and the full hash manifest before evidentiary submission.",
                    "BodyTextSmall",
                ),
            ]
        )

        doc.build(
            elements,
            onFirstPage=lambda canvas, doc: self._decorate_page(canvas, doc, case_id, generated_at),
            onLaterPages=lambda canvas, doc: self._decorate_page(canvas, doc, case_id, generated_at),
        )
        print(f"[+] Successfully generated Executive PDF Report: {filepath}")
        return True
