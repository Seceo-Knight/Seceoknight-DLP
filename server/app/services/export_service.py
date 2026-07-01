"""
Export Service
Handles CSV and PDF export functionality for reports
"""

import csv
import io
from typing import List, Dict, Any, Optional
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph,
    Spacer, PageBreak, Image, HRFlowable, KeepTogether,
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.pdfgen import canvas as pdfgen_canvas

from app.core.observability import StructuredLogger

logger = StructuredLogger(__name__)

# ── Brand colours ─────────────────────────────────────────────────────────────
BRAND_DARK   = colors.HexColor('#0f172a')   # slate-900
BRAND_NAVY   = colors.HexColor('#1e3a8a')   # blue-900
BRAND_BLUE   = colors.HexColor('#2563eb')   # blue-600
BRAND_LIGHT  = colors.HexColor('#eff6ff')   # blue-50
BRAND_ACCENT = colors.HexColor('#6366f1')   # indigo-500
GRAY_100     = colors.HexColor('#f3f4f6')
GRAY_700     = colors.HexColor('#374151')
RED_BG       = colors.HexColor('#fee2e2')
RED_HDR      = colors.HexColor('#dc2626')


class _NumberedCanvas(pdfgen_canvas.Canvas):
    """Canvas subclass that stamps page number and footer on every page."""

    def __init__(self, *args, report_title: str = "", generated_at: str = "", **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states: list = []
        self._report_title = report_title
        self._generated_at = generated_at

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self._draw_page_decorations(total)
            pdfgen_canvas.Canvas.showPage(self)
        pdfgen_canvas.Canvas.save(self)

    def _draw_page_decorations(self, page_count: int):
        page_num = self._pageNumber
        w, h = letter

        # ── Top brand bar (skip cover page = page 1) ──────────────────────────
        if page_num > 1:
            self.setFillColor(BRAND_NAVY)
            self.rect(0, h - 0.45 * inch, w, 0.45 * inch, fill=1, stroke=0)
            self.setFillColor(colors.white)
            self.setFont("Helvetica-Bold", 8)
            self.drawString(0.5 * inch, h - 0.28 * inch, "SeceoKnight DLP")
            self.setFont("Helvetica", 8)
            self.drawRightString(w - 0.5 * inch, h - 0.28 * inch, self._report_title)

        # ── Bottom footer ─────────────────────────────────────────────────────
        self.setFillColor(GRAY_700)
        self.rect(0, 0, w, 0.38 * inch, fill=1, stroke=0)
        self.setFillColor(colors.white)
        self.setFont("Helvetica", 7)
        self.drawString(0.5 * inch, 0.13 * inch,
                        f"Generated: {self._generated_at}  |  CONFIDENTIAL — Internal Use Only")
        self.setFont("Helvetica-Bold", 7)
        self.drawRightString(w - 0.5 * inch, 0.13 * inch,
                             f"Page {page_num} of {page_count}")


class ExportService:
    """Service for exporting data to various formats"""

    @staticmethod
    def export_to_csv(
        data: List[Dict[str, Any]],
        columns: Optional[List[str]] = None
    ) -> str:
        """
        Export data to CSV format

        Args:
            data: List of dictionaries to export
            columns: Optional list of columns to include (defaults to all)

        Returns:
            CSV string
        """
        if not data:
            return ""

        # Use provided columns or extract from first row
        if not columns:
            columns = list(data[0].keys())

        # Create CSV in memory
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=columns, extrasaction='ignore')

        writer.writeheader()
        for row in data:
            # Flatten nested dictionaries
            flat_row = ExportService._flatten_dict(row)
            writer.writerow(flat_row)

        return output.getvalue()

    @staticmethod
    def _flatten_dict(d: Dict[str, Any], parent_key: str = '', sep: str = '_') -> Dict[str, Any]:
        """Flatten nested dictionary"""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(ExportService._flatten_dict(v, new_key, sep=sep).items())
            elif isinstance(v, list):
                items.append((new_key, ', '.join(map(str, v))))
            else:
                items.append((new_key, v))
        return dict(items)

    @staticmethod
    def export_incidents_to_csv(incidents: List[Dict[str, Any]]) -> str:
        """
        Export incidents to CSV with proper formatting

        Args:
            incidents: List of incident dictionaries

        Returns:
            CSV string
        """
        columns = [
            'event_id', 'timestamp', 'severity', 'event_type',
            'agent_name', 'hostname', 'username', 'source_ip',
            'classification_type', 'confidence', 'blocked',
            'policy_id', 'policy_name'
        ]

        return ExportService.export_to_csv(incidents, columns)

    @staticmethod
    def export_analytics_to_csv(
        analytics_data: Dict[str, Any],
        report_type: str
    ) -> str:
        """
        Export analytics data to CSV

        Args:
            analytics_data: Analytics data dictionary
            report_type: Type of report (trends, violators, data_types, etc.)

        Returns:
            CSV string
        """
        if report_type == "trends":
            # Handle time series data
            if "series" in analytics_data:
                # Multiple series (grouped data)
                rows = []
                for series_name, data_points in analytics_data["series"].items():
                    for point in data_points:
                        rows.append({
                            "timestamp": point["timestamp"],
                            "series": series_name,
                            "count": point["count"]
                        })
            else:
                # Single series
                rows = analytics_data.get("data", [])

            return ExportService.export_to_csv(rows)

        elif report_type == "violators":
            return ExportService.export_to_csv(analytics_data)

        elif report_type == "data_types":
            return ExportService.export_to_csv(analytics_data)

        elif report_type == "policy_violations":
            return ExportService.export_to_csv(analytics_data)

        elif report_type == "incident_detail":
            # analytics_data is {"summary": {...}, "incidents": [...], "truncated": bool, ...}
            incidents = analytics_data.get("incidents", []) if isinstance(analytics_data, dict) else []
            return ExportService.export_to_csv(incidents)

        else:
            # Generic export
            return ExportService.export_to_csv(analytics_data)

    @staticmethod
    def export_to_pdf(
        title: str,
        data: Dict[str, Any],
        report_type: str,
        logo_path: Optional[str] = None,
        period_start: Optional[str] = None,
        period_end: Optional[str] = None,
        generated_by: Optional[str] = None,
    ) -> bytes:
        """
        Export data to PDF with branded cover page, header/footer, and page numbers.

        Args:
            title: Report title
            data: Data to export
            report_type: Type of report (summary, trends, violators, …)
            logo_path: Optional path to company logo
            period_start: Human-readable report period start
            period_end: Human-readable report period end
            generated_by: Who requested this report

        Returns:
            PDF bytes
        """
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        buffer = io.BytesIO()

        # Extra bottom margin to clear the footer bar
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=0.65 * inch,
            leftMargin=0.65 * inch,
            topMargin=0.65 * inch,
            bottomMargin=0.6 * inch,
        )

        # ── Styles ──────────────────────────────────────────────────────────────
        styles = getSampleStyleSheet()

        cover_title_style = ParagraphStyle(
            'CoverTitle',
            parent=styles['Title'],
            fontSize=28,
            textColor=colors.white,
            spaceAfter=16,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold',
        )
        cover_sub_style = ParagraphStyle(
            'CoverSub',
            parent=styles['Normal'],
            fontSize=12,
            textColor=colors.HexColor('#bfdbfe'),  # blue-200
            spaceAfter=8,
            alignment=TA_CENTER,
        )
        heading_style = ParagraphStyle(
            'SKHeading',
            parent=styles['Heading2'],
            fontSize=13,
            textColor=BRAND_NAVY,
            spaceBefore=18,
            spaceAfter=8,
            fontName='Helvetica-Bold',
        )
        body_style = ParagraphStyle(
            'SKBody',
            parent=styles['Normal'],
            fontSize=9,
            textColor=GRAY_700,
            spaceAfter=4,
        )

        elements: list = []

        # ── Cover page ──────────────────────────────────────────────────────────
        # Full-page dark background achieved via a 1-row table spanning the page
        page_w = letter[0] - 1.3 * inch  # usable width
        cover_bg_color = BRAND_DARK

        cover_inner: list = [Spacer(1, 1.2 * inch)]

        # Brand pill
        pill_style = ParagraphStyle('Pill', parent=styles['Normal'],
                                    fontSize=9, textColor=BRAND_ACCENT,
                                    alignment=TA_CENTER, fontName='Helvetica-Bold')
        cover_inner.append(Paragraph("▶  SECEOKNIGHT  DLP  PLATFORM", pill_style))
        cover_inner.append(Spacer(1, 0.25 * inch))

        # Title
        cover_inner.append(Paragraph(title, cover_title_style))
        cover_inner.append(Spacer(1, 0.1 * inch))

        # Divider line
        cover_inner.append(HRFlowable(width="80%", thickness=1,
                                       color=BRAND_ACCENT, spaceAfter=16, spaceBefore=0,
                                       hAlign='CENTER'))

        # Meta block
        meta_lines = []
        if period_start and period_end:
            meta_lines.append(f"Period: {period_start}  →  {period_end}")
        meta_lines.append(f"Report Type: {report_type.replace('_', ' ').title()}")
        meta_lines.append(f"Generated: {timestamp}")
        if generated_by:
            meta_lines.append(f"Requested by: {generated_by}")

        for line in meta_lines:
            cover_inner.append(Paragraph(line, cover_sub_style))

        cover_inner.append(Spacer(1, 1.5 * inch))

        # Confidentiality notice at bottom of cover
        conf_style = ParagraphStyle('Conf', parent=styles['Normal'],
                                    fontSize=8, textColor=colors.HexColor('#64748b'),
                                    alignment=TA_CENTER)
        cover_inner.append(HRFlowable(width="60%", thickness=0.5,
                                       color=colors.HexColor('#334155'),
                                       spaceAfter=12, hAlign='CENTER'))
        cover_inner.append(Paragraph(
            "CONFIDENTIAL — For internal use only. Do not distribute without authorization.",
            conf_style,
        ))

        # Wrap in a dark-background table
        cover_table = Table([[cover_inner]], colWidths=[page_w])
        cover_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), cover_bg_color),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 0),
            ('RIGHTPADDING', (0, 0), (-1, -1), 0),
            ('TOPPADDING', (0, 0), (-1, -1), 0),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
        ]))
        elements.append(cover_table)
        elements.append(PageBreak())

        # ── Content ─────────────────────────────────────────────────────────────
        dispatch = {
            "summary":           ExportService._create_summary_pdf_content,
            "violations":        ExportService._create_policy_violations_pdf_content,
            "trends":            ExportService._create_trends_pdf_content,
            "violators":         ExportService._create_violators_pdf_content,
            "data_types":        ExportService._create_data_types_pdf_content,
            "policy_violations": ExportService._create_policy_violations_pdf_content,
            "incidents":         ExportService._create_incidents_pdf_content,
            "compliance":        ExportService._create_summary_pdf_content,
            "policies":          ExportService._create_policy_violations_pdf_content,
            "incident_detail":   ExportService._create_incident_detail_pdf_content,
        }
        builder = dispatch.get(report_type, ExportService._create_summary_pdf_content)
        elements.extend(builder(data, styles, heading_style))

        # ── Build ────────────────────────────────────────────────────────────────
        def make_canvas(filename, **kwargs):
            return _NumberedCanvas(
                filename,
                report_title=title,
                generated_at=timestamp,
                **kwargs,
            )

        doc.build(elements, canvasmaker=make_canvas)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        return pdf_bytes

    @staticmethod
    def _create_summary_pdf_content(
        data: Dict[str, Any],
        styles: Any,
        heading_style: ParagraphStyle
    ) -> List:
        """Create PDF content for summary report"""
        elements = []

        # Period
        elements.append(Paragraph("Report Period", heading_style))
        period_data = [
            ["Start Date", data["period"]["start"]],
            ["End Date", data["period"]["end"]]
        ]
        period_table = Table(period_data, colWidths=[2*inch, 4*inch])
        period_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#e5e7eb')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
        ]))
        elements.append(period_table)
        elements.append(Spacer(1, 0.3*inch))

        # Key Metrics
        elements.append(Paragraph("Key Metrics", heading_style))
        metrics_data = [
            ["Metric", "Value"],
            ["Total Incidents", f"{data['total_incidents']:,}"],
            ["Critical Incidents", f"{data['critical_incidents']:,}"],
            ["Blocked Incidents", f"{data['blocked_incidents']:,}"],
            ["Active Agents", f"{data['active_agents']:,}"],
            ["Policy Violations", f"{data['policy_violations']:,}"],
            ["Block Rate", f"{data['block_rate']:.2f}%"],
            ["Most Common Data Type", data.get('most_common_datatype', 'N/A')]
        ]
        metrics_table = Table(metrics_data, colWidths=[3*inch, 3*inch])
        metrics_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), BRAND_NAVY),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, GRAY_100])
        ]))
        elements.append(metrics_table)

        return elements

    @staticmethod
    def _create_trends_pdf_content(
        data: Dict[str, Any],
        styles: Any,
        heading_style: ParagraphStyle
    ) -> List:
        """Create PDF content for trends report"""
        elements = []

        elements.append(Paragraph("Incident Trends", heading_style))
        elements.append(Paragraph(
            f"Interval: {data['interval'].capitalize()} | "
            f"Period: {data['start_date']} to {data['end_date']}",
            styles['Normal']
        ))
        elements.append(Spacer(1, 0.2*inch))

        # If grouped data, create table for each series
        if "series" in data:
            for series_name, data_points in data["series"].items():
                elements.append(Paragraph(f"Series: {series_name}", styles['Heading3']))

                # Limit to first 50 rows to avoid overly long PDFs
                limited_points = data_points[:50]
                table_data = [["Timestamp", "Count"]]
                table_data.extend([[point["timestamp"], point["count"]] for point in limited_points])

                table = Table(table_data, colWidths=[3.5*inch, 2.5*inch])
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), BRAND_NAVY),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, GRAY_100])
                ]))
                elements.append(table)
                elements.append(Spacer(1, 0.2*inch))

                if len(data_points) > 50:
                    elements.append(Paragraph(
                        f"(Showing first 50 of {len(data_points)} data points)",
                        styles['Italic']
                    ))
                    elements.append(Spacer(1, 0.2*inch))
        else:
            # Single series
            limited_points = data.get("data", [])[:50]
            table_data = [["Timestamp", "Count"]]
            table_data.extend([[point["timestamp"], point["count"]] for point in limited_points])

            table = Table(table_data, colWidths=[3.5*inch, 2.5*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), BRAND_NAVY),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, GRAY_100])
            ]))
            elements.append(table)

        elements.append(Spacer(1, 0.2*inch))
        elements.append(Paragraph(
            f"Total Incidents: {data.get('total_incidents', 0):,}",
            styles['Heading3']
        ))

        return elements

    @staticmethod
    def _create_violators_pdf_content(
        data: List[Dict[str, Any]],
        styles: Any,
        heading_style: ParagraphStyle
    ) -> List:
        """Create PDF content for top violators report"""
        elements = []

        elements.append(Paragraph("Top Violators", heading_style))

        if not data:
            elements.append(Paragraph("No violators found for this period.", styles['Normal']))
            return elements

        # Determine columns based on first row
        first_row = data[0]
        if "agent_id" in first_row:
            # Agent name IS the hostname — no separate hostname field exists.
            # Omit raw Agent ID (long UUID) and redundant Hostname column.
            table_data = [["Agent Name", "OS / IP", "Incidents", "Critical"]]
            for row in data:
                name = str(row.get("agent_name") or row.get("agent_id") or "Unknown")
                os_ip = str(row.get("os", "")).title()
                table_data.append([
                    Paragraph(name[:60], styles['Normal']),
                    Paragraph(os_ip[:30], styles['Normal']),
                    row.get("incident_count", 0),
                    row.get("critical_count", 0)
                ])
            col_widths = [3.0*inch, 2.0*inch, 1.0*inch, 0.8*inch]

        elif "username" in first_row:
            table_data = [["Username", "Incidents", "Critical"]]
            for row in data:
                table_data.append([
                    row.get("username", ""),
                    row.get("incident_count", 0),
                    row.get("critical_count", 0)
                ])
            col_widths = [3*inch, 1.5*inch, 1.5*inch]

        else:  # IP address
            table_data = [["IP Address", "Incidents", "Critical"]]
            for row in data:
                table_data.append([
                    row.get("ip_address", ""),
                    row.get("incident_count", 0),
                    row.get("critical_count", 0)
                ])
            col_widths = [3*inch, 1.5*inch, 1.5*inch]

        table = Table(table_data, colWidths=col_widths)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), RED_HDR),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('ALIGN', (-2, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, RED_BG])
        ]))
        elements.append(table)

        return elements

    @staticmethod
    def _create_data_types_pdf_content(
        data: List[Dict[str, Any]],
        styles: Any,
        heading_style: ParagraphStyle
    ) -> List:
        """Create PDF content for data types report"""
        elements = []

        elements.append(Paragraph("Detected Data Types", heading_style))

        if not data:
            elements.append(Paragraph("No data types detected for this period.", styles['Normal']))
            return elements

        table_data = [["Data Type", "Count", "Percentage", "Avg Confidence"]]
        for row in data:
            table_data.append([
                row.get("data_type", ""),
                f"{row.get('count', 0):,}",
                f"{row.get('percentage', 0):.2f}%",
                f"{row.get('avg_confidence', 0):.2f}"
            ])

        table = Table(table_data, colWidths=[2*inch, 1.5*inch, 1.5*inch, 1.5*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), BRAND_NAVY),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, GRAY_100])
        ]))
        elements.append(table)

        return elements

    @staticmethod
    def _create_policy_violations_pdf_content(
        data: List[Dict[str, Any]],
        styles: Any,
        heading_style: ParagraphStyle
    ) -> List:
        """Create PDF content for policy violations report"""
        elements = []

        elements.append(Paragraph("Policy Violations", heading_style))

        if not data:
            elements.append(Paragraph("No policy violations for this period.", styles['Normal']))
            return elements

        table_data = [["Policy ID", "Policy Name", "Violations", "Blocked", "Block Rate"]]
        for row in data:
            table_data.append([
                row.get("policy_id", "")[:20],  # Truncate long IDs
                row.get("policy_name", "")[:30],  # Truncate long names
                f"{row.get('violation_count', 0):,}",
                f"{row.get('blocked_count', 0):,}",
                f"{row.get('block_rate', 0):.2f}%"
            ])

        table = Table(table_data, colWidths=[1.3*inch, 2*inch, 1*inch, 1*inch, 1*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), BRAND_NAVY),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (1, -1), 'LEFT'),
            ('ALIGN', (2, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, GRAY_100])
        ]))
        elements.append(table)

        return elements

    @staticmethod
    def _create_incidents_pdf_content(
        data: List[Dict[str, Any]],
        styles: Any,
        heading_style: ParagraphStyle
    ) -> List:
        """Create PDF content for incidents report"""
        elements = []

        elements.append(Paragraph("Incident Report", heading_style))

        if not data:
            elements.append(Paragraph("No incidents found for this period.", styles['Normal']))
            return elements

        # Limit to first 100 incidents
        limited_data = data[:100]

        table_data = [["Event ID", "Timestamp", "Severity", "Type", "Agent", "Blocked"]]
        for row in limited_data:
            table_data.append([
                row.get("event_id", "")[:15],
                row.get("timestamp", "")[:19],  # Remove microseconds
                row.get("severity", ""),
                row.get("event_type", "")[:15],
                row.get("agent_name", "")[:15],
                "Yes" if row.get("blocked") else "No"
            ])

        table = Table(table_data, colWidths=[1.2*inch, 1.3*inch, 0.8*inch, 1.2*inch, 1.2*inch, 0.7*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), BRAND_NAVY),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('ALIGN', (-1, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 7),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, GRAY_100])
        ]))
        elements.append(table)

        if len(data) > 100:
            elements.append(Spacer(1, 0.2*inch))
            elements.append(Paragraph(
                f"(Showing first 100 of {len(data)} incidents)",
                styles['Italic']
            ))

        return elements

    @staticmethod
    def _create_incident_detail_pdf_content(
        data: Dict[str, Any],
        styles: Any,
        heading_style: ParagraphStyle,
    ) -> List:
        """
        Enterprise-grade Incident Detail Report.

        Layout:
          1. Summary strip  — key counts at a glance
          2. Per-severity sections (Critical → High → Medium → Low → Info)
             - Colour-coded section header with count badge
             - Table with full alert fields, colour-coded rows
             - PageBreak between sections (except last)
          3. Truncation notice if capped at limit
        """
        # ── Colour palette ───────────────────────────────────────────────────────
        SEV_COLORS = {
            "critical": colors.HexColor("#7f1d1d"),   # deep red header
            "high":     colors.HexColor("#7c2d12"),   # deep orange header
            "medium":   colors.HexColor("#713f12"),   # amber header
            "low":      colors.HexColor("#1e3a5f"),   # navy header
            "info":     colors.HexColor("#1e3a5f"),
        }
        SEV_ROW_ODD = {
            "critical": colors.HexColor("#fee2e2"),
            "high":     colors.HexColor("#ffedd5"),
            "medium":   colors.HexColor("#fef9c3"),
            "low":      colors.HexColor("#f0f9ff"),
            "info":     colors.HexColor("#f0f9ff"),
        }
        SEV_ROW_EVEN = {
            "critical": colors.HexColor("#fecaca"),
            "high":     colors.HexColor("#fed7aa"),
            "medium":   colors.HexColor("#fef08a"),
            "low":      colors.HexColor("#e0f2fe"),
            "info":     colors.HexColor("#e0f2fe"),
        }
        ACTION_COLORS = {
            "blocked":     colors.HexColor("#dc2626"),
            "quarantined": colors.HexColor("#d97706"),
            "alerted":     colors.HexColor("#2563eb"),
            "allowed":     colors.HexColor("#16a34a"),
            "logged":      colors.HexColor("#6b7280"),
            "log":         colors.HexColor("#6b7280"),
        }

        # ── Small styles ─────────────────────────────────────────────────────────
        cell_style = ParagraphStyle(
            "cell", parent=styles["Normal"],
            fontSize=7, leading=9, spaceAfter=0,
        )
        small_bold = ParagraphStyle(
            "small_bold", parent=styles["Normal"],
            fontSize=7, leading=9, fontName="Helvetica-Bold",
        )
        section_label = ParagraphStyle(
            "section_label", parent=styles["Normal"],
            fontSize=11, fontName="Helvetica-Bold",
            textColor=colors.white, leading=14,
        )
        note_style = ParagraphStyle(
            "note", parent=styles["Normal"],
            fontSize=8, textColor=GRAY_700, leading=10,
        )

        elements: List = []

        # ── 1. Summary strip ─────────────────────────────────────────────────────
        summary = data.get("summary", {})
        total      = summary.get("total_incidents", 0)
        critical   = summary.get("critical_incidents", 0)
        blocked    = summary.get("blocked_incidents", 0)
        policy_v   = summary.get("policy_violations", 0)
        block_rate = summary.get("block_rate", 0)
        period     = summary.get("period", {})

        elements.append(Paragraph("Incident Detail Report", heading_style))
        elements.append(Spacer(1, 0.1 * inch))

        # Summary cards table
        summary_data = [[
            Paragraph(f"<b>{total}</b><br/>Total Incidents",   cell_style),
            Paragraph(f"<b>{critical}</b><br/>Critical",       cell_style),
            Paragraph(f"<b>{blocked}</b><br/>Blocked",         cell_style),
            Paragraph(f"<b>{policy_v}</b><br/>Policy Violations", cell_style),
            Paragraph(f"<b>{block_rate:.1f}%</b><br/>Block Rate",  cell_style),
        ]]
        summary_table = Table(summary_data, colWidths=[1.3*inch]*5)
        summary_table.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, -1), BRAND_NAVY),
            ("TEXTCOLOR",    (0, 0), (-1, -1), colors.white),
            ("ALIGN",        (0, 0), (-1, -1), "CENTER"),
            ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
            ("FONTSIZE",     (0, 0), (-1, -1), 9),
            ("TOPPADDING",   (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 8),
            ("LINEAFTER",    (0, 0), (-2, -1), 0.5, colors.HexColor("#3b5ea6")),
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 0.2 * inch))

        incidents = data.get("incidents", [])
        truncated = data.get("truncated", False)
        total_in_range = data.get("total_in_range", total)

        if not incidents:
            elements.append(Paragraph(
                "No incidents found for the selected period.", styles["Normal"]
            ))
            return elements

        # ── 2. Group by severity ─────────────────────────────────────────────────
        SEV_ORDER = ["critical", "high", "medium", "low", "info"]
        grouped: Dict[str, list] = {s: [] for s in SEV_ORDER}
        for inc in incidents:
            sev = (inc.get("severity") or "info").lower()
            grouped.setdefault(sev, []).append(inc)

        # Column headers and widths (landscape-ish on A4/letter)
        # Total usable width ≈ 7.5 inch (letter with 0.5" margins each side)
        COL_HEADERS = [
            "Timestamp", "Sev", "Event Type", "File / Path",
            "Detected Data", "Class. Level", "Conf %",
            "Action", "User / Agent", "Policy",
        ]
        COL_WIDTHS = [
            1.05*inch,  # Timestamp
            0.45*inch,  # Sev
            0.80*inch,  # Event Type
            1.30*inch,  # File / Path
            0.90*inch,  # Detected Data
            0.65*inch,  # Classification Level
            0.45*inch,  # Confidence %
            0.60*inch,  # Action
            0.90*inch,  # User / Agent
            0.90*inch,  # Policy
        ]

        non_empty_sevs = [s for s in SEV_ORDER if grouped.get(s)]

        for idx, sev in enumerate(SEV_ORDER):
            rows = grouped.get(sev, [])
            if not rows:
                continue

            # Section header bar
            hdr_color = SEV_COLORS.get(sev, BRAND_NAVY)
            sev_label = sev.upper()
            sev_hdr = Table(
                [[Paragraph(
                    f"● {sev_label}  —  {len(rows)} Incident{'s' if len(rows) != 1 else ''}",
                    section_label
                )]],
                colWidths=[sum(COL_WIDTHS)]
            )
            sev_hdr.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), hdr_color),
                ("TOPPADDING",    (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ("LEFTPADDING",   (0, 0), (-1, -1), 10),
            ]))
            elements.append(KeepTogether([sev_hdr, Spacer(1, 0.05*inch)]))

            # Build table rows
            odd_bg  = SEV_ROW_ODD.get(sev,  colors.white)
            even_bg = SEV_ROW_EVEN.get(sev, GRAY_100)

            table_data = [COL_HEADERS]
            row_styles: List = []

            for r_idx, inc in enumerate(rows, start=1):
                # Timestamp — strip microseconds
                ts_raw = inc.get("timestamp", "")
                ts = ts_raw[:19].replace("T", " ") if ts_raw else "—"

                # File display: filename bold + path smaller below
                fname = inc.get("file_name", "") or ""
                fpath = inc.get("file_path", "") or ""
                if fname and fpath and fname not in fpath:
                    file_cell = Paragraph(
                        f"<b>{fname[:28]}</b><br/><font size='6'>{fpath[:40]}</font>",
                        cell_style
                    )
                elif fname:
                    file_cell = Paragraph(f"<b>{fname[:35]}</b>", cell_style)
                elif fpath:
                    file_cell = Paragraph(f"<font size='6'>{fpath[:40]}</font>", cell_style)
                else:
                    file_cell = Paragraph("—", cell_style)

                # Action with colour tag
                action     = (inc.get("action") or "logged").lower()
                _act_hex_map = {
                    "blocked":     "#dc2626",
                    "quarantined": "#d97706",
                    "alerted":     "#2563eb",
                    "allowed":     "#16a34a",
                    "logged":      "#6b7280",
                    "log":         "#6b7280",
                }
                act_hex = _act_hex_map.get(action, "#6b7280")
                action_cell = Paragraph(
                    f"<font color='{act_hex}'><b>{action.upper()}</b></font>",
                    cell_style,
                )

                # Confidence
                conf = inc.get("confidence_score")
                conf_cell = Paragraph(
                    f"{conf:.0f}%" if conf is not None else "—", cell_style
                )

                # User/Agent
                user = inc.get("username") or inc.get("user_email") or inc.get("agent_id") or "—"

                table_data.append([
                    Paragraph(ts, cell_style),
                    Paragraph(sev[:4].upper(), small_bold),
                    Paragraph((inc.get("event_type") or "—")[:20], cell_style),
                    file_cell,
                    Paragraph((inc.get("detected_data") or "—")[:30], cell_style),
                    Paragraph((inc.get("classification_level") or "—")[:15], cell_style),
                    conf_cell,
                    action_cell,
                    Paragraph(str(user)[:25], cell_style),
                    Paragraph((inc.get("policy_name") or "—")[:30], cell_style),
                ])

                bg = odd_bg if r_idx % 2 == 1 else even_bg
                row_styles.append(("BACKGROUND", (0, r_idx), (-1, r_idx), bg))

            tbl = Table(table_data, colWidths=COL_WIDTHS, repeatRows=1)
            base_style = [
                ("BACKGROUND",    (0, 0), (-1, 0), hdr_color),
                ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
                ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE",      (0, 0), (-1, 0), 7),
                ("FONTSIZE",      (0, 1), (-1, -1), 7),
                ("ALIGN",         (0, 0), (-1, -1), "LEFT"),
                ("VALIGN",        (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING",    (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING",   (0, 0), (-1, -1), 3),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 3),
                ("GRID",          (0, 0), (-1, -1), 0.3, colors.HexColor("#d1d5db")),
                ("LINEBELOW",     (0, 0), (-1, 0), 1, colors.white),
            ] + row_styles
            tbl.setStyle(TableStyle(base_style))
            elements.append(tbl)
            elements.append(Spacer(1, 0.15 * inch))

            # Page break between severity sections (not after the last one)
            if sev != non_empty_sevs[-1]:
                elements.append(PageBreak())

        # ── 3. Truncation notice ─────────────────────────────────────────────────
        if truncated:
            elements.append(Spacer(1, 0.15 * inch))
            elements.append(HRFlowable(width="100%", thickness=0.5, color=GRAY_700))
            elements.append(Spacer(1, 0.05 * inch))
            elements.append(Paragraph(
                f"⚠  This PDF shows the first 500 incidents of {total_in_range:,} total "
                f"in the selected period. Download the CSV export for the complete dataset.",
                note_style,
            ))

        return elements
