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
    Spacer, PageBreak, Image
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

from app.core.observability import StructuredLogger

logger = StructuredLogger(__name__)


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

        else:
            # Generic export
            return ExportService.export_to_csv(analytics_data)

    @staticmethod
    def export_to_pdf(
        title: str,
        data: Dict[str, Any],
        report_type: str,
        logo_path: Optional[str] = None
    ) -> bytes:
        """
        Export data to PDF format

        Args:
            title: Report title
            data: Data to export
            report_type: Type of report
            logo_path: Optional path to company logo

        Returns:
            PDF bytes
        """
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter,
                               rightMargin=0.75*inch, leftMargin=0.75*inch,
                               topMargin=1*inch, bottomMargin=0.75*inch)

        # Container for PDF elements
        elements = []

        # Styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1e3a8a'),
            spaceAfter=30,
            alignment=TA_CENTER
        )
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#1e40af'),
            spaceAfter=12
        )

        # Add logo if provided
        if logo_path:
            try:
                logo = Image(logo_path, width=2*inch, height=1*inch)
                elements.append(logo)
                elements.append(Spacer(1, 0.3*inch))
            except:
                pass  # Skip logo if file not found

        # Add title
        elements.append(Paragraph(title, title_style))
        elements.append(Spacer(1, 0.2*inch))

        # Add generation timestamp
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        elements.append(Paragraph(f"Generated: {timestamp}", styles['Normal']))
        elements.append(Spacer(1, 0.3*inch))

        # Add content based on report type
        if report_type == "summary":
            elements.extend(ExportService._create_summary_pdf_content(data, styles, heading_style))

        elif report_type == "trends":
            elements.extend(ExportService._create_trends_pdf_content(data, styles, heading_style))

        elif report_type == "violators":
            elements.extend(ExportService._create_violators_pdf_content(data, styles, heading_style))

        elif report_type == "data_types":
            elements.extend(ExportService._create_data_types_pdf_content(data, styles, heading_style))

        elif report_type == "policy_violations":
            elements.extend(ExportService._create_policy_violations_pdf_content(data, styles, heading_style))

        elif report_type == "incidents":
            elements.extend(ExportService._create_incidents_pdf_content(data, styles, heading_style))

        # Build PDF
        doc.build(elements)
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
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e3a8a')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f3f4f6')])
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
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e3a8a')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f3f4f6')])
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
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e3a8a')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f3f4f6')])
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
            table_data = [["Agent ID", "Name", "Hostname", "Incidents", "Critical"]]
            for row in data:
                table_data.append([
                    row.get("agent_id", ""),
                    row.get("agent_name", ""),
                    row.get("hostname", ""),
                    row.get("incident_count", 0),
                    row.get("critical_count", 0)
                ])
            col_widths = [1.2*inch, 1.5*inch, 1.8*inch, 0.8*inch, 0.7*inch]

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
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#dc2626')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('ALIGN', (-2, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#fee2e2')])
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
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e3a8a')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f3f4f6')])
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
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e3a8a')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (1, -1), 'LEFT'),
            ('ALIGN', (2, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f3f4f6')])
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
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e3a8a')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('ALIGN', (-1, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 7),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f3f4f6')])
        ]))
        elements.append(table)

        if len(data) > 100:
            elements.append(Spacer(1, 0.2*inch))
            elements.append(Paragraph(
                f"(Showing first 100 of {len(data)} incidents)",
                styles['Italic']
            ))

        return elements
