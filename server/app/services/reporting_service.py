"""
Scheduled Reporting Service
Handles automated report generation and delivery
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
import smtplib
from pathlib import Path

from app.services.analytics_service import AnalyticsService
from app.services.export_service import ExportService
from app.core.config import settings
from app.core.observability import StructuredLogger

logger = StructuredLogger(__name__)


class ReportSchedule:
    """Report schedule configuration"""

    def __init__(
        self,
        name: str,
        frequency: str,  # daily, weekly, monthly
        report_types: List[str],  # summary, trends, violators, etc.
        recipients: List[str],
        formats: List[str] = ["pdf"],  # pdf, csv
        enabled: bool = True
    ):
        self.name = name
        self.frequency = frequency
        self.report_types = report_types
        self.recipients = recipients
        self.formats = formats
        self.enabled = enabled


class ReportingService:
    """Service for scheduled report generation and delivery"""

    def __init__(self, db_session=None, opensearch=None):
        self.db = db_session
        self.opensearch = opensearch
        self.analytics = AnalyticsService(db_session, opensearch) if db_session else None
        self.export = ExportService()

    async def generate_scheduled_report(
        self,
        schedule: ReportSchedule,
        start_date: datetime,
        end_date: datetime
    ) -> Dict[str, Any]:
        """
        Generate a scheduled report

        Args:
            schedule: Report schedule configuration
            start_date: Start of reporting period
            end_date: End of reporting period

        Returns:
            Dictionary with report generation results
        """
        try:
            logger.logger.info("generating_scheduled_report",
                              report_name=schedule.name,
                              frequency=schedule.frequency,
                              start_date=start_date.isoformat(),
                              end_date=end_date.isoformat())

            reports = []

            # Generate each requested report type
            for report_type in schedule.report_types:
                if report_type == "summary":
                    data = await self.analytics.get_summary_statistics(start_date, end_date)
                    reports.append({
                        "type": "summary",
                        "data": data
                    })

                elif report_type == "trends":
                    # Determine interval based on frequency
                    interval = self._get_interval_for_frequency(schedule.frequency)
                    data = await self.analytics.get_incident_trends(
                        start_date, end_date, interval, group_by="severity"
                    )
                    reports.append({
                        "type": "trends",
                        "data": data
                    })

                elif report_type == "violators":
                    data = await self.analytics.get_top_violators(
                        start_date, end_date, limit=20, by="agent"
                    )
                    reports.append({
                        "type": "violators",
                        "data": data
                    })

                elif report_type == "data_types":
                    data = await self.analytics.get_data_type_statistics(start_date, end_date)
                    reports.append({
                        "type": "data_types",
                        "data": data
                    })

                elif report_type == "policy_violations":
                    data = await self.analytics.get_policy_violation_breakdown(
                        start_date, end_date
                    )
                    reports.append({
                        "type": "policy_violations",
                        "data": data
                    })

            # Generate files in requested formats
            attachments = []

            for report in reports:
                report_type = report["type"]
                data = report["data"]

                if "pdf" in schedule.formats:
                    title = self._get_report_title(report_type, schedule.frequency)
                    pdf_bytes = self.export.export_to_pdf(title, data, report_type)
                    filename = f"{report_type}_{start_date.strftime('%Y%m%d')}.pdf"
                    attachments.append({
                        "filename": filename,
                        "content": pdf_bytes,
                        "content_type": "application/pdf"
                    })

                if "csv" in schedule.formats and report_type != "summary":
                    csv_content = self.export.export_analytics_to_csv(data, report_type)
                    filename = f"{report_type}_{start_date.strftime('%Y%m%d')}.csv"
                    attachments.append({
                        "filename": filename,
                        "content": csv_content.encode('utf-8'),
                        "content_type": "text/csv"
                    })

            # Send email with attachments
            email_sent = await self._send_report_email(
                schedule=schedule,
                attachments=attachments,
                start_date=start_date,
                end_date=end_date,
                summary=reports[0]["data"] if reports and reports[0]["type"] == "summary" else None
            )

            logger.logger.info("scheduled_report_generated",
                              report_name=schedule.name,
                              attachments_count=len(attachments),
                              email_sent=email_sent)

            return {
                "success": True,
                "report_name": schedule.name,
                "reports_generated": len(reports),
                "attachments": len(attachments),
                "email_sent": email_sent,
                "recipients": schedule.recipients
            }

        except Exception as e:
            logger.log_error(e, {
                "operation": "generate_scheduled_report",
                "report_name": schedule.name
            })
            return {
                "success": False,
                "error": str(e)
            }

    async def _send_report_email(
        self,
        schedule: ReportSchedule,
        attachments: List[Dict[str, Any]],
        start_date: datetime,
        end_date: datetime,
        summary: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Send report via email"""
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = settings.SMTP_FROM_EMAIL
            msg['To'] = ', '.join(schedule.recipients)
            msg['Subject'] = self._get_email_subject(schedule, start_date, end_date)

            # Create email body
            body = self._create_email_body(schedule, start_date, end_date, summary)
            msg.attach(MIMEText(body, 'html'))

            # Attach files
            for attachment in attachments:
                part = MIMEApplication(attachment["content"], Name=attachment["filename"])
                part['Content-Disposition'] = f'attachment; filename="{attachment["filename"]}"'
                msg.attach(part)

            # Send email
            with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
                if settings.SMTP_TLS:
                    server.starttls()
                if settings.SMTP_USER and settings.SMTP_PASSWORD:
                    server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
                server.send_message(msg)

            logger.logger.info("report_email_sent",
                              recipients=schedule.recipients,
                              attachments=len(attachments))

            return True

        except Exception as e:
            logger.log_error(e, {"operation": "send_report_email"})
            return False

    def _get_interval_for_frequency(self, frequency: str) -> str:
        """Get time interval based on report frequency"""
        if frequency == "daily":
            return "hour"
        elif frequency == "weekly":
            return "day"
        elif frequency == "monthly":
            return "day"
        else:
            return "day"

    def _get_report_title(self, report_type: str, frequency: str) -> str:
        """Get report title"""
        type_titles = {
            "summary": "DLP Summary Report",
            "trends": "Incident Trends Report",
            "violators": "Top Violators Report",
            "data_types": "Data Type Statistics",
            "policy_violations": "Policy Violations Report"
        }

        title = type_titles.get(report_type, "DLP Report")
        return f"{frequency.capitalize()} {title}"

    def _get_email_subject(
        self,
        schedule: ReportSchedule,
        start_date: datetime,
        end_date: datetime
    ) -> str:
        """Generate email subject line"""
        return (
            f"DLP {schedule.frequency.capitalize()} Report: "
            f"{schedule.name} ({start_date.strftime('%Y-%m-%d')} - {end_date.strftime('%Y-%m-%d')})"
        )

    def _create_email_body(
        self,
        schedule: ReportSchedule,
        start_date: datetime,
        end_date: datetime,
        summary: Optional[Dict[str, Any]] = None
    ) -> str:
        """Create HTML email body"""

        summary_html = ""
        if summary:
            summary_html = f"""
            <h3>Summary Statistics</h3>
            <table style="border-collapse: collapse; width: 100%; margin-bottom: 20px;">
                <tr style="background-color: #f3f4f6;">
                    <td style="padding: 10px; border: 1px solid #ddd;"><strong>Total Incidents</strong></td>
                    <td style="padding: 10px; border: 1px solid #ddd;">{summary.get('total_incidents', 0):,}</td>
                </tr>
                <tr>
                    <td style="padding: 10px; border: 1px solid #ddd;"><strong>Critical Incidents</strong></td>
                    <td style="padding: 10px; border: 1px solid #ddd;">{summary.get('critical_incidents', 0):,}</td>
                </tr>
                <tr style="background-color: #f3f4f6;">
                    <td style="padding: 10px; border: 1px solid #ddd;"><strong>Blocked Incidents</strong></td>
                    <td style="padding: 10px; border: 1px solid #ddd;">{summary.get('blocked_incidents', 0):,}</td>
                </tr>
                <tr>
                    <td style="padding: 10px; border: 1px solid #ddd;"><strong>Block Rate</strong></td>
                    <td style="padding: 10px; border: 1px solid #ddd;">{summary.get('block_rate', 0):.2f}%</td>
                </tr>
                <tr style="background-color: #f3f4f6;">
                    <td style="padding: 10px; border: 1px solid #ddd;"><strong>Active Agents</strong></td>
                    <td style="padding: 10px; border: 1px solid #ddd;">{summary.get('active_agents', 0):,}</td>
                </tr>
                <tr>
                    <td style="padding: 10px; border: 1px solid #ddd;"><strong>Policy Violations</strong></td>
                    <td style="padding: 10px; border: 1px solid #ddd;">{summary.get('policy_violations', 0):,}</td>
                </tr>
            </table>
            """

        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .header {{ background-color: #1e3a8a; color: white; padding: 20px; text-align: center; }}
                .content {{ padding: 20px; }}
                .footer {{ background-color: #f3f4f6; padding: 15px; text-align: center; font-size: 12px; color: #666; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>SeceoKnight DLP</h1>
                <h2>{schedule.frequency.capitalize()} Report: {schedule.name}</h2>
            </div>

            <div class="content">
                <p><strong>Report Period:</strong> {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}</p>
                <p><strong>Generated:</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>

                {summary_html}

                <h3>Attached Reports</h3>
                <p>The following reports are attached to this email:</p>
                <ul>
                    {''.join([f'<li>{report_type.replace("_", " ").title()}</li>' for report_type in schedule.report_types])}
                </ul>

                <p>Please review the attached files for detailed analysis and metrics.</p>

                <p style="margin-top: 30px;">
                    <strong>Need help?</strong> Contact your DLP administrator or visit the
                    <a href="https://dlp.example.com">DLP Dashboard</a> for more information.
                </p>
            </div>

            <div class="footer">
                <p>This is an automated report from SeceoKnight DLP. Please do not reply to this email.</p>
                <p>&copy; {datetime.utcnow().year} SeceoKnight. All rights reserved.</p>
            </div>
        </body>
        </html>
        """

        return html


# Predefined report schedules
DEFAULT_SCHEDULES = [
    ReportSchedule(
        name="Daily Executive Summary",
        frequency="daily",
        report_types=["summary", "trends"],
        recipients=["security@company.com", "ciso@company.com"],
        formats=["pdf"],
        enabled=True
    ),
    ReportSchedule(
        name="Weekly Security Report",
        frequency="weekly",
        report_types=["summary", "trends", "violators", "policy_violations"],
        recipients=["security-team@company.com"],
        formats=["pdf", "csv"],
        enabled=True
    ),
    ReportSchedule(
        name="Monthly Compliance Report",
        frequency="monthly",
        report_types=["summary", "trends", "policy_violations", "data_types"],
        recipients=["compliance@company.com", "audit@company.com"],
        formats=["pdf"],
        enabled=True
    )
]
