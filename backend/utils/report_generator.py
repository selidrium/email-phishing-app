import os
import csv
import logging
import re
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class ReportGenerator:
    def __init__(self, output_dir='reports'):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        logger.info(f'ReportGenerator initialized with output directory: {output_dir}')

    def sanitize_text(self, text):
        """Remove HTML tags and clean text for PDF generation"""
        if not isinstance(text, str):
            return str(text)
        # Remove HTML tags
        text = re.sub(r'<[^>]+>', '', text)
        # Replace HTML entities
        text = text.replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&')
        # Remove any remaining special characters that might cause issues
        text = re.sub(r'[^\x00-\x7F]+', '', text)
        return text.strip()

    def generate_pdf(self, analysis_data, filename=None):
        """Generate PDF report from analysis data"""
        temp_file = None
        try:
            logger.info('Starting PDF generation')
            if not filename:
                filename = f"analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            
            filepath = os.path.join(self.output_dir, filename)
            logger.info(f'Will save PDF to: {filepath}')
            
            # Validate required data
            if not isinstance(analysis_data, dict):
                raise ValueError("Analysis data must be a dictionary")
            
            required_fields = ['subject', 'from', 'to', 'risk_assessment']
            missing_fields = [field for field in required_fields if field not in analysis_data]
            if missing_fields:
                raise ValueError(f"Missing required fields: {', '.join(missing_fields)}")
            
            # Create a temporary file first
            temp_file = filepath + '.tmp'
            doc = SimpleDocTemplate(temp_file, pagesize=letter)
            styles = getSampleStyleSheet()
            story = []

            # Title
            logger.info('Adding title to PDF')
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                spaceAfter=30
            )
            story.append(Paragraph("Email Analysis Report", title_style))
            story.append(Spacer(1, 12))

            # Basic Information
            logger.info('Adding basic information to PDF')
            story.append(Paragraph("Basic Information", styles['Heading2']))
            basic_info = [
                ["Subject:", self.sanitize_text(analysis_data.get('subject', 'N/A'))],
                ["From:", self.sanitize_text(analysis_data.get('from', 'N/A'))],
                ["To:", self.sanitize_text(analysis_data.get('to', 'N/A'))]
            ]
            t = Table(basic_info, colWidths=[100, 400])
            t.setStyle(TableStyle([
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('BACKGROUND', (0, 0), (0, -1), colors.grey),
                ('TEXTCOLOR', (0, 0), (0, -1), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 12),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('TOPPADDING', (0, 0), (-1, -1), 12),
            ]))
            story.append(t)
            story.append(Spacer(1, 20))

            # Risk Assessment
            logger.info('Adding risk assessment to PDF')
            story.append(Paragraph("Risk Assessment", styles['Heading2']))
            ra = analysis_data.get('risk_assessment', {})
            risk_score = ra.get('score', 0)
            risk_level = ra.get('level', 'low')
            risk_factors = ra.get('factors', [])
            risk_text = f"Risk Score: {risk_score}/100"
            story.append(Paragraph(risk_text, styles['Normal']))
            story.append(Paragraph(f"Risk Level: {risk_level.upper()}", styles['Normal']))
            if risk_factors:
                story.append(Paragraph("Risk Factors:", styles['Normal']))
                for factor in risk_factors:
                    story.append(Paragraph(f"- {self.sanitize_text(factor)}", styles['Normal']))
            else:
                story.append(Paragraph("No risk factors identified.", styles['Normal']))
            story.append(Spacer(1, 20))

            # Authentication Results
            logger.info('Adding authentication results to PDF')
            story.append(Paragraph("Authentication Results", styles['Heading2']))
            spf = analysis_data.get('spf', {}).get('result', 'unknown')
            dkim = analysis_data.get('dkim', {}).get('result', False)
            dmarc = analysis_data.get('dmarc', {}).get('result', 'unknown')
            auth_table = [
                ["SPF", self.sanitize_text(spf)],
                ["DKIM", 'Pass' if dkim else 'Fail'],
                ["DMARC", self.sanitize_text(dmarc)]
            ]
            t = Table(auth_table, colWidths=[100, 200])
            t.setStyle(TableStyle([
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('BACKGROUND', (0, 0), (0, -1), colors.grey),
                ('TEXTCOLOR', (0, 0), (0, -1), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 12),
            ]))
            story.append(t)
            story.append(Spacer(1, 20))

            # Threat Intelligence
            story.append(Paragraph("Threat Intelligence", styles['Heading2']))
            threat_data = analysis_data.get('threat_intelligence', {}).get('threat_data', {})
            if not threat_data or len(threat_data) == 0:
                story.append(Paragraph("No threat intelligence data available.", styles['Normal']))
            else:
                ti_table = [["IP Address", "Abuse Score", "Country", "ISP", "Hostnames", "Last Reported"]]
                for ip, data in threat_data.items():
                    row = [
                        self.sanitize_text(ip),
                        self.sanitize_text(data.get('data', {}).get('abuseConfidenceScore', 'N/A')),
                        self.sanitize_text(data.get('data', {}).get('countryCode', 'N/A')),
                        self.sanitize_text(data.get('data', {}).get('isp', 'N/A')),
                        self.sanitize_text(', '.join(data.get('data', {}).get('hostnames', [])) if data.get('data', {}).get('hostnames') else 'N/A'),
                        self.sanitize_text(data.get('data', {}).get('lastReportedAt', 'N/A'))
                    ]
                    ti_table.append(row)
                t = Table(ti_table, colWidths=[80, 60, 60, 80, 100, 80])
                t.setStyle(TableStyle([
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                ]))
                story.append(t)
            story.append(Spacer(1, 20))

            # Server Hops
            story.append(Paragraph("Server Hops", styles['Heading2']))
            server_hops = analysis_data.get('server_hops', [])
            if not server_hops:
                story.append(Paragraph("No server hop information available.", styles['Normal']))
            else:
                hops_data = [["Header", "IP Addresses"]]
                for hop in server_hops:
                    hops_data.append([
                        self.sanitize_text(hop.get('header', 'N/A')),
                        self.sanitize_text(', '.join(hop.get('ip_addresses', [])) if hop.get('ip_addresses') else 'N/A')
                    ])
                t = Table(hops_data, colWidths=[300, 200])
                t.setStyle(TableStyle([
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                ]))
                story.append(t)
            story.append(Spacer(1, 20))

            # Attachments Section
            attachments = analysis_data.get('attachments', {}).get('attachments', [])
            cell_style = ParagraphStyle('cell', fontName='Helvetica', fontSize=8, leading=10, wordWrap='CJK')
            attach_data = [
                ["Filename", "Type", "Size", "Hash", "VirusTotal Status", "Detection Count"]
            ]
            if attachments:
                for att in attachments:
                    vt = att.get('virustotal', {}) or {}
                    vt_status = vt.get('verbose_msg', 'Not scanned')
                    vt_count = f"{vt.get('positives', 0)}/{vt.get('total', 0)}" if vt else 'N/A'
                    attach_data.append([
                        Paragraph(self.sanitize_text(att.get('filename', 'N/A')), cell_style),
                        Paragraph(self.sanitize_text(att.get('content_type', 'N/A')), cell_style),
                        self.sanitize_text(att.get('size', 'N/A') if att.get('size') else 'N/A'),
                        Paragraph(self.sanitize_text(att.get('hash', 'N/A')), cell_style),
                        Paragraph(self.sanitize_text(vt_status), cell_style),
                        self.sanitize_text(vt_count)
                    ])
            else:
                attach_data.append(["N/A"] * 6)
            t = Table(attach_data, colWidths=[140, 90, 50, 140, 140, 60])
            t.setStyle(TableStyle([
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
            ]))
            story.append(t)
            story.append(Spacer(1, 20))

            # Suspicious HTML Elements
            story.append(Paragraph("Suspicious HTML Elements", styles['Heading2']))
            suspicious_elements = analysis_data.get('html_content', {}).get('suspicious_elements', [])
            if not suspicious_elements:
                story.append(Paragraph("No suspicious HTML elements found.", styles['Normal']))
            else:
                html_table = [["Type", "Details"]]
                for el in suspicious_elements:
                    if isinstance(el, dict):
                        el_type = self.sanitize_text(el.get('type', 'Unknown'))
                        el_details = self.sanitize_text(el.get('content', el.get('href', 'N/A')))
                    else:
                        el_type = 'Unknown'
                        el_details = self.sanitize_text(str(el))
                    html_table.append([el_type, el_details])
                
                t = Table(html_table, colWidths=[100, 400])
                t.setStyle(TableStyle([
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                ]))
                story.append(t)
            story.append(Spacer(1, 20))

            # Suspicious Language Patterns
            story.append(Paragraph("Suspicious Language Patterns", styles['Heading2']))
            suspicious_patterns = analysis_data.get('language', {}).get('suspicious_patterns', [])
            if not suspicious_patterns:
                story.append(Paragraph("No suspicious language patterns found.", styles['Normal']))
            else:
                pattern_table = [["Pattern", "Context"]]
                for pat in suspicious_patterns:
                    if isinstance(pat, dict):
                        pattern = self.sanitize_text(pat.get('pattern', 'Unknown'))
                        context = self.sanitize_text(pat.get('context', 'N/A'))
                    else:
                        pattern = self.sanitize_text(str(pat))
                        context = 'N/A'
                    pattern_table.append([pattern, context])
                
                t = Table(pattern_table, colWidths=[200, 300])
                t.setStyle(TableStyle([
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                ]))
                story.append(t)
            story.append(Spacer(1, 20))

            # Build PDF
            logger.info('Building PDF document')
            doc.build(story)
            
            # Move temp file to final location
            os.replace(temp_file, filepath)
            temp_file = None
            
            logger.info(f'PDF generation completed successfully: {filepath}')
            return filepath
            
        except Exception as e:
            logger.error(f'Error generating PDF: {str(e)}', exc_info=True)
            # Clean up temp file if it exists
            if temp_file and os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                except Exception as cleanup_error:
                    logger.error(f'Error cleaning up temp file: {str(cleanup_error)}')
            raise

    def generate_csv(self, analysis_data, filename=None):
        """Generate CSV report from analysis data"""
        temp_file = None
        try:
            logger.info('Starting CSV generation')
            if not filename:
                filename = f"analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            
            filepath = os.path.join(self.output_dir, filename)
            logger.info(f'Will save CSV to: {filepath}')
            
            # Validate required data
            if not isinstance(analysis_data, dict):
                raise ValueError("Analysis data must be a dictionary")
            
            required_fields = ['subject', 'from', 'to', 'risk_assessment']
            missing_fields = [field for field in required_fields if field not in analysis_data]
            if missing_fields:
                raise ValueError(f"Missing required fields: {', '.join(missing_fields)}")
            
            # Create a temporary file first
            temp_file = filepath + '.tmp'
            with open(temp_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                
                # Basic Information
                writer.writerow(['Basic Information'])
                writer.writerow(['Subject', analysis_data.get('subject', 'N/A')])
                writer.writerow(['From', analysis_data.get('from', 'N/A')])
                writer.writerow(['To', analysis_data.get('to', 'N/A')])
                writer.writerow([])
                
                # Risk Assessment
                writer.writerow(['Risk Assessment'])
                ra = analysis_data.get('risk_assessment', {})
                writer.writerow(['Risk Score', ra.get('score', 'N/A')])
                writer.writerow(['Risk Level', ra.get('level', 'N/A')])
                if ra.get('factors'):
                    writer.writerow(['Risk Factors'])
                    for factor in ra['factors']:
                        writer.writerow(['', factor])
                writer.writerow([])
                
                # Authentication Results
                writer.writerow(['Authentication Results'])
                writer.writerow(['SPF', analysis_data.get('spf', {}).get('result', 'N/A')])
                writer.writerow(['DKIM', analysis_data.get('dkim', {}).get('result', 'N/A')])
                writer.writerow(['DMARC', analysis_data.get('dmarc', {}).get('result', 'N/A')])
                writer.writerow([])
                
                # Threat Intelligence
                writer.writerow(['Threat Intelligence'])
                threat_data = analysis_data.get('threat_intelligence', {}).get('threat_data', {})
                if threat_data:
                    writer.writerow(['IP Address', 'Abuse Score', 'Country', 'ISP', 'Hostnames', 'Last Reported'])
                    for ip, data in threat_data.items():
                        writer.writerow([
                            ip,
                            data.get('data', {}).get('abuseConfidenceScore', 'N/A'),
                            data.get('data', {}).get('countryCode', 'N/A'),
                            data.get('data', {}).get('isp', 'N/A'),
                            ', '.join(data.get('data', {}).get('hostnames', [])) if data.get('data', {}).get('hostnames') else 'N/A',
                            data.get('data', {}).get('lastReportedAt', 'N/A')
                        ])
                else:
                    writer.writerow(['No threat intelligence data available'])
                writer.writerow([])
                
                # Server Hops
                writer.writerow(['Server Hops'])
                server_hops = analysis_data.get('server_hops', [])
                if server_hops:
                    writer.writerow(['Header', 'IP Addresses'])
                    for hop in server_hops:
                        writer.writerow([
                            hop.get('header', 'N/A'),
                            ', '.join(hop.get('ip_addresses', [])) if hop.get('ip_addresses') else 'N/A'
                        ])
                else:
                    writer.writerow(['No server hop information available'])
                writer.writerow([])
                
                # Attachments
                writer.writerow(['Attachments'])
                attachments = analysis_data.get('attachments', {}).get('attachments', [])
                if attachments:
                    writer.writerow(['Filename', 'Type', 'Size', 'Hash', 'VirusTotal Status', 'Detection Count'])
                    for att in attachments:
                        vt = att.get('virustotal', {}) or {}
                        writer.writerow([
                            att.get('filename', 'N/A'),
                            att.get('content_type', 'N/A'),
                            att.get('size', 'N/A'),
                            att.get('hash', 'N/A'),
                            vt.get('verbose_msg', 'Not scanned'),
                            f"{vt.get('positives', 0)}/{vt.get('total', 0)}" if vt else 'N/A'
                        ])
                else:
                    writer.writerow(['No attachments found'])
                writer.writerow([])
                
                # Suspicious HTML Elements
                writer.writerow(['Suspicious HTML Elements'])
                suspicious_elements = analysis_data.get('html_content', {}).get('suspicious_elements', [])
                if suspicious_elements:
                    for el in suspicious_elements:
                        writer.writerow([str(el)])
                else:
                    writer.writerow(['No suspicious HTML elements found'])
                writer.writerow([])
                
                # Suspicious Language Patterns
                writer.writerow(['Suspicious Language Patterns'])
                suspicious_patterns = analysis_data.get('language', {}).get('suspicious_patterns', [])
                if suspicious_patterns:
                    for pat in suspicious_patterns:
                        writer.writerow([str(pat)])
                else:
                    writer.writerow(['No suspicious language patterns found'])
            
            # Move temp file to final location
            os.replace(temp_file, filepath)
            temp_file = None
            
            logger.info(f'CSV generation completed successfully: {filepath}')
            return filepath
            
        except Exception as e:
            logger.error(f'Error generating CSV: {str(e)}', exc_info=True)
            # Clean up temp file if it exists
            if temp_file and os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                except Exception as cleanup_error:
                    logger.error(f'Error cleaning up temp file: {str(cleanup_error)}')
            raise 