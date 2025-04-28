import os
import csv
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

class ReportGenerator:
    def __init__(self, output_dir='reports'):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate_pdf(self, analysis_data, filename=None):
        """Generate PDF report from analysis data"""
        if not filename:
            filename = f"analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        
        filepath = os.path.join(self.output_dir, filename)
        doc = SimpleDocTemplate(filepath, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []

        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30
        )
        story.append(Paragraph("Email Analysis Report", title_style))
        story.append(Spacer(1, 12))

        # Basic Information
        story.append(Paragraph("Basic Information", styles['Heading2']))
        basic_info = [
            ["Subject:", analysis_data.get('subject', 'N/A')],
            ["From:", analysis_data.get('from', 'N/A')],
            ["To:", analysis_data.get('to', 'N/A')]
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
        story.append(Paragraph("Risk Assessment", styles['Heading2']))
        ra = analysis_data.get('risk_assessment', {})
        risk_score = ra.get('score') if ra else analysis_data.get('risk_score', 'N/A')
        risk_level = ra.get('level', 'N/A') if ra else 'N/A'
        risk_factors = ra.get('factors', []) if ra else []
        risk_text = f"Risk Score: {risk_score}/100"
        story.append(Paragraph(risk_text, styles['Normal']))
        if risk_factors:
            story.append(Paragraph("Risk Factors:", styles['Normal']))
            for factor in risk_factors:
                story.append(Paragraph(f"- {factor}", styles['Normal']))
        else:
            story.append(Paragraph("No risk factors identified.", styles['Normal']))
        story.append(Spacer(1, 20))

        # Authentication Results
        story.append(Paragraph("Authentication Results", styles['Heading2']))
        spf = analysis_data.get('spf', {}).get('result', 'N/A')
        dkim = analysis_data.get('dkim', {}).get('result', 'N/A')
        dmarc = analysis_data.get('dmarc', {}).get('result', 'N/A')
        auth_table = [["SPF", spf], ["DKIM", 'Pass' if dkim == 'pass' else 'Fail' if dkim == 'fail' else dkim], ["DMARC", dmarc]]
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
                    ip,
                    data.get('data', {}).get('abuseConfidenceScore', 'N/A'),
                    data.get('data', {}).get('countryCode', 'N/A'),
                    data.get('data', {}).get('isp', 'N/A'),
                    ', '.join(data.get('data', {}).get('hostnames', [])) if data.get('data', {}).get('hostnames') else 'N/A',
                    data.get('data', {}).get('lastReportedAt', 'N/A')
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
                    hop.get('header', 'N/A'),
                    ', '.join(hop.get('ip_addresses', [])) if hop.get('ip_addresses') else 'N/A'
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
            ["Filename", "Type", "Size", "Hash (truncated)", "VirusTotal Status", "Detection Count"]
        ]
        if attachments:
            for att in attachments:
                vt = att.get('virustotal', {}) or {}
                vt_status = vt.get('verbose_msg', 'Not scanned')
                vt_count = f"{vt.get('positives', 0)}/{vt.get('total', 0)}" if vt else 'N/A'
                attach_data.append([
                    Paragraph(att.get('filename', 'N/A'), cell_style),
                    Paragraph(att.get('content_type', 'N/A'), cell_style),
                    att.get('size', 'N/A') if att.get('size') else 'N/A',
                    Paragraph((att.get('hash', '')[:16] + '...') if att.get('hash') else 'N/A', cell_style),
                    Paragraph(vt_status, cell_style),
                    vt_count
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
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(KeepTogether([Paragraph("Attachments", styles['Heading2']), t]))
        story.append(Spacer(1, 20))

        # Suspicious HTML Elements
        story.append(Paragraph("Suspicious HTML Elements", styles['Heading2']))
        suspicious_elements = analysis_data.get('html_content', {}).get('suspicious_elements', [])
        if not suspicious_elements:
            story.append(Paragraph("No suspicious HTML elements found.", styles['Normal']))
        else:
            for el in suspicious_elements:
                story.append(Paragraph(str(el), styles['Normal']))
        story.append(Spacer(1, 20))

        # Suspicious Language Patterns
        story.append(Paragraph("Suspicious Language Patterns", styles['Heading2']))
        suspicious_patterns = analysis_data.get('language', {}).get('suspicious_patterns', [])
        if not suspicious_patterns:
            story.append(Paragraph("No suspicious language patterns found.", styles['Normal']))
        else:
            for pat in suspicious_patterns:
                story.append(Paragraph(str(pat), styles['Normal']))
        story.append(Spacer(1, 20))

        # Build PDF
        doc.build(story)
        return filepath

    def generate_csv(self, analysis_data, filename=None):
        """Generate CSV report from analysis data"""
        if not filename:
            filename = f"analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            
            # Write basic information
            writer.writerow(['Basic Information'])
            writer.writerow(['Subject', analysis_data['subject']])
            writer.writerow(['From', analysis_data['from']])
            writer.writerow(['To', analysis_data['to']])
            writer.writerow([])
            
            # Write URLs
            if analysis_data.get('urls'):
                writer.writerow(['URLs Found'])
                for url in analysis_data['urls']:
                    writer.writerow([url])
                writer.writerow([])
            
            # Write server hops
            if analysis_data.get('server_hops'):
                writer.writerow(['Server Hops'])
                for hop in analysis_data['server_hops']:
                    writer.writerow([hop['header'], ', '.join(hop['ip_addresses'])])
                writer.writerow([])
            
            # Write risk score
            if 'risk_score' in analysis_data:
                writer.writerow(['Risk Assessment'])
                writer.writerow(['Risk Score', analysis_data['risk_score']])
        
        return filepath 