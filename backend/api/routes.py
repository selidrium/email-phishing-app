import os
import json
import logging
import datetime
import uuid
import re
import requests
import io
import csv
from typing import Optional
from fastapi import APIRouter, Depends, File, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, validator
from sqlalchemy.orm import Session
from fastapi_jwt_auth import AuthJWT
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from email_validator import validate_email, EmailNotValidError

from backend.models.sqlalchemy_models import User, Email
from backend.services.auth import authenticate_user, hash_password, create_access_token
from backend.services.upload import upload_service
from backend.services import email_forensics
from backend.utils.database import get_db
from backend.utils.auth import get_current_user
from backend.utils.exceptions import (
    ValidationError, AuthenticationError, NotFoundError, 
    AnalysisError, ReportGenerationError, DatabaseError,
    handle_service_error
)

logger = logging.getLogger(__name__)

router = APIRouter()

class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str
    
    @validator('email')
    def validate_email_address(cls, v):
        try:
            validate_email(v)
            return v
        except EmailNotValidError as e:
            raise ValueError(str(e))
    
    @validator('username')
    def validate_username(cls, v):
        if len(v) < 3:
            raise ValueError('Username must be at least 3 characters')
        return v
    
    @validator('password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        return v

    class Config:
        anystr_strip_whitespace = True

class LoginRequest(BaseModel):
    username: str
    password: str
    
    class Config:
        anystr_strip_whitespace = True

@router.post("/auth/register")
async def register(request: RegisterRequest, db: Session = Depends(get_db)):
    """Register new user with comprehensive error handling"""
    try:
        logger.info(f"Registration attempt for username: {request.username}")
        
        # Check if user exists
        existing_user = db.query(User).filter(
            (User.username == request.username) | (User.email == request.email)
        ).first()
        
        if existing_user:
            logger.warning(f"Registration failed - user already exists: {request.username}")
            raise ValidationError("Username or email already exists")
            
        # Create user
        hashed = hash_password(request.password)
        user = User(username=request.username, email=request.email, hashed_password=hashed)
        db.add(user)
        db.commit()
        
        logger.info(f"User registered successfully: {request.username}")
        return {"msg": "Registration successful"}
        
    except (ValidationError, DatabaseError):
        raise
    except Exception as e:
        logger.error(f"Service error in user_registration: {type(e).__name__}")
        raise handle_service_error(e, "user_registration")

@router.post("/auth/login")
async def login(request: LoginRequest, Authorize: AuthJWT = Depends(), db: Session = Depends(get_db)):
    """Login user with comprehensive error handling"""
    try:
        logger.info(f"Login attempt for username: {request.username}")
        
        # Validate input
        if not request.username or not request.password:
            raise ValidationError("Username and password required")
            
        # Authenticate user
        user = authenticate_user(db, request.username, request.password)
        if not user:
            logger.warning(f"Login failed - invalid credentials for: {request.username}")
            raise AuthenticationError("Invalid credentials")
            
        # Create access token
        access_token = create_access_token(identity=user.username, Authorize=Authorize)
        
        logger.info(f"User logged in successfully: {request.username}")
        return {"access_token": access_token}
        
    except (ValidationError, AuthenticationError):
        raise
    except Exception as e:
        logger.error(f"Service error in user_login: {type(e).__name__}")
        raise handle_service_error(e, "user_login")

def safe_get(d, key, default='N/A'):
    if isinstance(d, dict):
        return d.get(key, default)
    return d if isinstance(d, str) else default

def extract_report_data(report_data):
    """Extract and validate common report data fields"""
    return {
        'metadata': report_data.get('metadata', {}),
        'header_summary': report_data.get('header_summary', {}),
        'risk_scoring': report_data.get('risk_scoring', {}),
        'delivery_chain': report_data.get('delivery_chain', {}),
        'threat_indicators': report_data.get('threat_indicators', []),
        'virustotal_summary': report_data.get('virustotal_summary', {}),
        'attachments': report_data.get('attachments', []),
        'file_integrity': report_data.get('file_integrity', {})
    }

def create_metadata_table_data(metadata, risk_scoring):
    """Create metadata table data for both CSV and PDF"""
    return [
        ['Field', 'Value'],
        ['From', safe_get(metadata, 'from')],
        ['To', safe_get(metadata, 'to')],
        ['Subject', safe_get(metadata, 'subject')],
        ['Date', safe_get(metadata, 'date')],
        ['Message ID', safe_get(metadata, 'message_id')],
        ['Sender IP', safe_get(metadata, 'sender_ip')],
        ['Phishing Score', f"{safe_get(risk_scoring, 'phishing_score', 0)} / 100"],
        ['Overall Risk Score', f"{safe_get(risk_scoring, 'overall_risk_score', 0)} / 100"],
        ['Risk Level', safe_get(risk_scoring, 'risk_level', 'unknown')],
        ['Flagged as', 'Phishing' if safe_get(risk_scoring, 'is_phishing', False) else 'Benign']
    ]

def create_header_summary_table_data(metadata, header_summary):
    """Create header summary table data for both CSV and PDF"""
    return [
        ['Field', 'Value'],
        ['From', safe_get(metadata, 'from')],
        ['To', safe_get(metadata, 'to')],
        ['Subject', safe_get(metadata, 'subject')],
        ['Date', safe_get(metadata, 'date')],
        ['Message ID', safe_get(metadata, 'message_id')],
        ['Total Headers', safe_get(header_summary, 'total_headers', 0)],
        ['Security Headers', safe_get(header_summary, 'security_headers', 0)],
        ['Custom Headers', safe_get(header_summary, 'custom_headers', 0)]
    ]

def create_delivery_chain_table_data(delivery_chain):
    """Create delivery chain table data for both CSV and PDF"""
    routing_path = delivery_chain.get('routing_path', [])
    if not routing_path:
        return None
    
    table_data = [['Hop', 'IP Address', 'Hostname', 'Timestamp']]
    for i, hop in enumerate(routing_path, 1):
        ip_addresses = hop.get('ip_addresses', [])
        ip = ip_addresses[0] if ip_addresses else ''
        table_data.append([
            str(i),
            ip,
            safe_get(hop, 'from_host'),
            safe_get(hop, 'timestamp')
        ])
    return table_data

def create_threat_indicators_table_data(threat_indicators):
    """Create threat indicators table data for both CSV and PDF"""
    if not threat_indicators:
        return None
    
    table_data = [['Type', 'Severity', 'Description']]
    for indicator in threat_indicators:
        table_data.append([
            safe_get(indicator, 'type'),
            safe_get(indicator, 'severity'),
            safe_get(indicator, 'description')
        ])
    return table_data

def create_risk_scoring_table_data(risk_scoring):
    """Create risk scoring table data for both CSV and PDF"""
    if not risk_scoring:
        return None
    
    return [
        ['Field', 'Value'],
        ['Phishing Score', f"{safe_get(risk_scoring, 'phishing_score', 0)} / 100"],
        ['Overall Risk Score', f"{safe_get(risk_scoring, 'overall_risk_score', 0)} / 100"],
        ['Risk Level', safe_get(risk_scoring, 'risk_level', 'unknown')],
        ['Is Phishing', 'Yes' if safe_get(risk_scoring, 'is_phishing', False) else 'No']
    ]

def create_virustotal_table_data(virustotal_summary):
    """Create VirusTotal table data for both CSV and PDF"""
    if not virustotal_summary:
        return None
    
    table_data = [['Analysis Type', 'Status', 'Details']]
    
    ip_reputation = virustotal_summary.get('ip_reputation', {})
    if isinstance(ip_reputation, dict) and ip_reputation.get('available'):
        table_data.append([
            'IP Reputation',
            safe_get(ip_reputation, 'verdict', 'unknown'),
            f"Score: {safe_get(ip_reputation, 'score', 0)}, Country: {safe_get(ip_reputation, 'country', 'Unknown')}"
        ])
    else:
        table_data.append(['IP Reputation', 'Not Available', safe_get(ip_reputation, 'error', 'No data')])
    
    file_hash = virustotal_summary.get('file_hash', {})
    if isinstance(file_hash, dict) and file_hash.get('available'):
        table_data.append([
            'File Hash',
            safe_get(file_hash, 'verdict', 'unknown'),
            f"Score: {safe_get(file_hash, 'score', 0)}"
        ])
    else:
        table_data.append(['File Hash', 'Not Available', safe_get(file_hash, 'error', 'No data')])
    
    return table_data

def create_attachments_table_data(attachments):
    """Create attachments table data for both CSV and PDF"""
    if not attachments:
        return None
    
    table_data = [['File Name', 'Type', 'Size', 'Suspicious']]
    for attachment in attachments:
        table_data.append([
            safe_get(attachment, 'filename'),
            safe_get(attachment, 'content_type'),
            f"{safe_get(attachment, 'size', 0)} bytes",
            'Yes' if safe_get(attachment, 'suspicious', False) else 'No'
        ])
    return table_data

def get_recommendation(risk_scoring):
    """Get recommendation based on risk scoring"""
    is_phishing = safe_get(risk_scoring, 'is_phishing', False)
    risk_level = safe_get(risk_scoring, 'risk_level', 'unknown')
    
    if is_phishing:
        return "🚨 BLOCK - This email has been identified as phishing and should be blocked immediately."
    elif risk_level in ['high', 'medium']:
        return "⚠️ CAUTION - This email shows suspicious indicators and should be handled with caution."
    else:
        return "✅ ALLOW - This email appears to be legitimate and can be delivered."

@router.post("/upload")
async def upload(file: UploadFile = File(...), db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    """Upload and analyze email file with comprehensive error handling"""
    try:
        logger.info(f"File upload attempt by user: {current_user['username']}, file: {file.filename}")
        contents = await upload_service.validate_upload(file)
        
        # Get comprehensive analysis with VirusTotal integration
        scan_result = await upload_service.scan_file(contents)
        
        # Check if there was an error in analysis
        if 'error' in scan_result:
            logger.error(f"Analysis error: {scan_result['error']}")
            raise AnalysisError(f"Analysis failed: {scan_result['error']}")
        
        # Extract the unified report
        unified_report = scan_result.get('report', {})
        
        upload_time = datetime.datetime.utcnow().isoformat()
        
        # Extract risk scoring for database storage
        risk_scoring = unified_report.get('risk_scoring', {})
        
        # Store the complete unified report
        analysis_json = json.dumps({
            "unified_report": unified_report,
            "uploaded_by": current_user['username'],
            "uploaded_at": upload_time
        })
        
        email = Email(
            filename=file.filename,
            uploaded_at=datetime.datetime.utcnow(),
            phishing_score=risk_scoring.get('overall_risk_score', 0),  # Use overall risk score
            is_phishing=risk_scoring.get('is_phishing', False),  # Use correct is_phishing flag
            analysis_json=analysis_json,
            user_id=current_user["id"]
        )
        db.add(email)
        db.commit()
        
        logger.info(f"File analysis completed for user {current_user['username']}: score={risk_scoring.get('overall_risk_score', 0)}")
        return {
            "report": unified_report,
            "email_id": email.id,
            "message": "File analyzed successfully"
        }
    except (ValidationError, AnalysisError):
        raise
    except Exception as e:
        logger.error(f"Service error in file_upload: {type(e).__name__}")
        raise handle_service_error(e, "file_upload", {"file_name": file.filename})

def generate_csv_report_unified(report_data):
    """Generate CSV report from unified report data"""
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Extract data using shared helper
    data = extract_report_data(report_data)
    metadata = data['metadata']
    header_summary = data['header_summary']
    risk_scoring = data['risk_scoring']
    delivery_chain = data['delivery_chain']
    threat_indicators = data['threat_indicators']
    virustotal_summary = data['virustotal_summary']
    attachments = data['attachments']
    file_integrity = data['file_integrity']
    
    # Report Metadata
    writer.writerow(['🧾 Phishing Analysis & Email Forensics Report'])
    writer.writerow([])
    writer.writerow(['1. Report Metadata'])
    writer.writerow(['Field', 'Value'])
    
    # Use shared metadata table data
    metadata_data = create_metadata_table_data(metadata, risk_scoring)
    for row in metadata_data[1:]:  # Skip header row
        writer.writerow(row)
    writer.writerow([])
    
    # File Integrity
    writer.writerow(['1.5. File Integrity & Security'])
    writer.writerow(['Field', 'Value'])
    writer.writerow(['File Size (bytes)', safe_get(file_integrity, 'file_size', 0)])
    writer.writerow(['Hash Verification', safe_get(file_integrity, 'hash_verification', 'unknown')])
    hashes = file_integrity.get('hashes', {}) if isinstance(file_integrity, dict) else {}
    writer.writerow(['SHA256 Hash', safe_get(hashes, 'sha256')])
    writer.writerow(['MD5 Hash', safe_get(hashes, 'md5')])
    writer.writerow([])
    
    # Header Analysis
    writer.writerow(['2. Header Analysis'])
    writer.writerow(['Field', 'Value'])
    header_data = create_header_summary_table_data(metadata, header_summary)
    for row in header_data[1:]:  # Skip header row
        writer.writerow(row)
    writer.writerow([])
    
    # Delivery Chain
    delivery_data = create_delivery_chain_table_data(delivery_chain)
    if delivery_data:
        writer.writerow(['3. Email Delivery Chain'])
        for row in delivery_data:
            writer.writerow(row)
    writer.writerow([])
    
    # Threat Indicators
    threat_data = create_threat_indicators_table_data(threat_indicators)
    if threat_data:
        writer.writerow(['4. Threat Indicators'])
        for row in threat_data:
            writer.writerow(row)
    writer.writerow([])
    
    # Risk Scoring
    risk_data = create_risk_scoring_table_data(risk_scoring)
    if risk_data:
        writer.writerow(['5. Risk Scoring Breakdown'])
        for row in risk_data:
            writer.writerow(row)
    writer.writerow([])
    
    # VirusTotal Results
    vt_data = create_virustotal_table_data(virustotal_summary)
    if vt_data:
        writer.writerow(['6. VirusTotal Analysis'])
        for row in vt_data:
            writer.writerow(row)
    writer.writerow([])
    
    # Attachments
    attachment_data = create_attachments_table_data(attachments)
    if attachment_data:
        writer.writerow(['7. Attachments Summary'])
        for row in attachment_data:
            writer.writerow(row)
        writer.writerow([])
    # Summary
    writer.writerow(['8. Summary & Recommendation'])
    recommendation = get_recommendation(risk_scoring)
    writer.writerow(['Recommendation', recommendation])
    
    return output.getvalue()

def generate_pdf_report_unified(report_data):
    """Generate PDF report from unified report data"""
    try:
        logger.info(f"PDF generation started with report_data type: {type(report_data)}")
        logger.info(f"Report data keys: {list(report_data.keys()) if isinstance(report_data, dict) else 'Not a dict'}")
        
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4)
        story = []
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=16,
            spaceAfter=30,
            alignment=1  # Center
        )
        story.append(Paragraph('🧾 Phishing Analysis & Email Forensics Report', title_style))
        story.append(Spacer(1, 20))
        
        # Extract data using shared helper
        data = extract_report_data(report_data)
        metadata = data['metadata']
        header_summary = data['header_summary']
        risk_scoring = data['risk_scoring']
        delivery_chain = data['delivery_chain']
        threat_indicators = data['threat_indicators']
        virustotal_summary = data['virustotal_summary']
        attachments = data['attachments']
        file_integrity = data['file_integrity']
        
        logger.info(f"Metadata type: {type(metadata)}, Header summary type: {type(header_summary)}, Risk scoring type: {type(risk_scoring)}")
    
        # 1. Report Metadata
        story.append(Paragraph('1. Report Metadata', styles['Heading2']))
        metadata_data = create_metadata_table_data(metadata, risk_scoring)
        # Wrap non-header cells
        for row_idx, row in enumerate(metadata_data):
            for col_idx, cell in enumerate(row):
                if row_idx > 0:
                    metadata_data[row_idx][col_idx] = Paragraph(str(cell), styles['Normal'])
        metadata_table = Table(metadata_data, colWidths=[2*inch, 4*inch])
        metadata_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(metadata_table)
        story.append(Spacer(1, 20))
    
        # 2. Email Header Summary
        story.append(Paragraph('2. Email Header Summary', styles['Heading2']))
        header_data = create_header_summary_table_data(metadata, header_summary)
        for row_idx, row in enumerate(header_data):
            for col_idx, cell in enumerate(row):
                if row_idx > 0:
                    header_data[row_idx][col_idx] = Paragraph(str(cell), styles['Normal'])
        header_table = Table(header_data, colWidths=[2*inch, 4*inch])
        header_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(header_table)
        story.append(Spacer(1, 20))
    
        # 3. Email Delivery Chain
        delivery_data = create_delivery_chain_table_data(delivery_chain)
        logger.info(f"Delivery data type: {type(delivery_data)}, length: {len(delivery_data) if delivery_data else 'None'}")
        if delivery_data:
            story.append(Paragraph('3. Email Delivery Chain', styles['Heading2']))
            for row_idx, row in enumerate(delivery_data):
                for col_idx, cell in enumerate(row):
                    if row_idx > 0:
                        delivery_data[row_idx][col_idx] = Paragraph(str(cell), styles['Normal'])
            delivery_table = Table(delivery_data, colWidths=[0.5*inch, 1.5*inch, 2*inch, 2*inch])
            delivery_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(delivery_table)
            story.append(Spacer(1, 20))
    
        # 4. Threat Indicators
        threat_data = create_threat_indicators_table_data(threat_indicators)
        logger.info(f"Threat data type: {type(threat_data)}, length: {len(threat_data) if threat_data else 'None'}")
        if threat_data:
            story.append(Paragraph('4. Threat Indicators', styles['Heading2']))
            for row_idx, row in enumerate(threat_data):
                for col_idx, cell in enumerate(row):
                    if row_idx > 0:
                        threat_data[row_idx][col_idx] = Paragraph(str(cell), styles['Normal'])
            threat_table = Table(threat_data, colWidths=[1.5*inch, 1*inch, 3.5*inch])
            threat_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(threat_table)
            story.append(Spacer(1, 20))
    
        # 5. Risk Scoring Breakdown
        risk_data = create_risk_scoring_table_data(risk_scoring)
        if risk_data:
            story.append(Paragraph('5. Risk Scoring Breakdown', styles['Heading2']))
            for row_idx, row in enumerate(risk_data):
                for col_idx, cell in enumerate(row):
                    if row_idx > 0:
                        risk_data[row_idx][col_idx] = Paragraph(str(cell), styles['Normal'])
            risk_table = Table(risk_data, colWidths=[2*inch, 4*inch])
            risk_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(risk_table)
            story.append(Spacer(1, 20))
    
        # 6. VirusTotal Analysis
        vt_data = create_virustotal_table_data(virustotal_summary)
        logger.info(f"VT data type: {type(vt_data)}, length: {len(vt_data) if vt_data else 'None'}")
        if vt_data:
            story.append(Paragraph('6. VirusTotal Analysis', styles['Heading2']))
            for row_idx, row in enumerate(vt_data):
                for col_idx, cell in enumerate(row):
                    if row_idx > 0:
                        vt_data[row_idx][col_idx] = Paragraph(str(cell), styles['Normal'])
            vt_table = Table(vt_data, colWidths=[1.5*inch, 1.5*inch, 3*inch])
            vt_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(vt_table)
            story.append(Spacer(1, 20))
    
        # 7. Attachments Summary
        attachment_data = create_attachments_table_data(attachments)
        logger.info(f"Attachment data type: {type(attachment_data)}, length: {len(attachment_data) if attachment_data else 'None'}")
        if attachment_data:
            story.append(Paragraph('7. Attachments Summary', styles['Heading2']))
            for row_idx, row in enumerate(attachment_data):
                for col_idx, cell in enumerate(row):
                    if row_idx > 0:
                        attachment_data[row_idx][col_idx] = Paragraph(str(cell), styles['Normal'])
            attachment_table = Table(attachment_data, colWidths=[2*inch, 1*inch, 1*inch, 1*inch])
            attachment_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(attachment_table)
            story.append(Spacer(1, 20))
        
        # 8. Summary & Recommendation
        story.append(Paragraph('8. Summary & Recommendation', styles['Heading2']))
        recommendation = get_recommendation(risk_scoring)
        
        # Determine color based on recommendation
        if "BLOCK" in recommendation:
            color = colors.red
        elif "CAUTION" in recommendation:
            color = colors.orange
        else:
            color = colors.green
            
        story.append(Paragraph(recommendation, ParagraphStyle(
            'Recommendation',
            parent=styles['Normal'],
            fontSize=12,
            textColor=color,
            spaceAfter=20
        )))
        
        doc.build(story)
        buffer.seek(0)
        logger.info("PDF generation completed successfully")
        return buffer
    except (ValidationError, ReportGenerationError):
        raise
    except Exception as e:
        logger.error(f"Service error in pdf_generation: {type(e).__name__}")
        raise handle_service_error(e, "pdf_generation", {"filename": "report"})

@router.get("/export/csv/{email_id}")
async def export_csv_report(email_id: int, current_user=Depends(get_current_user), db: Session = Depends(get_db)):
    """Export CSV report for specific email analysis"""
    try:
        # Get email record
        email = db.query(Email).filter(Email.id == email_id, Email.user_id == current_user["id"]).first()
        if not email:
            raise NotFoundError("Email not found")
        
        # Parse analysis data
        try:
            analysis_data = json.loads(email.analysis_json)
            logger.info(f"Analysis data keys: {list(analysis_data.keys())}")
        except json.JSONDecodeError as e:
            logger.error(f"Service error in json_decode: {type(e).__name__}")
            raise handle_service_error(e, "json_decode", {"email_id": email_id})
        
        unified_report = analysis_data.get("unified_report", {})
        logger.info(f"Unified report keys: {list(unified_report.keys()) if unified_report else 'No unified report'}")
        
        # Generate CSV - pass the unified_report directly
        try:
            csv_content = generate_csv_report_unified(unified_report)
        except Exception as e:
            logger.error(f"Service error in csv_generation: {type(e).__name__}")
            raise handle_service_error(e, "csv_generation", {"email_id": email_id})
        
        # Create response
        response = StreamingResponse(
            io.StringIO(csv_content),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=phishing_report_{email_id}.csv"}
        )
        
        logger.info(f"CSV report exported for email {email_id} by user {current_user['username']}")
        return response
        
    except (ValidationError, NotFoundError):
        raise
    except Exception as e:
        logger.error(f"Service error in csv_export: {type(e).__name__}")
        raise handle_service_error(e, "csv_export", {"email_id": email_id})

@router.get("/export/pdf/{email_id}")
async def export_pdf_report(email_id: int, current_user=Depends(get_current_user), db: Session = Depends(get_db)):
    """Export PDF report for specific email analysis"""
    try:
        # Get email record
        email = db.query(Email).filter(Email.id == email_id, Email.user_id == current_user["id"]).first()
        if not email:
            raise NotFoundError("Email not found")
        
        # Parse analysis data
        try:
            analysis_data = json.loads(email.analysis_json)
            logger.info(f"Analysis data keys: {list(analysis_data.keys())}")
        except json.JSONDecodeError as e:
            logger.error(f"Service error in json_decode_pdf: {type(e).__name__}")
            raise handle_service_error(e, "json_decode_pdf", {"email_id": email_id})
        
        unified_report = analysis_data.get("unified_report", {})
        logger.info(f"Unified report keys: {list(unified_report.keys()) if unified_report else 'No unified report'}")
        
        # Generate PDF - pass the unified_report directly
        try:
            pdf_buffer = generate_pdf_report_unified(unified_report)
        except Exception as e:
            logger.error(f"Service error in pdf_generation_export: {type(e).__name__}")
            raise handle_service_error(e, "pdf_generation_export", {"email_id": email_id})
        
        # Create response
        response = StreamingResponse(
            io.BytesIO(pdf_buffer.getvalue()),
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=phishing_report_{email_id}.pdf"}
        )
        
        logger.info(f"PDF report exported for email {email_id} by user {current_user['username']}")
        return response
        
    except (ValidationError, NotFoundError):
        raise
    except Exception as e:
        logger.error(f"Service error in pdf_export: {type(e).__name__}")
        raise handle_service_error(e, "pdf_export", {"email_id": email_id})

@router.get("/dashboard")
async def get_dashboard(current_user=Depends(get_current_user), db: Session = Depends(get_db)):
    """Get user's analysis dashboard"""
    try:
        # Get user's emails
        emails = db.query(Email).filter(Email.user_id == current_user["id"]).order_by(Email.uploaded_at.desc()).all()
        
        dashboard_data = []
        for email in emails:
            try:
                analysis_data = json.loads(email.analysis_json)
                unified_report = analysis_data.get("unified_report", {})
                risk_scoring = unified_report.get('risk_scoring', {})
                
                dashboard_data.append({
                    "id": email.id,
                    "filename": email.filename,
                    "uploaded_at": email.uploaded_at.isoformat(),
                    "phishing_score": risk_scoring.get('overall_risk_score', 0),
                    "is_phishing": risk_scoring.get('is_phishing', False),
                    "risk_level": risk_scoring.get('risk_level', 'unknown')
                })
            except json.JSONDecodeError:
                # Handle legacy data format
                dashboard_data.append({
                    "id": email.id,
                    "filename": email.filename,
                    "uploaded_at": email.uploaded_at.isoformat(),
                    "phishing_score": email.phishing_score or 0,
                    "is_phishing": email.is_phishing or False,
                    "risk_level": "unknown"
                })
        
        logger.info(f"Dashboard data retrieved for user {current_user['username']}: {len(dashboard_data)} emails")
        return {"emails": dashboard_data}
        
    except Exception as e:
        logger.error(f"Service error in dashboard: {type(e).__name__}")
        raise handle_service_error(e, "dashboard")
