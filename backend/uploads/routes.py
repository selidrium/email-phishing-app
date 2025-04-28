import os
import hashlib
from flask import Blueprint, request, jsonify, send_file
from flask_jwt_extended import jwt_required
from werkzeug.utils import secure_filename
from analysis.email_parser import parse_email
from utils.threat_intelligence import ThreatIntelligence
from utils.report_generator import ReportGenerator

upload_bp = Blueprint('uploads', __name__)
threat_intel = ThreatIntelligence()
report_generator = ReportGenerator()

ALLOWED_EXTENSIONS = {'eml'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def calculate_file_hash(file_content):
    """Calculate SHA-256 hash of file content"""
    return hashlib.sha256(file_content).hexdigest()

@upload_bp.route('/upload', methods=['POST'])
@jwt_required()
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type. Only .eml files are allowed'}), 400
    
    try:
        # Read file content
        file_content = file.read()
        
        # Parse email content
        analysis_result = parse_email(file_content)
        
        # Add raw email for debugging
        analysis_result['raw_email'] = file_content.decode(errors='replace')
        
        # --- Per-attachment hashing and VirusTotal ---
        attachments = analysis_result.get('attachments', {}).get('attachments', [])
        for att in attachments:
            if 'content_bytes' in att and att['content_bytes']:
                att_bytes = att['content_bytes']
                att_hash = hashlib.sha256(att_bytes).hexdigest()
                att['hash'] = att_hash
                vt_result = threat_intel.check_virustotal(att_hash)
                att['virustotal'] = vt_result if vt_result else None
            else:
                att['hash'] = None
                att['virustotal'] = None
        # Remove content_bytes before sending to frontend
        for att in attachments:
            if 'content_bytes' in att:
                del att['content_bytes']
        
        # Calculate file hash for VirusTotal
        file_hash = calculate_file_hash(file_content)
        
        # Check threat intelligence
        vt_results = threat_intel.check_virustotal(file_hash)
        abuseipdb_results = {}
        
        # Extract all IP addresses from server hops
        all_ips = set()
        for hop in analysis_result.get('server_hops', []):
            all_ips.update(hop.get('ip_addresses', []))
        
        # Check each unique IP against AbuseIPDB
        for ip in all_ips:
            if ip not in abuseipdb_results:
                result = threat_intel.check_abuseipdb(ip)
                if result:  # Only add if we got a valid response
                    abuseipdb_results[ip] = result
        
        # Calculate risk score
        risk_score = threat_intel.calculate_risk_score(
            analysis_result,
            vt_results,
            abuseipdb_results
        )
        
        # Add threat intelligence results to analysis
        analysis_result.update({
            'risk_score': risk_score,
            'threat_intelligence': {
                'threat_data': abuseipdb_results
            }
        })
        
        # Save file temporarily
        filename = secure_filename(file.filename)
        file_path = os.path.join('uploads', filename)
        with open(file_path, 'wb') as f:
            f.write(file_content)
        
        return jsonify({
            'message': 'File uploaded and analyzed successfully',
            'analysis': analysis_result
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error processing file: {str(e)}'}), 500

@upload_bp.route('/download/pdf/<filename>', methods=['POST'])
@jwt_required()
def download_pdf(filename):
    try:
        analysis_data = request.get_json()
        pdf_path = report_generator.generate_pdf(
            analysis_data,
            filename=f"{filename}.pdf"
        )
        return send_file(
            pdf_path,
            as_attachment=True,
            download_name=f"{filename}.pdf",
            mimetype='application/pdf'
        )
    except Exception as e:
        return jsonify({'error': f'Error generating PDF: {str(e)}'}), 500

@upload_bp.route('/download/csv/<filename>', methods=['POST'])
@jwt_required()
def download_csv(filename):
    try:
        analysis_data = request.get_json()
        csv_path = report_generator.generate_csv(
            analysis_data,
            filename=f"{filename}.csv"
        )
        return send_file(
            csv_path,
            as_attachment=True,
            download_name=f"{filename}.csv",
            mimetype='text/csv'
        )
    except Exception as e:
        return jsonify({'error': f'Error generating CSV: {str(e)}'}), 500 