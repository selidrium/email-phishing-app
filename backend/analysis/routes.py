from flask import Blueprint, request, jsonify
from .enhanced_analysis import EnhancedEmailAnalysis
import os

analysis_bp = Blueprint('analysis', __name__)

@analysis_bp.route('/analyze', methods=['POST'])
def analyze_email():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not file.filename.endswith('.eml'):
        return jsonify({'error': 'File must be an .eml file'}), 400
    
    try:
        # Read the email content
        email_content = file.read()
        
        # Analyze the email using enhanced analysis
        analyzer = EnhancedEmailAnalysis()
        results = analyzer.analyze_email(email_content)
        
        # Format results for frontend
        formatted_results = {
            "email_info": {
                "subject": results['email_info']['subject'],
                "from": results['email_info']['from'],
                "to": results['email_info']['to']
            },
            "risk_assessment": {
                "risk_score": results['risk_assessment']['risk_score'],
                "risk_factors": results['risk_assessment']['risk_factors']
            },
            "authentication_results": results['authentication_results'],
            "attachments": results['attachments'],
            "suspicious_html": results['suspicious_html'],
            "suspicious_language": results['suspicious_language']
        }
        
        return jsonify(formatted_results)
    
    except Exception as e:
        print(f"Error analyzing email: {str(e)}")  # Add logging
        return jsonify({'error': str(e)}), 500 