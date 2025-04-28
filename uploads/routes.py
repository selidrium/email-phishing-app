import os
import logging
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required
from werkzeug.utils import secure_filename
from analysis.enhanced_parser import EnhancedEmailAnalyzer

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

upload_bp = Blueprint('uploads', __name__)

ALLOWED_EXTENSIONS = {'eml'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@upload_bp.route('/upload', methods=['POST'])
@jwt_required()
def upload_file():
    if 'file' not in request.files:
        logger.error('No file part in request')
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        logger.error('No selected file')
        return jsonify({'error': 'No selected file'}), 400
    
    if not allowed_file(file.filename):
        logger.error(f'Invalid file type: {file.filename}')
        return jsonify({'error': 'Invalid file type. Only .eml files are allowed'}), 400
    
    try:
        # Read file content
        file_content = file.read()
        logger.info(f'Read file content: {len(file_content)} bytes')
        
        # Analyze email using enhanced analyzer
        logger.info('Starting email analysis')
        analyzer = EnhancedEmailAnalyzer(file_content)
        analysis_result = analyzer.analyze()
        logger.info('Email analysis completed')
        logger.debug(f'Analysis result: {analysis_result}')
        
        # Save file temporarily
        filename = secure_filename(file.filename)
        file_path = os.path.join('uploads', filename)
        with open(file_path, 'wb') as f:
            f.write(file_content)
        logger.info(f'File saved to: {file_path}')
        
        return jsonify({
            'message': 'File uploaded and analyzed successfully',
            'analysis': analysis_result
        }), 200
        
    except Exception as e:
        logger.error(f'Error processing file: {str(e)}', exc_info=True)
        return jsonify({'error': f'Error processing file: {str(e)}'}), 500 