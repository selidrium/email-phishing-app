from flask import Flask
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Configure JWT
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your-secret-key')
jwt = JWTManager(app)

# Enable CORS
CORS(app)

# Create uploads directory if it doesn't exist
os.makedirs('uploads', exist_ok=True)

# Import and register blueprints
from auth.routes import auth_bp
from uploads.routes import upload_bp

app.register_blueprint(auth_bp, url_prefix='/auth')
app.register_blueprint(upload_bp, url_prefix='/uploads')

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True) 