from flask import Flask, request, jsonify, render_template, send_file, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
from dotenv import load_dotenv
import os
from openai import OpenAI, APIError, APIConnectionError, RateLimitError, APITimeoutError, AuthenticationError
import PyPDF2
from docx import Document
from io import BytesIO


# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:4895@localhost:5432/improve writting'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Initialize OpenAI client
# The client will automatically use the OPENAI_API_KEY environment variable
client = OpenAI()

# File configuration
ALLOWED_EXTENSIONS = {'pdf', 'docx'}

# Models
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    submissions = db.relationship('UploadedFile', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class UploadedFile(db.Model):
    __tablename__ = 'uploaded_files'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    file_data = db.Column(db.LargeBinary, nullable=False)
    grammar_feedback = db.Column(db.Text, nullable=True)
    clarity_feedback = db.Column(db.Text, nullable=True)
    content_quality_feedback = db.Column(db.Text, nullable=True)
    upload_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

# Helper functions
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_file_content(file, filename):
    """Extract text content from uploaded files."""
    try:
        if filename.endswith('.pdf'):
            reader = PyPDF2.PdfReader(file.stream)
            content = "\n".join([
                page.extract_text() 
                for page in reader.pages 
                if page.extract_text()
            ])
            file.stream.seek(0)
            return content
        elif filename.endswith('.docx'):
            doc = Document(file.stream)
            content = "\n".join([para.text for para in doc.paragraphs])
            file.stream.seek(0)
            return content
    except Exception as e:
        raise Exception(f"Error reading file: {str(e)}")

def generate_ai_feedback(text_content):
    """Generate feedback using OpenAI API."""
    try:
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {
                    "role": "system",
                    "content": "You are a writing assistant that provides detailed feedback on grammar, clarity, and content quality."
                },
                {
                    "role": "user",
                    "content": f"""Please analyze this text and provide specific feedback in three sections:
                    1. Grammar and Spelling: Check for grammatical errors, spelling mistakes, and punctuation issues.
                    2. Clarity and Style: Evaluate the writing style, sentence structure, and overall clarity.
                    3. Content Quality: Assess the coherence, organization, and effectiveness of the content.

                    Text to analyze:
                    {text_content}"""
                }
            ],
            max_tokens=1000,
            temperature=0.7
        )
        
        feedback_text = response.choices[0].message.content.strip()
        sections = feedback_text.split('\n\n')
        
        feedback = {
            "grammar_feedback": "No grammar feedback available.",
            "clarity_feedback": "No clarity feedback available.",
            "content_quality_feedback": "No content quality feedback available."
        }
        
        for section in sections:
            section_lower = section.lower()
            if 'grammar' in section_lower or 'spelling' in section_lower:
                feedback['grammar_feedback'] = section
            elif 'clarity' in section_lower or 'style' in section_lower:
                feedback['clarity_feedback'] = section
            elif 'content' in section_lower:
                feedback['content_quality_feedback'] = section
                
        return feedback
        
    except AuthenticationError:
        raise Exception("OpenAI API authentication failed. Please check your API key.")
    except RateLimitError:
        raise Exception("OpenAI API rate limit exceeded. Please try again later.")
    except APIConnectionError:
        raise Exception("Failed to connect to OpenAI API. Please check your internet connection.")
    except APITimeoutError:
        raise Exception("OpenAI API request timed out. Please try again.")
    except APIError as e:
        raise Exception(f"OpenAI API error: {str(e)}")
    except Exception as e:
        raise Exception(f"Error generating feedback: {str(e)}")

# Routes
@app.route('/')
@login_required
def index():
    return redirect(url_for('upload_page'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        try:
            data = request.get_json()
            
            if User.query.filter_by(username=data['username']).first():
                return jsonify({'error': 'Username already exists'}), 400
            
            if User.query.filter_by(email=data['email']).first():
                return jsonify({'error': 'Email already registered'}), 400

            user = User(username=data['username'], email=data['email'])
            user.set_password(data['password'])

            db.session.add(user)
            db.session.commit()
            login_user(user)
            return jsonify({'message': 'Signup successful', 'username': user.username}), 200

        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('upload_page'))
        
    if request.method == 'POST':
        try:
            data = request.get_json()
            user = User.query.filter_by(username=data['username']).first()

            if user and user.check_password(data['password']):
                login_user(user)
                return jsonify({'message': 'Login successful', 'username': user.username}), 200
            
            return jsonify({'error': 'Invalid username or password'}), 401

        except Exception as e:
            return jsonify({'error': str(e)}), 500

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/upload-page')
@login_required
def upload_page():
    try:
        submissions = UploadedFile.query.filter_by(user_id=current_user.id)\
            .order_by(UploadedFile.upload_date.desc()).all()
        return render_template('upload.html', 
                             username=current_user.username,
                             submissions=submissions)
    except Exception as e:
        print(f"Error in upload_page: {str(e)}")
        return render_template('upload.html', 
                             username=current_user.username,
                             submissions=[])

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file part"}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "No selected file"}), 400

        if not allowed_file(file.filename):
            return jsonify({"error": "Invalid file type. Please upload a PDF or DOCX file."}), 400

        filename = secure_filename(file.filename)
        
        # Get file content
        try:
            file_content = get_file_content(file, filename)
            if not file_content.strip():
                return jsonify({"error": "File is empty or could not be read"}), 400
        except Exception as e:
            return jsonify({"error": str(e)}), 400

        # Generate AI feedback
        try:
            feedback = generate_ai_feedback(file_content)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

        # Save to database
        try:
            new_file = UploadedFile(
                filename=filename,
                file_data=file.read(),
                grammar_feedback=feedback['grammar_feedback'],
                clarity_feedback=feedback['clarity_feedback'],
                content_quality_feedback=feedback['content_quality_feedback'],
                user_id=current_user.id
            )

            db.session.add(new_file)
            db.session.commit()

            return jsonify({
                "message": "File uploaded successfully",
                "feedback": feedback
            }), 200

        except Exception as e:
            db.session.rollback()
            return jsonify({"error": f"Database error: {str(e)}"}), 500

    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route('/view-submission/<int:submission_id>')
@login_required
def view_submission(submission_id):
    try:
        submission = UploadedFile.query.get_or_404(submission_id)
        if submission.user_id != current_user.id:
            return jsonify({"error": "Unauthorized access"}), 403
        
        return render_template('submission.html',
                             submission=submission,
                             username=current_user.username)
    except Exception as e:
        print(f"Error viewing submission: {str(e)}")
        return redirect(url_for('upload_page'))

@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    try:
        uploaded_file = UploadedFile.query.get_or_404(file_id)
        if uploaded_file.user_id != current_user.id:
            return jsonify({"error": "Unauthorized access"}), 403
            
        return send_file(
            BytesIO(uploaded_file.file_data),
            as_attachment=True,
            download_name=uploaded_file.filename
        )
    except Exception as e:
        return jsonify({"error": f"Download error: {str(e)}"}), 500

@app.route('/delete-submission/<int:submission_id>', methods=['POST'])
@login_required
def delete_submission(submission_id):
    try:
        submission = UploadedFile.query.get_or_404(submission_id)
        if submission.user_id != current_user.id:
            return jsonify({"error": "Unauthorized access"}), 403
        
        db.session.delete(submission)
        db.session.commit()
        return jsonify({"message": "Submission deleted successfully"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Error deleting submission: {str(e)}"}), 500

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return jsonify({"error": "Resource not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return jsonify({"error": "Internal server error"}), 500

# Database initialization
def init_db():
    with app.app_context():
        db.create_all()
        print("Database tables created successfully!")

if __name__ == '__main__':
    init_db()  # Initialize database on startup
    app.run(debug=True)
