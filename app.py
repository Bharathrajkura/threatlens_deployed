from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from datetime import datetime
import os
from dotenv import load_dotenv

load_dotenv()


BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
DEFAULT_DB_PATH = os.path.join(INSTANCE_DIR, "threatlens.db")


def _database_uri() -> str:
    uri = os.getenv("DATABASE_URL")
    if uri:
        # Force SQLAlchemy to use psycopg v3, which is installed in requirements.
        if uri.startswith("postgres://"):
            return uri.replace("postgres://", "postgresql+psycopg://", 1)
        if uri.startswith("postgresql://"):
            return uri.replace("postgresql://", "postgresql+psycopg://", 1)
        return uri
    return f"sqlite:///{DEFAULT_DB_PATH}"


os.makedirs(INSTANCE_DIR, exist_ok=True)

app = Flask(__name__, template_folder="templates", static_folder="frontend")
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "threatlens-secret-2024")
app.config["SQLALCHEMY_DATABASE_URI"] = _database_uri()
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["REMEMBER_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# ─── Models ───────────────────────────────────────────────────────────────────

class User(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    username    = db.Column(db.String(80), unique=True, nullable=False)
    email       = db.Column(db.String(120), unique=True, nullable=False)
    password    = db.Column(db.String(200), nullable=False)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    searches    = db.relationship('SearchHistory', backref='user', lazy=True)

    def get_id(self): return str(self.id)
    @property
    def is_authenticated(self): return True
    @property
    def is_active(self): return True
    @property
    def is_anonymous(self): return False


class SearchHistory(db.Model):
    id              = db.Column(db.Integer, primary_key=True)
    user_id         = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    url             = db.Column(db.String(2048), nullable=False)
    final_score     = db.Column(db.Float)
    verdict         = db.Column(db.String(20))
    ml_score        = db.Column(db.Float)
    nlp_score       = db.Column(db.Float)
    api_score       = db.Column(db.Float)
    searched_at     = db.Column(db.DateTime, default=datetime.utcnow)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# ─── Auth Routes ──────────────────────────────────────────────────────────────

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route("/healthz")
def healthz():
    return jsonify({"ok": True}), 200

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        data = request.get_json()
        user = User.query.filter_by(email=data.get('email')).first()
        if user and bcrypt.check_password_hash(user.password, data.get('password')):
            login_user(user)
            return jsonify({'success': True, 'username': user.username})
        return jsonify({'success': False, 'message': 'Invalid email or password'}), 401
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        data = request.get_json()
        if User.query.filter_by(email=data.get('email')).first():
            return jsonify({'success': False, 'message': 'Email already registered'}), 400
        if User.query.filter_by(username=data.get('username')).first():
            return jsonify({'success': False, 'message': 'Username already taken'}), 400
        hashed = bcrypt.generate_password_hash(data.get('password')).decode('utf-8')
        user = User(username=data['username'], email=data['email'], password=hashed)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return jsonify({'success': True, 'username': user.username})
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=current_user.username)

# ─── API Routes ───────────────────────────────────────────────────────────────

@app.route('/api/analyze', methods=['POST'])
@login_required
def analyze():
    from backend.modules.ml_analyzer import MLAnalyzer
    from backend.modules.nlp_analyzer import NLPAnalyzer
    from backend.modules.api_analyzer import APIAnalyzer
    from backend.modules.score_normalizer import ScoreNormalizer

    data = request.get_json()
    url  = data.get('url', '').strip()
    vt_key     = data.get('virustotal_key') or os.getenv("VIRUSTOTAL_API_KEY", "")
    abuse_key  = data.get('abuseipdb_key') or os.getenv("ABUSEIPDB_API_KEY", "")

    if not url:
        return jsonify({'error': 'URL is required'}), 400
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    try:
        ml_result  = MLAnalyzer().analyze(url)
        nlp_result = NLPAnalyzer().analyze(url)
        api_result = APIAnalyzer().analyze(url, vt_key, abuse_key)
        final      = ScoreNormalizer().combine(ml_result, nlp_result, api_result)

        # Save to history
        entry = SearchHistory(
            user_id    = current_user.id,
            url        = url,
            final_score= final['normalized_score'],
            verdict    = final['verdict'],
            ml_score   = ml_result['score'],
            nlp_score  = nlp_result['score'],
            api_score  = api_result['score'],
        )
        db.session.add(entry)
        db.session.commit()

        return jsonify({
            'url': url,
            'ml_analysis':  ml_result,
            'nlp_analysis': nlp_result,
            'api_analysis': api_result,
            'final_result': final
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/history')
@login_required
def history():
    records = SearchHistory.query.filter_by(user_id=current_user.id)\
                .order_by(SearchHistory.searched_at.desc()).limit(50).all()
    return jsonify([{
        'id':          r.id,
        'url':         r.url,
        'verdict':     r.verdict,
        'final_score': r.final_score,
        'ml_score':    r.ml_score,
        'nlp_score':   r.nlp_score,
        'api_score':   r.api_score,
        'searched_at': r.searched_at.strftime('%Y-%m-%d %H:%M'),
    } for r in records])


@app.route('/api/history/<int:record_id>', methods=['DELETE'])
@login_required
def delete_history(record_id):
    record = SearchHistory.query.filter_by(id=record_id, user_id=current_user.id).first()
    if record:
        db.session.delete(record)
        db.session.commit()
    return jsonify({'success': True})


@app.route('/api/stats')
@login_required
def stats():
    records = SearchHistory.query.filter_by(user_id=current_user.id).all()
    total   = len(records)
    safe    = sum(1 for r in records if r.verdict in ('SAFE', 'LOW'))
    risky   = sum(1 for r in records if r.verdict in ('SUSPICIOUS', 'MEDIUM'))
    danger  = sum(1 for r in records if r.verdict in ('MALICIOUS', 'HIGH', 'CRITICAL'))
    return jsonify({'total': total, 'safe': safe, 'risky': risky, 'dangerous': danger})


with app.app_context():
    db.create_all()


if __name__ == '__main__':
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=debug)
