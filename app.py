import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime

# -------------------- Configuración --------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = 'intelcheck-nullscape-prototipo-2026'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 8 * 1024 * 1024  # 8 MB

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Debes iniciar sesión para acceder a esta página.'
login_manager.login_message_category = 'warning'

# API Key de Claude (opcional, configúrala en las variables de entorno de Render)
ANTHROPIC_API_KEY = os.environ.get('ANTHROPIC_API_KEY')

# -------------------- Modelos --------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user')  # creator, administrador, calificador, user
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

    news = db.relationship('News', backref='author', lazy=True, foreign_keys='News.author_id')
    requests = db.relationship('VerificationRequest', backref='requester', lazy=True, foreign_keys='VerificationRequest.requester_id')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_creator(self):
        return self.role == 'creator'

    def is_administrador(self):
        return self.role == 'administrador'

    def is_calificador(self):
        return self.role in ('calificador', 'creator', 'administrador')

    def is_user(self):
        return self.role == 'user'

    def puede_gestionar_usuarios(self):
        return self.role in ('creator', 'administrador')

    def __repr__(self):
        return f'<User {self.username} ({self.role})>'


class News(db.Model):
    __tablename__ = 'news'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(300), nullable=True)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    status = db.Column(db.String(20), default='published')
    veracity_level = db.Column(db.String(30), nullable=True)  # falsa, verdadera, parcialmente_correcta, parcialmente_incorrecta
    veracity_note = db.Column(db.Text, nullable=True)

    verified_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    verified_at = db.Column(db.DateTime, nullable=True)

    verifier = db.relationship('User', foreign_keys=[verified_by])

    def __repr__(self):
        return f'<News {self.title}>'


class VerificationRequest(db.Model):
    __tablename__ = 'verification_request'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(300), nullable=True)
    requester_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    reviewed_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    admin_response = db.Column(db.Text, nullable=True)

    reviewer = db.relationship('User', foreign_keys=[reviewed_by])

    def __repr__(self):
        return f'<VerificationRequest {self.title}>'


# -------------------- Utilidades --------------------
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def role_required(*roles):
    def decorator(f):
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Debes iniciar sesión primero.', 'warning')
                return redirect(url_for('login'))
            if current_user.role not in roles:
                flash('No tienes permiso para acceder a esta sección.', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        wrapped.__name__ = f.__name__
        return wrapped
    return decorator


# -------------------- Rutas públicas --------------------
@app.route('/')
def index():
    noticias = News.query.filter_by(status='published').order_by(News.created_at.desc()).all()
    return render_template('index.html', noticias=noticias)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password) and user.is_active:
            login_user(user)
            flash(f'Bienvenido de nuevo, {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        flash('Credenciales incorrectas o cuenta desactivada.', 'danger')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    user_count = User.query.count()
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        if not username or not email or not password:
            flash('Todos los campos son obligatorios.', 'danger')
            return render_template('register.html')
        if User.query.filter_by(email=email).first():
            flash('Ya existe un usuario con ese correo.', 'danger')
            return render_template('register.html')
        if User.query.filter_by(username=username).first():
            flash('Ese nombre de usuario ya está tomado.', 'danger')
            return render_template('register.html')

        # El primer usuario es creador
        if user_count == 0:
            role = 'creator'
        else:
            role = 'user'

        nuevo = User(username=username, email=email, role=role)
        nuevo.set_password(password)
        db.session.add(nuevo)
        db.session.commit()
        flash(f'Registro exitoso. Rol asignado: {role}.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', first_user=(user_count == 0))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Sesión cerrada correctamente.', 'info')
    return redirect(url_for('index'))


# -------------------- Dashboard --------------------
@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_creator():
        return redirect(url_for('admin_panel'))
    if current_user.is_administrador():
        return redirect(url_for('admin_panel'))
    if current_user.is_calificador():
        return redirect(url_for('calificador_panel'))
    return redirect(url_for('user_panel'))


@app.route('/panel')
@login_required
def user_panel():
    mis_solicitudes = VerificationRequest.query.filter_by(
        requester_id=current_user.id
    ).order_by(VerificationRequest.created_at.desc()).all()
    return render_template('dashboard.html', solicitudes=mis_solicitudes)


# -------------------- Panel Calificador --------------------
@app.route('/calificador')
@login_required
@role_required('creator', 'administrador', 'calificador')
def calificador_panel():
    noticias_no_verificadas = News.query.filter(
        News.status == 'published',
        News.veracity_level.is_(None)
    ).order_by(News.created_at.desc()).all()

    solicitudes_pendientes = VerificationRequest.query.filter_by(
        status='pending'
    ).order_by(VerificationRequest.created_at.desc()).all()

    return render_template('calificador.html',
                           noticias=noticias_no_verificadas,
                           solicitudes=solicitudes_pendientes)


# -------------------- Panel Administración --------------------
@app.route('/admin')
@login_required
@role_required('creator', 'administrador')
def admin_panel():
    usuarios = User.query.order_by(User.created_at.desc()).all()
    solicitudes = VerificationRequest.query.order_by(
        VerificationRequest.created_at.desc()
    ).all()
    noticias = News.query.order_by(News.created_at.desc()).all()
    return render_template('admin.html',
                           usuarios=usuarios,
                           solicitudes=solicitudes,
                           noticias=noticias)


# -------------------- Noticias --------------------
@app.route('/news/create', methods=['GET', 'POST'])
@login_required
@role_required('creator', 'administrador', 'calificador')
def create_news():
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        if not title or not content:
            flash('Título y contenido son obligatorios.', 'danger')
            return render_template('create_news.html')

        image_url = None
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                unique_name = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_name))
                image_url = f"uploads/{unique_name}"

        noticia = News(
            title=title,
            content=content,
            image_url=image_url,
            author_id=current_user.id,
            status='published'
        )
        db.session.add(noticia)
        db.session.commit()
        flash('Noticia publicada correctamente.', 'success')
        return redirect(url_for('news_detail', news_id=noticia.id))
    return render_template('create_news.html')


@app.route('/news/<int:news_id>')
def news_detail(news_id):
    noticia = News.query.get_or_404(news_id)
    puede_calificar = (
        current_user.is_authenticated and
        current_user.is_calificador() and
        not noticia.veracity_level
    )
    return render_template('news_detail.html', noticia=noticia, puede_calificar=puede_calificar)


@app.route('/news/<int:news_id>/calificar', methods=['GET', 'POST'])
@login_required
@role_required('creator', 'administrador', 'calificador')
def calificar_noticia(news_id):
    noticia = News.query.get_or_404(news_id)

    if noticia.veracity_level:
        flash('Esta noticia ya tiene una calificación de veracidad.', 'warning')
        return redirect(url_for('news_detail', news_id=news_id))

    if request.method == 'POST':
        nivel = request.form.get('veracity_level')
        nota = request.form.get('veracity_note', '').strip()

        niveles_validos = ('falsa', 'verdadera', 'parcialmente_correcta', 'parcialmente_incorrecta')
        if nivel not in niveles_validos:
            flash('Nivel de veracidad no válido.', 'danger')
            return redirect(url_for('calificar_noticia', news_id=news_id))

        noticia.veracity_level = nivel
        noticia.veracity_note = nota
        noticia.verified_by = current_user.id
        noticia.verified_at = datetime.utcnow()
        db.session.commit()
        flash(f'Noticia calificada como: {nivel.replace("_", " ").title()}.', 'success')
        return redirect(url_for('news_detail', news_id=news_id))

    return render_template('calificar_noticia.html', noticia=noticia)


@app.route('/news/<int:news_id>/delete', methods=['POST'])
@login_required
@role_required('creator', 'administrador')
def delete_news(news_id):
    noticia = News.query.get_or_404(news_id)
    db.session.delete(noticia)
    db.session.commit()
    flash('Noticia eliminada correctamente.', 'success')
    return redirect(url_for('admin_panel'))


# -------------------- Solicitudes de verificación --------------------
@app.route('/request-verification', methods=['GET', 'POST'])
@login_required
def request_verification():
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        if not title or not content:
            flash('Título y contenido son obligatorios.', 'danger')
            return render_template('verification_request.html')

        image_url = None
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                unique_name = f"req_{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_name))
                image_url = f"uploads/{unique_name}"

        solicitud = VerificationRequest(
            title=title,
            content=content,
            image_url=image_url,
            requester_id=current_user.id,
            status='pending'
        )
        db.session.add(solicitud)
        db.session.commit()
        flash('Solicitud de verificación enviada. Un experto la revisará pronto.', 'success')
        return redirect(url_for('user_panel'))
    return render_template('verification_request.html')


@app.route('/request/<int:req_id>/review-page', methods=['GET', 'POST'])
@login_required
@role_required('creator', 'administrador', 'calificador')
def request_review_page(req_id):
    solicitud = VerificationRequest.query.get_or_404(req_id)

    if request.method == 'POST':
        decision = request.form.get('decision')
        respuesta = request.form.get('admin_response', '').strip()

        if decision not in ('approved', 'rejected'):
            flash('Decisión no válida.', 'danger')
            return redirect(url_for('calificador_panel'))

        solicitud.status = decision
        solicitud.reviewed_by = current_user.id
        solicitud.reviewed_at = datetime.utcnow()
        solicitud.admin_response = respuesta

        # Si se aprueba, se publica automáticamente como noticia
        if decision == 'approved':
            nueva_noticia = News(
                title=solicitud.title,
                content=solicitud.content,
                image_url=solicitud.image_url,
                author_id=solicitud.requester_id,
                status='published'
            )
            db.session.add(nueva_noticia)
            flash('Solicitud aprobada y publicada como noticia.', 'success')
        else:
            flash('Solicitud rechazada.', 'info')

        db.session.commit()
        return redirect(url_for('calificador_panel'))

    return render_template('request_review.html', solicitud=solicitud)


# -------------------- Gestión de usuarios (Admin) --------------------
@app.route('/admin/user/<int:user_id>/role', methods=['POST'])
@login_required
@role_required('creator', 'administrador')
def change_user_role(user_id):
    usuario = User.query.get_or_404(user_id)
    nuevo_rol = request.form.get('role')

    roles_validos = ('user', 'calificador', 'administrador', 'creator')
    if nuevo_rol not in roles_validos:
        flash('Rol no válido.', 'danger')
        return redirect(url_for('admin_panel'))

    # No permitir quitarse el rol de creator a sí mismo
    if usuario.id == current_user.id and nuevo_rol != 'creator':
        flash('No puedes quitarte tu propio rol de creador.', 'danger')
        return redirect(url_for('admin_panel'))

    usuario.role = nuevo_rol
    db.session.commit()
    flash(f'Rol de {usuario.username} actualizado a {nuevo_rol}.', 'success')
    return redirect(url_for('admin_panel'))


@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@login_required
@role_required('creator', 'administrador', 'calificador')