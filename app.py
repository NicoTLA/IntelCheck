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
app.config['MAX_CONTENT_LENGTH'] = 8 * 1024 * 1024

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Debes iniciar sesión para acceder a esta página.'
login_manager.login_message_category = 'warning'

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
    role = db.Column(db.String(20), default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

    # Relaciones con foreign_keys explícitos para evitar errores
    news = db.relationship('News', backref='author', lazy=True, foreign_keys='News.author_id')
    requests = db.relationship('VerificationRequest', backref='requester', lazy=True, foreign_keys='VerificationRequest.requester_id')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_creator(self):
        return self.role == 'creator'

    def is_calibrador(self):
        return self.role in ('calibrador', 'creator')

    def is_user(self):
        return self.role == 'user'

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
    veracity_level = db.Column(db.String(20), nullable=True)
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
    status = db.Column(db.String(20), default='pending')
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


# -------------------- Rutas --------------------
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
        role = 'creator' if user_count == 0 else 'user'
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


@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_creator():
        return redirect(url_for('admin_panel'))
    if current_user.is_calibrador():
        return redirect(url_for('calibrador_panel'))
    return redirect(url_for('user_panel'))


@app.route('/panel')
@login_required
def user_panel():
    mis_solicitudes = VerificationRequest.query.filter_by(
        requester_id=current_user.id
    ).order_by(VerificationRequest.created_at.desc()).all()
    return render_template('dashboard.html', solicitudes=mis_solicitudes)


@app.route('/calibrador')
@login_required
@role_required('creator', 'calibrador')
def calibrador_panel():
    noticias_no_verificadas = News.query.filter(
        News.status == 'published',
        News.veracity_level.is_(None)
    ).order_by(News.created_at.desc()).all()
    solicitudes_pendientes = VerificationRequest.query.filter_by(
        status='pending'
    ).order_by(VerificationRequest.created_at.desc()).all()
    return render_template('calibrador.html',
                           noticias=noticias_no_verificadas,
                           solicitudes=solicitudes_pendientes)


@app.route('/admin')
@login_required
@role_required('creator')
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


@app.route('/news/create', methods=['GET', 'POST'])
@login_required
@role_required('creator', 'calibrador')
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
    return render_template('news_detail.html', noticia=noticia)


@app.route('/news/<int:news_id>/verify', methods=['POST'])
@login_required
@role_required('creator', 'calibrador')
def verify_news(news_id):
    noticia = News.query.get_or_404(news_id)
    nivel = request.form.get('veracity_level')
    nota = request.form.get('veracity_note', '').strip()
    if nivel not in ('alta', 'media', 'baja', 'falsa'):
        flash('Nivel de veracidad no válido.', 'danger')
        return redirect(url_for('news_detail', news_id=news_id))
    noticia.veracity_level = nivel
    noticia.veracity_note = nota
    noticia.verified_by = current_user.id
    noticia.verified_at = datetime.utcnow()
    db.session.commit()
    flash(f'Noticia calificada como: {nivel}.', 'success')
    return redirect(url_for('news_detail', news_id=news_id))


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
@role_required('creator', 'calibrador')
def request_review_page(req_id):
    solicitud = VerificationRequest.query.get_or_404(req_id)
    if request.method == 'POST':
        decision = request.form.get('decision')
        respuesta = request.form.get('admin_response', '').strip()
        if decision not in ('approved', 'rejected'):
            flash('Decisión no válida.', 'danger')
            return redirect(url_for('calibrador_panel'))
        solicitud.status = decision
        solicitud.reviewed_by = current_user.id
        solicitud.reviewed_at = datetime.utcnow()
        solicitud.admin_response = respuesta
        db.session.commit()
        flash(f'Solicitud {decision} correctamente.', 'success')
        return redirect(url_for('calibrador_panel'))
    return render_template('request_review.html', solicitud=solicitud)


@app.route('/admin/user/<int:user_id>/role', methods=['POST'])
@login_required
@role_required('creator')
def change_user_role(user_id):
    usuario = User.query.get_or_404(user_id)
    nuevo_rol = request.form.get('role')
    if nuevo_rol not in ('user', 'calibrador', 'creator'):
        flash('Rol no válido.', 'danger')
        return redirect(url_for('admin_panel'))
    if usuario.id == current_user.id and nuevo_rol != 'creator':
        flash('No puedes quitarte tu propio rol de creador.', 'danger')
        return redirect(url_for('admin_panel'))
    usuario.role = nuevo_rol
    db.session.commit()
    flash(f'Rol de {usuario.username} actualizado a {nuevo_rol}.', 'success')
    return redirect(url_for('admin_panel'))


@app.route('/admin/user/<int:user_id>/toggle', methods=['POST'])
@login_required
@role_required('creator')
def toggle_user(user_id):
    usuario = User.query.get_or_404(user_id)
    if usuario.id == current_user.id:
        flash('No puedes desactivar tu propia cuenta.', 'danger')
        return redirect(url_for('admin_panel'))
    usuario.is_active = not usuario.is_active
    db.session.commit()
    estado = 'activada' if usuario.is_active else 'desactivada'
    flash(f'Usuario {usuario.username} {estado}.', 'success')
    return redirect(url_for('admin_panel'))


# -------------------- IA integrada --------------------
@app.route('/ai-chat', methods=['GET', 'POST'])
@login_required
def ai_chat():
    historial = session.get('ai_historial', [])
    if request.method == 'POST':
        mensaje = request.form.get('mensaje', '').strip()
        if not mensaje:
            flash('Escribe un mensaje.', 'danger')
            return redirect(url_for('ai_chat'))
        respuesta_ia = generar_respuesta_ia(mensaje, current_user)
        historial.append({'usuario': mensaje, 'ia': respuesta_ia})
        session['ai_historial'] = historial
        return redirect(url_for('ai_chat'))
    return render_template('ai_chat.html', historial=historial)


@app.route('/ai-clear', methods=['POST'])
@login_required
def ai_clear():
    session.pop('ai_historial', None)
    flash('Historial de la IA borrado.', 'info')
    return redirect(url_for('ai_chat'))


def generar_respuesta_ia(mensaje, user):
    texto = mensaje.lower()
    if any(palabra in texto for palabra in ['hola', 'buenos', 'buenas', 'hey']):
        return f"Hola {user.username}. Soy el asistente de IntelCheck. ¿En qué puedo ayudarte hoy?"
    if 'veracidad' in texto or 'calificar' in texto:
        return ("Los calificadores evalúan las noticias con niveles: alta, media, baja o falsa. "
                "Solo los usuarios con rol de calificador o creador pueden asignar una calificación.")
    if 'solicitud' in texto or 'verificar' in texto:
        return ("Puedes enviar una solicitud de verificación desde tu panel. "
                "Adjunta el artículo (y opcionalmente una imagen) y un experto la revisará.")
    if 'rol' in texto or 'permisos' in texto:
        return ("Hay tres roles: Creador (acceso total), Calificador (publica y verifica) y Usuario (lee y consulta IA).")
    if 'noticia' in texto:
        return ("Las noticias publicadas aparecen en el feed principal. "
                "Si tienes dudas sobre alguna, usa el chat o solicita su verificación.")
    return ("Entiendo tu consulta. Como este es un prototipo, mi conocimiento es limitado. "
            "Si necesitas ayuda específica, contacta al creador de la plataforma o publica tu duda en el feed.")


# -------------------- Archivos subidos --------------------
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


# -------------------- Inicio --------------------
def crear_carpetas():
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


crear_carpetas()
with app.app_context():
    db.create_all()
    if User.query.count() == 0:
        print("\n" + "=" * 60)
        print("  No hay usuarios en la base de datos.")
        print("  Regístrate en http://127.0.0.1:5000/register")
        print("  El primer usuario creado será el CREADOR del sistema.")
        print("=" * 60 + "\n")


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))