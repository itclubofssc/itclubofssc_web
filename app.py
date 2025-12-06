import os
import sqlite3
import functools
from datetime import datetime
from flask import Flask, redirect, render_template, request, g, url_for, flash, session, abort
import bcrypt
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from flask import url_for

load_dotenv()

app = Flask(__name__)

app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))

app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')  # used to build URL path (e.g. /static/uploads/...)
app.config['UPLOAD_PATH'] = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'])  # absolute filesystem path
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['DATABASE'] = os.path.join(app.instance_path, 'database.db')

os.makedirs(app.config['UPLOAD_PATH'], exist_ok=True)
os.makedirs(app.instance_path, exist_ok=True)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'mp4', 'mov'}
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename, file_type='image'):
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    if file_type == 'image':
        return ext in ALLOWED_IMAGE_EXTENSIONS
    return ext in ALLOWED_EXTENSIONS

def save_file(file_storage, file_type='image'):
    if not file_storage or file_storage.filename == '':
        return None
    
    if not allowed_file(file_storage.filename, file_type):
        return None
    
    filename = secure_filename(file_storage.filename)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    unique_filename = f"{timestamp}_{filename}"
    
    # filesystem destination (absolute)
    fs_dest = os.path.join(app.config['UPLOAD_PATH'], unique_filename)
    try:
        file_storage.save(fs_dest)
    except:
        # fail silently and return None if save fails
        return None
    # return a URL-style path (starts with '/') so templates can show it directly
    url_path = '/' + os.path.join(app.config['UPLOAD_FOLDER'], unique_filename).replace('\\', '/')
    return url_path

def get_fs_path(url_path):
    """Convert stored URL-path (like '/static/uploads/xxx') to absolute filesystem path."""
    if not url_path:
        return None
    return os.path.join(app.root_path, url_path.lstrip('/'))

def delete_file(url_path):
    """Safely delete a stored file given its URL path (may be None)."""
    fs = get_fs_path(url_path)
    if fs and os.path.exists(fs):
        try:
            os.remove(fs)
        except:
            pass

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def hash_password(plain_password):
    if not plain_password:
        return None
    return bcrypt.hashpw(plain_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password(plain_password, hashed):
    if not plain_password or not hashed:
        return False
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed.encode('utf-8'))
    except:
        return False

def init_db():
    db = sqlite3.connect(app.config['DATABASE'])
    cursor = db.cursor()
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS members (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT NOT NULL,
        class_name TEXT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        phone_number TEXT,
        telegram_username TEXT,
        department TEXT,
        profile_picture TEXT,
        status TEXT DEFAULT 'active',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS courses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        time TEXT,
        category TEXT,
        teacher TEXT,
        description TEXT,
        course_video TEXT,
        course_material TEXT,
        thumbnail TEXT,
        is_featured INTEGER DEFAULT 0,
        status TEXT DEFAULT 'active',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT NOT NULL,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    # Ensure 'profile_picture' column exists in admins (safe migration for existing DBs)
    cursor.execute("PRAGMA table_info(admins)")
    admin_cols = [row[1] for row in cursor.fetchall()]
    if 'profile_picture' not in admin_cols:
        try:
            cursor.execute("ALTER TABLE admins ADD COLUMN profile_picture TEXT")
        except Exception:
            # ignore if migration fails for any reason
            pass

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS announcements (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        author_id INTEGER,
        is_public INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (author_id) REFERENCES admins (id)
    )
    ''')

    # Ensure 'poster' column exists in announcements (safe migration for existing DBs)
    cursor.execute("PRAGMA table_info(announcements)")
    cols = [row[1] for row in cursor.fetchall()]
    if 'poster' not in cols:
        try:
            cursor.execute("ALTER TABLE announcements ADD COLUMN poster TEXT")
        except:
            pass

    cursor.execute('SELECT COUNT(*) FROM admins')
    count = cursor.fetchone()[0]
    
    if count == 0:
        hashed_super = hash_password('admin123')
        cursor.execute('''
            INSERT INTO admins (full_name, username, email, password, role)
            VALUES (?, ?, ?, ?, ?)
        ''', ('Super Admin', 'superadmin', 'admin@example.com', hashed_super, 'super_admin'))
        
        hashed_admin = hash_password('admin')
        cursor.execute('''
            INSERT INTO admins (full_name, username, email, password, role)
            VALUES (?, ?, ?, ?, ?)
        ''', ('System Admin', 'admin', 'admin@gmail.com', hashed_admin, 'admin'))
    
    db.commit()
    db.close()

def admin_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if 'admin_id' not in session:
            flash('Admin login required.', 'error')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated

def super_admin_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if 'admin_id' not in session or session.get('admin_role') != 'super_admin':
            flash('Super admin access required.', 'error')
            return redirect(url_for('admin_dashboard'))
        return f(*args, **kwargs)
    return decorated

def login_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if 'member_id' not in session:
            flash('Please login first.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# Add helpers near top (after imports)
def row_to_dict(row):
	"""Convert sqlite3.Row to dict (safe if row is None)."""
	if row is None:
		return None
	try:
		# sqlite3.Row supports keys()
		return {k: row[k] for k in row.keys()}
	except Exception:
		# fallback
		try:
			return dict(row)
		except Exception:
			return row

def resolve_media_path(val):
	"""Return a usable src for templates.
	- If val is None/empty -> None
	- If val looks like an absolute URL or starts with '/' -> return as-is
	- Otherwise treat as a static filename and return url_for('static', filename=val)
	"""
	if not val:
		return None
	val = str(val)
	if val.startswith('http://') or val.startswith('https://') or val.startswith('/'):
		return val
	# treat as path relative to static/
	return url_for('static', filename=val)

# ========================= USER ROUTES ======================

@app.route('/')
def index():
    return redirect('/home')

@app.route('/home')
def home():
    db = get_db()
    rows = db.execute('''
        SELECT a.*, ad.full_name as author_name
        FROM announcements a
        LEFT JOIN admins ad ON a.author_id = ad.id
        WHERE a.is_public = 1
        ORDER BY a.created_at DESC
        LIMIT 5
    ''').fetchall()

    announcements = []
    for r in rows:
        d = row_to_dict(r)
        if not d:
            continue
        # resolve poster so template can use it directly
        d['poster'] = resolve_media_path(d.get('poster'))
        # ensure author_name exists
        if not d.get('author_name'):
            author = db.execute('SELECT full_name FROM admins WHERE id = ?', (d.get('author_id'),)).fetchone()
            d['author_name'] = author['full_name'] if author else 'IT Club Admin'
        announcements.append(d)

    return render_template('main/index.html', announcements=announcements)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form.get('full_name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        class_name = request.form.get('class_name')
        phone_number = request.form.get('phone_number')
        
        if not full_name or not email or not password:
            flash('All fields are required.', 'error')
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('register'))
        
        db = get_db()
        existing = db.execute('SELECT id FROM members WHERE email = ?', (email,)).fetchone()
        if existing:
            flash('Email already registered.', 'error')
            return redirect(url_for('register'))
        
        password_hash = hash_password(password)
        db.execute('''
            INSERT INTO members (full_name, email, password, class_name, phone_number, status)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (full_name, email, password_hash, class_name, phone_number, 'active'))
        db.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('main/register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not email or not password:
            flash('Email and password are required.', 'error')
            return redirect(url_for('login'))
        
        db = get_db()
        member = db.execute('SELECT * FROM members WHERE email = ?', (email,)).fetchone()
        
        if not member:
            flash('Invalid email or password.', 'error')
            return redirect(url_for('login'))
        
        if not check_password(password, member['password']):
            flash('Invalid email or password.', 'error')
            return redirect(url_for('login'))
        
        db.execute('UPDATE members SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (member['id'],))
        db.commit()
        
        session['member_id'] = member['id']
        session['member_name'] = member['full_name']
        session['member_email'] = member['email']
        
        flash('Login successful!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('main/login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    member_id = session['member_id']
    
    member = db.execute('SELECT * FROM members WHERE id = ?', (member_id,)).fetchone()
    courses = db.execute('SELECT * FROM courses WHERE status = "active" ORDER BY created_at DESC LIMIT 6').fetchall()
    
    announcements = db.execute('''
        SELECT * FROM announcements 
        WHERE is_public = 1 
        ORDER BY created_at DESC LIMIT 5
    ''').fetchall()
    
    return render_template('main/dashboard.html', 
                          member=member, 
                          courses=courses,
                          announcements=announcements)

@app.route('/courses')
def courses():
    db = get_db()
    category = request.args.get('category')
    search = request.args.get('search')
    
    query = 'SELECT * FROM courses WHERE status = "active"'
    params = []
    
    if category:
        query += ' AND category = ?'
        params.append(category)
    
    if search:
        query += ' AND (title LIKE ? OR description LIKE ? OR teacher LIKE ?)'
        search_term = f'%{search}%'
        params.extend([search_term, search_term, search_term])
    
    query += ' ORDER BY created_at DESC'
    courses_list = db.execute(query, params).fetchall()
    
    categories = db.execute('SELECT DISTINCT category FROM courses WHERE category IS NOT NULL').fetchall()
    
    return render_template('main/courses.html', 
                          courses=courses_list, 
                          categories=categories,
                          selected_category=category,
                          search_query=search)

@app.route('/courses/details/<int:course_id>')
@login_required
def course_details(course_id):
    db = get_db()
    
    course = db.execute('SELECT * FROM courses WHERE id = ?', (course_id,)).fetchone()
    if not course:
        flash('Course not found.', 'error')
        return redirect(url_for('courses'))
    
    return render_template('main/course-detail.html', course=course)

@app.route('/announcements')
def announcements():
    return redirect(url_for('home') + '#announcements')

@app.route('/profile')
@login_required
def profile():
    db = get_db()
    member_id = session['member_id']
    
    member = db.execute('SELECT * FROM members WHERE id = ?', (member_id,)).fetchone()
    if not member:
        session.clear()
        return redirect(url_for('login'))
    
    return render_template('main/profile.html', member=member)

@app.route('/profile/update', methods=['GET', 'POST'])
@login_required
def profile_update():
    db = get_db()
    member_id = session['member_id']
    
    if request.method == 'POST':
        full_name = request.form.get('full_name')
        class_name = request.form.get('class_name')
        phone_number = request.form.get('phone_number')
        telegram_username = request.form.get('telegram_username')
        department = request.form.get('department')
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        profile_file = request.files.get('profile_picture')
        
        if not full_name:
            flash('Full name is required.', 'error')
            return redirect(url_for('profile_update'))
        
        member = db.execute('SELECT * FROM members WHERE id = ?', (member_id,)).fetchone()
        
        update_fields = []
        params = []
        
        if full_name != member['full_name']:
            update_fields.append('full_name = ?')
            params.append(full_name)
            session['member_name'] = full_name
        
        if class_name != member['class_name']:
            update_fields.append('class_name = ?')
            params.append(class_name)
        
        if phone_number != member['phone_number']:
            update_fields.append('phone_number = ?')
            params.append(phone_number)
        
        if telegram_username != member['telegram_username']:
            update_fields.append('telegram_username = ?')
            params.append(telegram_username)
        
        if department != member['department']:
            update_fields.append('department = ?')
            params.append(department)
        
        if new_password:
            if not current_password:
                flash('Current password is required to change password.', 'error')
                return redirect(url_for('profile_update'))
            
            if not check_password(current_password, member['password']):
                flash('Current password is incorrect.', 'error')
                return redirect(url_for('profile_update'))
            
            if new_password != confirm_password:
                flash('New passwords do not match.', 'error')
                return redirect(url_for('profile_update'))
            
            new_password_hash = hash_password(new_password)
            update_fields.append('password = ?')
            params.append(new_password_hash)
        
        profile_path = save_file(profile_file, 'image')
        if profile_path:
            old_picture = member['profile_picture']
            if old_picture:
                delete_file(old_picture)
            update_fields.append('profile_picture = ?')
            params.append(profile_path)
        
        if update_fields:
            params.append(member_id)
            query = f'UPDATE members SET {", ".join(update_fields)} WHERE id = ?'
            db.execute(query, params)
            db.commit()
            flash('Profile updated successfully!', 'success')
        else:
            flash('No changes made.', 'info')
        
        return redirect(url_for('profile'))
    
    member = db.execute('SELECT * FROM members WHERE id = ?', (member_id,)).fetchone()
    return render_template('main/profile-setting.html', member=member)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))



# ======================== ADMIN ROUTES =========================

@app.route('/admin')
def admin():
    return redirect(url_for('admin_login'))

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if 'admin_id' in session:
        return redirect(url_for('admin_dashboard'))
    
    if request.method == 'POST':
        identifier = request.form.get('identifier')
        password = request.form.get('password')
        
        if not identifier or not password:
            flash('Username/Email and password are required.', 'error')
            return redirect(url_for('admin_login'))
        
        db = get_db()
        admin = db.execute('SELECT * FROM admins WHERE username = ? OR email = ?', (identifier, identifier)).fetchone()
        
        if not admin:
            flash('Invalid credentials.', 'error')
            return redirect(url_for('admin_login'))
        
        if not check_password(password, admin['password']):
            flash('Invalid credentials.', 'error')
            return redirect(url_for('admin_login'))
        
        session['admin_id'] = admin['id']
        session['admin_username'] = admin['username']
        session['admin_role'] = admin['role']
        session['admin_name'] = admin['full_name']
        
        flash(f'Welcome back, {admin["full_name"]}!', 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('admin/login.html')

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    db = get_db()
    
    stats = {}
    stats['total_members'] = db.execute('SELECT COUNT(*) FROM members').fetchone()[0]
    stats['total_courses'] = db.execute('SELECT COUNT(*) FROM courses').fetchone()[0]
    stats['active_members'] = db.execute('SELECT COUNT(*) FROM members WHERE status = "active"').fetchone()[0]
    stats['featured_courses'] = db.execute('SELECT COUNT(*) FROM courses WHERE is_featured = 1').fetchone()[0]
    
    recent_members_rows = db.execute('SELECT * FROM members ORDER BY created_at DESC LIMIT 5').fetchall()
    recent_courses_rows = db.execute('SELECT * FROM courses ORDER BY created_at DESC LIMIT 5').fetchall()
    # normalize lists
    recent_members = []
    for r in recent_members_rows:
        d = row_to_dict(r)
        if d:
            d['profile_picture'] = resolve_media_path(d.get('profile_picture'))
        recent_members.append(d)
    recent_courses = []
    for r in recent_courses_rows:
        d = row_to_dict(r)
        if d:
            d['thumbnail'] = resolve_media_path(d.get('thumbnail'))
        recent_courses.append(d)
    
    return render_template('admin/dashboard.html', 
                          stats=stats, 
                          recent_members=recent_members,
                          recent_courses=recent_courses)



# ==================== MEMBERS MANAGEMENT ==========================

@app.route('/admin/members')
@admin_required
def admin_members():
    db = get_db()
    status = request.args.get('status')
    
    query = 'SELECT * FROM members WHERE 1=1'
    params = []
    
    if status and status != 'all':
        query += ' AND status = ?'
        params.append(status)
    
    query += ' ORDER BY created_at DESC'
    rows = db.execute(query, params).fetchall()
    # convert rows -> dicts and resolve profile images
    members = []
    for r in rows:
        d = row_to_dict(r)
        if d:
            d['profile_picture'] = resolve_media_path(d.get('profile_picture'))
        members.append(d)
    
    return render_template('admin/members.html', members=members, status=status)

@app.route('/admin/members/add', methods=['GET', 'POST'])
@admin_required
def add_members():
    if request.method == 'POST':
        full_name = request.form.get('full_name')
        class_name = request.form.get('class_name')
        email = request.form.get('email')
        password = request.form.get('password')
        phone_number = request.form.get('phone_number')
        telegram_username = request.form.get('telegram_username')
        department = request.form.get('department')
        status = request.form.get('status', 'active')
        profile_file = request.files.get('profile_picture')
        
        if not full_name or not email or not password:
            flash('Full name, email and password are required.', 'error')
            return redirect(url_for('add_members'))
        
        db = get_db()
        existing = db.execute('SELECT id FROM members WHERE email = ?', (email,)).fetchone()
        if existing:
            flash('Email already exists.', 'error')
            return redirect(url_for('add_members'))
        
        password_hash = hash_password(password)
        profile_path = save_file(profile_file, 'image')
        
        db.execute('''
            INSERT INTO members 
            (full_name, class_name, email, password, phone_number, telegram_username, department, profile_picture, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (full_name, class_name, email, password_hash, phone_number, telegram_username, department, profile_path, status))
        db.commit()
        
        flash('Member added successfully!', 'success')
        return redirect(url_for('admin_members'))
    
    return render_template('admin/add_members.html')

@app.route('/admin/members/edit/<int:member_id>', methods=['GET', 'POST'])
@admin_required
def edit_members(member_id):
    db = get_db()
    member = db.execute('SELECT * FROM members WHERE id = ?', (member_id,)).fetchone()
    
    if not member:
        flash('Member not found.', 'error')
        return redirect(url_for('admin_members'))
    
    if request.method == 'POST':
        full_name = request.form.get('full_name')
        class_name = request.form.get('class_name')
        email = request.form.get('email')
        phone_number = request.form.get('phone_number')
        telegram_username = request.form.get('telegram_username')
        department = request.form.get('department')
        status = request.form.get('status')
        reset_password = request.form.get('reset_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        profile_file = request.files.get('profile_picture')
        
        if not full_name or not email:
            flash('Full name and email are required.', 'error')
            return redirect(url_for('edit_members', member_id=member_id))
        
        if email != member['email']:
            existing = db.execute('SELECT id FROM members WHERE email = ? AND id != ?', (email, member_id)).fetchone()
            if existing:
                flash('Email already exists.', 'error')
                return redirect(url_for('edit_members', member_id=member_id))
        
        profile_path = save_file(profile_file, 'image')
        
        update_fields = []
        params = []
        
        if full_name != member['full_name']:
            update_fields.append('full_name = ?')
            params.append(full_name)
        
        if class_name != member['class_name']:
            update_fields.append('class_name = ?')
            params.append(class_name)
        
        if email != member['email']:
            update_fields.append('email = ?')
            params.append(email)
        
        if phone_number != member['phone_number']:
            update_fields.append('phone_number = ?')
            params.append(phone_number)
        
        if telegram_username != member['telegram_username']:
            update_fields.append('telegram_username = ?')
            params.append(telegram_username)
        
        if department != member['department']:
            update_fields.append('department = ?')
            params.append(department)
        
        if status != member['status']:
            update_fields.append('status = ?')
            params.append(status)
        
        # checkbox now named "reset_password" in template (value '1' when checked)
        reset_password = request.form.get('reset_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # handle password reset explicitly and validate
        if reset_password:
            if not new_password:
                flash("New password is required to reset member's password.", 'error')
                return redirect(url_for('edit_members', member_id=member_id))
            if len(new_password) < 6:
                flash('New password must be at least 6 characters.', 'error')
                return redirect(url_for('edit_members', member_id=member_id))
            if new_password != (confirm_password or ''):
                flash('New password and confirmation do not match.', 'error')
                return redirect(url_for('edit_members', member_id=member_id))
            password_hash = hash_password(new_password)
            update_fields.append('password = ?')
            params.append(password_hash)
        
        if profile_path:
            old_picture = member['profile_picture']
            if old_picture:
                delete_file(old_picture)
            update_fields.append('profile_picture = ?')
            params.append(profile_path)
        
        if update_fields:
            params.append(member_id)
            query = f'UPDATE members SET {", ".join(update_fields)} WHERE id = ?'
            db.execute(query, params)
            db.commit()
            flash('Member updated successfully!', 'success')
        
        return redirect(url_for('admin_members'))
    
    return render_template('admin/edit_members.html', member=member)

@app.route('/admin/members/delete/<int:member_id>', methods=['POST'])
@admin_required
def delete_member(member_id):
    db = get_db()
    
    member = db.execute('SELECT * FROM members WHERE id = ?', (member_id,)).fetchone()
    if not member:
        flash('Member not found.', 'error')
        return redirect(url_for('admin_members'))
    
    profile_picture = member['profile_picture']
    if profile_picture:
        delete_file(profile_picture)
    
    db.execute('DELETE FROM members WHERE id = ?', (member_id,))
    db.commit()
    
    flash('Member deleted successfully!', 'success')
    return redirect(url_for('admin_members'))

@app.route('/admin/members/view/<int:member_id>')
@admin_required
def view_member(member_id):
    db = get_db()
    
    member_row = db.execute('SELECT * FROM members WHERE id = ?', (member_id,)).fetchone()
    member = row_to_dict(member_row)
    if member:
        member['profile_picture'] = resolve_media_path(member.get('profile_picture'))
        member.setdefault('full_name', '')
        member.setdefault('created_at', None)
    return render_template('admin/view_member.html', member=member)



# ======================= COURSE MANAGEMENT ========================

@app.route('/admin/courses')
@admin_required
def admin_courses():
    db = get_db()
    category = request.args.get('category')
    status = request.args.get('status')
    
    query = 'SELECT * FROM courses WHERE 1=1'
    params = []
    
    if category and category != 'all':
        query += ' AND category = ?'
        params.append(category)
    
    if status and status != 'all':
        query += ' AND status = ?'
        params.append(status)
    
    query += ' ORDER BY created_at DESC'
    rows = db.execute(query, params).fetchall()
    # convert rows -> dicts and resolve thumbnails
    courses_list = []
    for r in rows:
        d = row_to_dict(r)
        if d:
            d['thumbnail'] = resolve_media_path(d.get('thumbnail'))
        courses_list.append(d)
    
    categories = db.execute('SELECT DISTINCT category FROM courses WHERE category IS NOT NULL').fetchall()
    
    return render_template('admin/courses.html', 
                          courses=courses_list, 
                          categories=categories,
                          category=category,
                          status=status)

@app.route('/admin/courses/add', methods=['GET', 'POST'])
@admin_required
def add_courses():
    if request.method == 'POST':
        title = request.form.get('title')
        time = request.form.get('time')
        category = request.form.get('category')
        teacher = request.form.get('teacher')
        description = request.form.get('description')
        course_video = request.form.get('course_video')
        course_material_url = request.form.get('course_material_url')
        course_material_file = request.files.get('course_material_file')
        thumb_file = request.files.get('thumbnail')
        is_featured = request.form.get('is_featured', '0')
        status = request.form.get('status', 'active')
        
        if not title:
            flash('Title is required.', 'error')
            return redirect(url_for('add_courses'))
        
        thumb_path = save_file(thumb_file, 'image')
        
        material_path = None
        if course_material_file:
            material_path = save_file(course_material_file, 'document')
        
        if not material_path and course_material_url:
            material_path = course_material_url
        
        db = get_db()
        db.execute('''
            INSERT INTO courses 
            (title, time, category, teacher, description, course_video, course_material, thumbnail, is_featured, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (title, time, category, teacher, description, course_video, material_path, thumb_path, is_featured, status))
        db.commit()
        
        flash('Course added successfully!', 'success')
        return redirect(url_for('admin_courses'))
    
    return render_template('admin/add_courses.html')

@app.route('/admin/courses/edit/<int:course_id>', methods=['GET', 'POST'])
@admin_required
def edit_courses(course_id):
    db = get_db()
    course = db.execute('SELECT * FROM courses WHERE id = ?', (course_id,)).fetchone()
    
    if not course:
        flash('Course not found.', 'error')
        return redirect(url_for('admin_courses'))
    
    if request.method == 'POST':
        title = request.form.get('title')
        time = request.form.get('time')
        category = request.form.get('category')
        teacher = request.form.get('teacher')
        description = request.form.get('description')
        course_video = request.form.get('course_video')
        course_material_url = request.form.get('course_material_url')
        course_material_file = request.files.get('course_material_file')
        thumb_file = request.files.get('thumbnail')
        is_featured = request.form.get('is_featured', '0')
        status = request.form.get('status')
        
        if not title:
            flash('Title is required.', 'error')
            return redirect(url_for('edit_courses', course_id=course_id))
        
        thumb_path = save_file(thumb_file, 'image')
        
        material_path = course['course_material']
        if course_material_file:
            material_path = save_file(course_material_file, 'document')
        elif course_material_url and course_material_url != course['course_material']:
            material_path = course_material_url
        
        update_fields = []
        params = []
        
        if title != course['title']:
            update_fields.append('title = ?')
            params.append(title)
        
        if time != course['time']:
            update_fields.append('time = ?')
            params.append(time)
        
        if category != course['category']:
            update_fields.append('category = ?')
            params.append(category)
        
        if teacher != course['teacher']:
            update_fields.append('teacher = ?')
            params.append(teacher)
        
        if description != course['description']:
            update_fields.append('description = ?')
            params.append(description)
        
        if course_video != course['course_video']:
            update_fields.append('course_video = ?')
            params.append(course_video)
        
        if material_path != course['course_material']:
            update_fields.append('course_material = ?')
            params.append(material_path)
        
        if thumb_path:
            old_thumbnail = course['thumbnail']
            if old_thumbnail:
                delete_file(old_thumbnail)
            update_fields.append('thumbnail = ?')
            params.append(thumb_path)
        
        if is_featured != str(course['is_featured']):
            update_fields.append('is_featured = ?')
            params.append(is_featured)
        
        if status != course['status']:
            update_fields.append('status = ?')
            params.append(status)
        
        if update_fields:
            params.append(course_id)
            query = f'UPDATE courses SET {", ".join(update_fields)} WHERE id = ?'
            db.execute(query, params)
            db.commit()
            flash('Course updated successfully!', 'success')
        
        return redirect(url_for('admin_courses'))
    
    return render_template('admin/edit_courses.html', course=course)

@app.route('/admin/courses/delete/<int:course_id>', methods=['POST'])
@admin_required
def delete_course(course_id):
    db = get_db()
    
    course = db.execute('SELECT * FROM courses WHERE id = ?', (course_id,)).fetchone()
    if not course:
        flash('Course not found.', 'error')
        return redirect(url_for('admin_courses'))
    
    thumbnail = course['thumbnail']
    if thumbnail:
        delete_file(thumbnail)
    
    course_material = course['course_material']
    # course_material may be a URL or a local stored path; delete only if it's a stored /static/... path
    if course_material and str(course_material).startswith('/' + app.config['UPLOAD_FOLDER'].split(os.sep)[0]):
        delete_file(course_material)
    
    db.execute('DELETE FROM courses WHERE id = ?', (course_id,))
    db.commit()
    
    flash('Course deleted successfully!', 'success')
    return redirect(url_for('admin_courses'))

@app.route('/admin/courses/view/<int:course_id>')
@admin_required
def view_course(course_id):
    db = get_db()
    
    course_row = db.execute('SELECT * FROM courses WHERE id = ?', (course_id,)).fetchone()
    course = row_to_dict(course_row)
    if course:
        # resolve thumbnail and material links if stored as filenames
        course['thumbnail'] = resolve_media_path(course.get('thumbnail'))
        course['course_material'] = resolve_media_path(course.get('course_material'))
        # course_video may be a full URL; leave as-is if it's http, otherwise resolve
        cv = course.get('course_video')
        if cv and not str(cv).startswith('http'):
            course['course_video'] = resolve_media_path(cv)
        # ensure keys exist
        course.setdefault('title', '')
        course.setdefault('created_at', None)
    return render_template('admin/view_course.html', course=course)



# ==================== ANNOUNCEMENTS MANAGEMENT ====================

@app.route('/admin/announcements')
@admin_required
def admin_announcements():
    db = get_db()
    rows = db.execute('''
        SELECT a.*, ad.full_name as author_name 
        FROM announcements a 
        LEFT JOIN admins ad ON a.author_id = ad.id 
        ORDER BY a.created_at DESC
    ''').fetchall()
    announcements_list = []
    for r in rows:
        d = row_to_dict(r)
        if d:
            d['poster'] = resolve_media_path(d.get('poster'))
        announcements_list.append(d)
    
    return render_template('admin/announcements.html', announcements=announcements_list)

@app.route('/admin/announcements/view/<int:announcement_id>')
@admin_required
def view_announcement(announcement_id):
    db = get_db()
    announcement_row = db.execute('SELECT * FROM announcements WHERE id = ?', (announcement_id,)).fetchone()
    announcement = row_to_dict(announcement_row)  # convert row -> dict

    # normalize poster (so template can directly use the resolved URL)
    if announcement:
        announcement['poster'] = resolve_media_path(announcement.get('poster'))
        # populate author_name if available via join (optional)
        if 'author_name' not in announcement:
            # try to fetch author name
            author = db.execute('SELECT full_name FROM admins WHERE id = ?', (announcement.get('author_id'),)).fetchone()
            announcement['author_name'] = author['full_name'] if author else None
        announcement.setdefault('created_at', None)

    return render_template('admin/view_announcement.html', announcement=announcement)

@app.route('/admin/announcements/add', methods=['GET', 'POST'])
@admin_required
def add_announcement():
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        is_public = request.form.get('is_public', '1')
        poster_file = request.files.get('poster')
        poster_path = save_file(poster_file, 'image')
        
        if not title or not content:
            flash('Title and content are required.', 'error')
            return redirect(url_for('add_announcement'))
        
        db = get_db()
        db.execute('''
            INSERT INTO announcements (title, content, author_id, is_public, poster)
            VALUES (?, ?, ?, ?, ?)
        ''', (title, content, session['admin_id'], is_public, poster_path))
        db.commit()
        
        flash('Announcement added successfully!', 'success')
        return redirect(url_for('admin_announcements'))
    
    return render_template('admin/add_announcement.html')

@app.route('/admin/announcements/edit/<int:announcement_id>', methods=['GET', 'POST'])
@admin_required
def edit_announcement(announcement_id):
    db = get_db()
    announcement = db.execute('SELECT * FROM announcements WHERE id = ?', (announcement_id,)).fetchone()

    if not announcement:
        flash('Announcement not found.', 'error')
        return redirect(url_for('admin_announcements'))

    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        is_public = request.form.get('is_public', '1')
        poster_file = request.files.get('poster')
        poster_path = None

        # only attempt save if a file was provided
        if poster_file and getattr(poster_file, 'filename', None):
            poster_path = save_file(poster_file, 'image')

        if not title or not content:
            flash('Title and content are required.', 'error')
            return redirect(url_for('edit_announcement', announcement_id=announcement_id))

        if poster_path:
            # delete previous poster if present
            try:
                old_poster = announcement['poster']
            except Exception:
                old_poster = None
            if old_poster:
                delete_file(old_poster)

            db.execute('''
                UPDATE announcements 
                SET title = ?, content = ?, is_public = ?, poster = ?
                WHERE id = ?
            ''', (title, content, is_public, poster_path, announcement_id))
        else:
            db.execute('''
                UPDATE announcements 
                SET title = ?, content = ?, is_public = ?
                WHERE id = ?
            ''', (title, content, is_public, announcement_id))

        db.commit()

        flash('Announcement updated successfully!', 'success')
        return redirect(url_for('admin_announcements'))

    return render_template('admin/edit_announcement.html', announcement=announcement)

@app.route('/admin/announcements/delete/<int:announcement_id>', methods=['POST'])
@admin_required
def delete_announcement(announcement_id):
    db = get_db()
    
    announcement = db.execute('SELECT * FROM announcements WHERE id = ?', (announcement_id,)).fetchone()
    if not announcement:
        flash('Announcement not found.', 'error')
        return redirect(url_for('admin_announcements'))
    
    # delete poster file if present
    poster = announcement['poster'] if 'poster' in announcement.keys() else None
    if poster:
        delete_file(poster)
    db.execute('DELETE FROM announcements WHERE id = ?', (announcement_id,))
    db.commit()
    
    flash('Announcement deleted successfully!', 'success')
    return redirect(url_for('admin_announcements'))



# ==================== ADMIN MANAGEMENT ====================

@app.route('/admin/admins')
@admin_required
@super_admin_required
def admin_admins():
    db = get_db()
    admins = db.execute('SELECT * FROM admins ORDER BY role, created_at DESC').fetchall()
    return render_template('admin/admins.html', admins=admins)

@app.route('/admin/admins/add', methods=['GET', 'POST'])
@admin_required
@super_admin_required
def add_admin():
    if request.method == 'POST':
        full_name = request.form.get('full_name')
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')
        
        if not all([full_name, username, email, password, role]):
            flash('All fields are required.', 'error')
            return redirect(url_for('add_admin'))
        
        if role not in ['admin', 'super_admin']:
            flash('Invalid role.', 'error')
            return redirect(url_for('add_admin'))
        
        db = get_db()
        existing_username = db.execute('SELECT id FROM admins WHERE username = ?', (username,)).fetchone()
        if existing_username:
            flash('Username already exists.', 'error')
            return redirect(url_for('add_admin'))
        
        existing_email = db.execute('SELECT id FROM admins WHERE email = ?', (email,)).fetchone()
        if existing_email:
            flash('Email already exists.', 'error')
            return redirect(url_for('add_admin'))
        
        password_hash = hash_password(password)
        
        db.execute('''
            INSERT INTO admins (full_name, username, email, password, role)
            VALUES (?, ?, ?, ?, ?)
        ''', (full_name, username, email, password_hash, role))
        db.commit()
        
        flash('Admin added successfully!', 'success')
        return redirect(url_for('admin_admins'))
    
    return render_template('admin/add_admin.html')

@app.route('/admin/admins/edit/<int:admin_id>', methods=['GET', 'POST'])
@admin_required
@super_admin_required
def edit_admin(admin_id):
    db = get_db()
    admin = db.execute('SELECT * FROM admins WHERE id = ?', (admin_id,)).fetchone()
    
    if not admin:
        flash('Admin not found.', 'error')
        return redirect(url_for('admin_admins'))
    
    if request.method == 'POST':
        full_name = request.form.get('full_name')
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')
        
        if not all([full_name, username, email, role]):
            flash('All fields except password are required.', 'error')
            return redirect(url_for('edit_admin', admin_id=admin_id))
        
        if role not in ['admin', 'super_admin']:
            flash('Invalid role.', 'error')
            return redirect(url_for('edit_admin', admin_id=admin_id))
        
        if username != admin['username']:
            existing = db.execute('SELECT id FROM admins WHERE username = ? AND id != ?', 
                                 (username, admin_id)).fetchone()
            if existing:
                flash('Username already exists.', 'error')
                return redirect(url_for('edit_admin', admin_id=admin_id))
        
        if email != admin['email']:
            existing = db.execute('SELECT id FROM admins WHERE email = ? AND id != ?', 
                                 (email, admin_id)).fetchone()
            if existing:
                flash('Email already exists.', 'error')
                return redirect(url_for('edit_admin', admin_id=admin_id))
        
        update_fields = []
        params = []
        
        if full_name != admin['full_name']:
            update_fields.append('full_name = ?')
            params.append(full_name)
        
        if username != admin['username']:
            update_fields.append('username = ?')
            params.append(username)
        
        if email != admin['email']:
            update_fields.append('email = ?')
            params.append(email)
        
        if role != admin['role']:
            update_fields.append('role = ?')
            params.append(role)
        
        if password:
            password_hash = hash_password(password)
            update_fields.append('password = ?')
            params.append(password_hash)
        
        if update_fields:
            params.append(admin_id)
            query = f'UPDATE admins SET {", ".join(update_fields)} WHERE id = ?'
            db.execute(query, params)
            db.commit()
            flash('Admin updated successfully!', 'success')
        
        return redirect(url_for('admin_admins'))
    
    return render_template('admin/edit_admin.html', admin=admin)

@app.route('/admin/admins/delete/<int:admin_id>', methods=['POST'])
@admin_required
@super_admin_required
def delete_admin(admin_id):
    db = get_db()
    
    if admin_id == session['admin_id']:
        flash('You cannot delete your own account.', 'error')
        return redirect(url_for('admin_admins'))
    
    admin = db.execute('SELECT id FROM admins WHERE id = ?', (admin_id,)).fetchone()
    if not admin:
        flash('Admin not found.', 'error')
        return redirect(url_for('admin_admins'))
    
    db.execute('DELETE FROM admins WHERE id = ?', (admin_id,))
    db.commit()
    
    flash('Admin deleted successfully!', 'success')
    return redirect(url_for('admin_admins'))

@app.route('/admin/profile')
@admin_required
def admin_profile():
    db = get_db()
    admin_id = session['admin_id']
    admin_row = db.execute('SELECT * FROM admins WHERE id = ?', (admin_id,)).fetchone()
    admin = row_to_dict(admin_row)
    if admin:
        admin['profile_picture'] = resolve_media_path(admin.get('profile_picture'))
    return render_template('admin/admin_profile.html', admin=admin)

@app.route('/admin/settings', methods=['GET', 'POST'])
@admin_required
def admin_settings():
    db = get_db()
    admin_id = session['admin_id']
    admin_row = db.execute('SELECT * FROM admins WHERE id = ?', (admin_id,)).fetchone()
    admin = row_to_dict(admin_row)
    if admin:
        admin['profile_picture'] = resolve_media_path(admin.get('profile_picture'))

    if request.method == 'POST':
        full_name = request.form.get('full_name')
        username = request.form.get('username')
        email = request.form.get('email')
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        profile_file = request.files.get('profile_picture')

        if not full_name or not username or not email:
            flash('Name, username and email are required.', 'error')
            return redirect(url_for('admin_settings'))

        update_fields = []
        params = []

        if full_name != admin['full_name']:
            update_fields.append('full_name = ?')
            params.append(full_name)
            session['admin_name'] = full_name

        if username != admin['username']:
            existing = db.execute('SELECT id FROM admins WHERE username = ? AND id != ?', (username, admin_id)).fetchone()
            if existing:
                flash('Username already exists.', 'error')
                return redirect(url_for('admin_settings'))
            update_fields.append('username = ?')
            params.append(username)
            session['admin_username'] = username

        if email != admin['email']:
            existing = db.execute('SELECT id FROM admins WHERE email = ? AND id != ?', (email, admin_id)).fetchone()
            if existing:
                flash('Email already exists.', 'error')
                return redirect(url_for('admin_settings'))
            update_fields.append('email = ?')
            params.append(email)

        if new_password:
            if not current_password:
                flash('Current password is required to change password.', 'error')
                return redirect(url_for('admin_settings'))
            if not check_password(current_password, admin['password']):
                flash('Current password is incorrect.', 'error')
                return redirect(url_for('admin_settings'))
            if new_password != confirm_password:
                flash('New passwords do not match.', 'error')
                return redirect(url_for('admin_settings'))
            new_password_hash = hash_password(new_password)
            update_fields.append('password = ?')
            params.append(new_password_hash)

        profile_path = save_file(profile_file, 'image')
        if profile_path:
            old_picture = admin.get('profile_picture')
            if old_picture:
                delete_file(old_picture)
            update_fields.append('profile_picture = ?')
            params.append(profile_path)

        if update_fields:
            params.append(admin_id)
            query = f'UPDATE admins SET {", ".join(update_fields)} WHERE id = ?'
            db.execute(query, params)
            db.commit()
            flash('Profile updated successfully!', 'success')
        else:
            flash('No changes made.', 'info')

        return redirect(url_for('admin_profile'))

    return render_template('admin/settings.html', admin=admin)

@app.route('/admin/logout')
def admin_logout():
    session.clear()
    flash('Admin logged out successfully.', 'info')
    return redirect(url_for('admin_login'))



# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(error):
    return render_template('error/404.html'), 404

@app.errorhandler(403)
def forbidden(error):
    return render_template('error/403.html'), 403

@app.errorhandler(500)
def internal_error(error):
    return render_template('error/500.html'), 500



if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=3000, host='0.0.0.0')