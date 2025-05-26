import sqlite3
import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, Response
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import uuid
import re
from datetime import datetime
import pytz
from io import BytesIO
import tempfile
import logging
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from io import BytesIO

app = Flask(__name__)
app.secret_key = os.urandom(24)
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Database setup
def init_db():
    with sqlite3.connect('scp.db') as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('O5', 'Scientist', 'Security', 'SCP', 'D-Class')),
            nickname TEXT,
            theme TEXT DEFAULT 'light',
            profile_image TEXT DEFAULT 'default.png'
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS scps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scp_id TEXT UNIQUE NOT NULL,
            class TEXT NOT NULL,
            containment_status TEXT NOT NULL,
            description TEXT
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            assigned_to INTEGER,
            status TEXT NOT NULL,
            description TEXT,
            FOREIGN KEY (assigned_to) REFERENCES users(id)
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS activities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS scp_assignments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scp_id INTEGER,
            user_id INTEGER,
            role TEXT NOT NULL,
            FOREIGN KEY (scp_id) REFERENCES scps(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )''')
        # Insert default O5 user if not exists
        c.execute('SELECT * FROM users WHERE username = ?', ('o5admin',))
        if not c.fetchone():
            c.execute('INSERT INTO users (username, password, role, nickname, theme) VALUES (?, ?, ?, ?, ?)',
                      ('o5admin', generate_password_hash('admin123'), 'O5', 'O5-Admin', 'light'))
        conn.commit()

init_db()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_db():
    conn = sqlite3.connect('scp.db')
    conn.row_factory = sqlite3.Row
    return conn

def log_activity(user_id, action):
    tz = pytz.timezone('Europe/Paris')  # Use CEST time zone
    timestamp = tz.localize(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')
    with get_db() as conn:
        c = conn.cursor()
        c.execute('INSERT INTO activities (user_id, action, timestamp) VALUES (?, ?, ?)',
                  (user_id, action, timestamp))
        conn.commit()

# Middleware to check login
def login_required(f):
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with get_db() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM users WHERE username = ?', (username,))
            user = c.fetchone()
            if user and check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['role'] = user['role']
                session['theme'] = user['theme']
                log_activity(user['id'], f"User {username} logged in")
                flash('Logged in successfully.', 'success')
                return redirect(url_for('dashboard'))
            flash('Invalid credentials.', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
@login_required
def register():
    if session.get('role') != 'O5':
        flash('Only O5 members can register new users.', 'error')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        nickname = request.form['nickname']
        if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
            flash('Invalid username. Use 3-20 alphanumeric characters or underscores.', 'error')
            return redirect(url_for('register'))
        with get_db() as conn:
            c = conn.cursor()
            try:
                c.execute('INSERT INTO users (username, password, role, nickname) VALUES (?, ?, ?, ?)',
                          (username, generate_password_hash(password), role, nickname))
                conn.commit()
                log_activity(session['user_id'], f"Registered user {username}")
                flash('User registered successfully.', 'success')
                return redirect(url_for('dashboard'))
            except sqlite3.IntegrityError:
                flash('Username already exists.', 'error')
    return render_template('register.html')

@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    session.clear()
    if user_id:
        log_activity(user_id, "User logged out")
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    with get_db() as conn:
        c = conn.cursor()
        c.execute('SELECT scp_id, class, containment_status FROM scps')
        scps = c.fetchall()
        c.execute('SELECT class, COUNT(*) as count FROM scps GROUP BY class')
        class_stats = c.fetchall()
        c.execute('SELECT containment_status, COUNT(*) as count FROM scps GROUP BY containment_status')
        status_stats = c.fetchall()
        c.execute('SELECT t.*, u.username FROM tasks t JOIN users u ON t.assigned_to = u.id WHERE t.assigned_to = ? OR ? = "O5"',
                  (session['user_id'], session.get('role')))
        tasks = c.fetchall()
        c.execute('SELECT s.scp_id, s.class FROM scps s JOIN scp_assignments sa ON s.id = sa.scp_id WHERE sa.user_id = ?',
                  (session['user_id'],))
        assigned_scps = c.fetchall()
        c.execute('SELECT COUNT(*) as count FROM users WHERE role = ?', ('Scientist',))
        scientist_count = c.fetchone()['count']
        c.execute('SELECT COUNT(*) as count FROM users WHERE role = ?', ('Security',))
        security_count = c.fetchone()['count']
        c.execute('SELECT COUNT(*) as count FROM tasks')
        task_count = c.fetchone()['count']
        c.execute('SELECT a.action, a.timestamp, u.username FROM activities a JOIN users u ON a.user_id = u.id ORDER BY a.timestamp DESC LIMIT 10')
        activities = c.fetchall()
    return render_template('dashboard.html', scps=scps, class_stats=class_stats, status_stats=status_stats, tasks=tasks,
                          assigned_scps=assigned_scps, scientist_count=scientist_count, security_count=security_count,
                          task_count=task_count, activities=activities, role=session['role'])

@app.route('/dashboard/data')
@login_required
def dashboard_data():
    with get_db() as conn:
        c = conn.cursor()
        c.execute('SELECT scp_id, class, containment_status FROM scps')
        scps = [dict(row) for row in c.fetchall()]
        c.execute('SELECT class, COUNT(*) as count FROM scps GROUP BY class')
        class_stats = [dict(row) for row in c.fetchall()]
        c.execute('SELECT containment_status, COUNT(*) as count FROM scps GROUP BY containment_status')
        status_stats = [dict(row) for row in c.fetchall()]
        c.execute('SELECT t.*, u.username FROM tasks t JOIN users u ON t.assigned_to = u.id WHERE t.assigned_to = ? OR ? = "O5"',
                  (session['user_id'], session.get('role')))
        tasks = [dict(row) for row in c.fetchall()]
        c.execute('SELECT s.scp_id, s.class FROM scps s JOIN scp_assignments sa ON s.id = sa.scp_id WHERE sa.user_id = ?',
                  (session['user_id'],))
        assigned_scps = [dict(row) for row in c.fetchall()]
        c.execute('SELECT COUNT(*) as count FROM users WHERE role = ?', ('Scientist',))
        scientist_count = c.fetchone()['count']
        c.execute('SELECT COUNT(*) as count FROM users WHERE role = ?', ('Security',))
        security_count = c.fetchone()['count']
        c.execute('SELECT COUNT(*) as count FROM tasks')
        task_count = c.fetchone()['count']
        c.execute('SELECT a.action, a.timestamp, u.username FROM activities a JOIN users u ON a.user_id = u.id ORDER BY a.timestamp DESC LIMIT 10')
        activities = [dict(row) for row in c.fetchall()]
    return jsonify({
        'scps': scps,
        'class_stats': class_stats,
        'status_stats': status_stats,
        'tasks': tasks,
        'assigned_scps': assigned_scps,
        'scientist_count': scientist_count,
        'security_count': security_count,
        'task_count': task_count,
        'activities': activities,
        'role': session['role']
    })

@app.route('/scp', methods=['GET', 'POST'])
@login_required
def manage_scp():
    if session.get('role') not in ['O5', 'Scientist']:
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        scp_id = request.form['scp_id']
        scp_class = request.form['class']
        containment_status = request.form['containment_status']
        description = request.form['description']
        assigned_user = request.form.get('assigned_user')
        with get_db() as conn:
            c = conn.cursor()
            c.execute('INSERT OR REPLACE INTO scps (scp_id, class, containment_status, description) VALUES (?, ?, ?, ?)',
                      (scp_id, scp_class, containment_status, description))
            scp_db_id = c.execute('SELECT id FROM scps WHERE scp_id = ?', (scp_id,)).fetchone()['id']
            if assigned_user:
                c.execute('INSERT OR REPLACE INTO scp_assignments (scp_id, user_id, role) VALUES (?, ?, ?)',
                          (scp_db_id, assigned_user, session['role']))
            conn.commit()
            log_activity(session['user_id'], f"Updated SCP {scp_id}")
            flash('SCP updated successfully.', 'success')
        return redirect(url_for('manage_scp'))
    with get_db() as conn:
        c = conn.cursor()
        c.execute('SELECT s.*, GROUP_CONCAT(u.username) as assigned_users FROM scps s LEFT JOIN scp_assignments sa ON s.id = sa.scp_id LEFT JOIN users u ON sa.user_id = u.id GROUP BY s.id')
        scps = c.fetchall()
        c.execute('SELECT id, username FROM users WHERE role IN ("Scientist", "Security")')
        users = c.fetchall()
    return render_template('scp.html', scps=scps, users=users)

@app.route('/scp/delete/<scp_id>', methods=['POST'])
@login_required
def delete_scp(scp_id):
    if session.get('role') != 'O5':
        flash('Only O5 members can delete SCPs.', 'error')
        return redirect(url_for('manage_scp'))
    with get_db() as conn:
        c = conn.cursor()
        c.execute('DELETE FROM scp_assignments WHERE scp_id = (SELECT id FROM scps WHERE scp_id = ?)', (scp_id,))
        c.execute('DELETE FROM scps WHERE scp_id = ?', (scp_id,))
        conn.commit()
        log_activity(session['user_id'], f"Deleted SCP {scp_id}")
        flash('SCP deleted successfully.', 'success')
    return redirect(url_for('manage_scp'))

@app.route('/scp/profile/<scp_id>')
@login_required
def scp_profile(scp_id):
    with get_db() as conn:
        c = conn.cursor()
        c.execute('SELECT s.*, GROUP_CONCAT(u.username) as assigned_users FROM scps s LEFT JOIN scp_assignments sa ON s.id = sa.scp_id LEFT JOIN users u ON sa.user_id = u.id WHERE s.scp_id = ? GROUP BY s.id', (scp_id,))
        scp = c.fetchone()
        c.execute('SELECT id, username FROM users WHERE role IN ("Scientist", "Security")')
        users = c.fetchall()
    if not scp:
        flash('SCP not found.', 'error')
        return redirect(url_for('manage_scp'))
    return render_template('scp_profile.html', scp=scp, users=users)

@app.route('/task', methods=['GET', 'POST'])
@login_required
def manage_task():
    if session.get('role') not in ['O5', 'Scientist']:
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        title = request.form['title']
        assigned_to = request.form['assigned_to']
        status = request.form['status']
        description = request.form['description']
        with get_db() as conn:
            c = conn.cursor()
            c.execute('INSERT INTO tasks (title, assigned_to, status, description) VALUES (?, ?, ?, ?)',
                      (title, assigned_to, status, description))
            conn.commit()
            log_activity(session['user_id'], f"Created task {title}")
            flash('Task created successfully.', 'success')
        return redirect(url_for('manage_task'))
    with get_db() as conn:
        c = conn.cursor()
        c.execute('SELECT t.*, u.username FROM tasks t JOIN users u ON t.assigned_to = u.id')
        tasks = c.fetchall()
        c.execute('SELECT id, username FROM users WHERE role IN ("Scientist", "Security", "D-Class")')
        users = c.fetchall()
    return render_template('task.html', tasks=tasks, users=users)

@app.route('/task/profile/<int:task_id>')
@login_required
def task_profile(task_id):
    with get_db() as conn:
        c = conn.cursor()
        c.execute('SELECT t.*, u.username FROM tasks t JOIN users u ON t.assigned_to = u.id WHERE t.id = ?', (task_id,))
        task = c.fetchone()
        c.execute('SELECT id, username FROM users WHERE role IN ("Scientist", "Security", "D-Class")')
        users = c.fetchall()
    if not task:
        flash('Task not found.', 'error')
        return redirect(url_for('manage_task'))
    return render_template('task_profile.html', task=task, users=users)

@app.route('/task/update/<int:task_id>', methods=['POST'])
@login_required
def update_task(task_id):
    if session.get('role') not in ['O5', 'Scientist']:
        flash('Access denied.', 'error')
        return redirect(url_for('task_profile', task_id=task_id))
    title = request.form['title']
    assigned_to = request.form['assigned_to']
    status = request.form['status']
    description = request.form['description']
    with get_db() as conn:
        c = conn.cursor()
        c.execute('UPDATE tasks SET title = ?, assigned_to = ?, status = ?, description = ? WHERE id = ?',
                  (title, assigned_to, status, description, task_id))
        conn.commit()
        log_activity(session['user_id'], f"Updated task {title}")
        flash('Task updated successfully.', 'success')
    return redirect(url_for('task_profile', task_id=task_id))

@app.route('/tasks/<int:task_id>/status', methods=['POST'])
@login_required
def update_task_status_endpoint(task_id):
    if session.get('role') not in ['O5', 'Scientist']:
        return jsonify({'success': False, 'message': 'Access denied.'}), 403
    data = request.get_json()
    new_status = data.get('status')
    if new_status not in ['Pending', 'In Progress', 'Completed']:
        return jsonify({'success': False, 'message': 'Invalid status.'}), 400
    with get_db() as conn:
        c = conn.cursor()
        c.execute('UPDATE tasks SET status = ? WHERE id = ?', (new_status, task_id))
        conn.commit()
        log_activity(session['user_id'], f"Updated task {task_id} status to {new_status}")
    return jsonify({'success': True})

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        nickname = request.form['nickname']
        password = request.form.get('password')
        theme = request.form['theme']
        profile_image = request.files.get('profile_image')
        filename = None
        if profile_image and allowed_file(profile_image.filename):
            filename = secure_filename(f"{uuid.uuid4()}.{profile_image.filename.rsplit('.', 1)[1].lower()}")
            profile_image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        with get_db() as conn:
            c = conn.cursor()
            if password:
                c.execute('UPDATE users SET nickname = ?, password = ?, theme = ? WHERE id = ?',
                          (nickname, generate_password_hash(password), theme, session['user_id']))
            else:
                c.execute('UPDATE users SET nickname = ?, theme = ? WHERE id = ?',
                          (nickname, theme, session['user_id']))
            if filename:
                c.execute('UPDATE users SET profile_image = ? WHERE id = ?', (filename, session['user_id']))
            conn.commit()
            session['theme'] = theme
            log_activity(session['user_id'], f"Updated profile for {nickname}")
            flash('Profile updated successfully.', 'success')
        return redirect(url_for('profile'))
    with get_db() as conn:
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
        user = c.fetchone()
    return render_template('profile.html', user=user)

@app.route('/user/profile/<int:user_id>')
@login_required
def user_profile(user_id):
    if session.get('role') != 'O5' and session['user_id'] != user_id:
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    with get_db() as conn:
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        user = c.fetchone()
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('manage_users'))
    return render_template('user_profile.html', user=user)

@app.route('/user/update/<int:user_id>', methods=['POST'])
@login_required
def update_user(user_id):
    if session.get('role') != 'O5':
        flash('Only O5 members can update other users.', 'error')
        return redirect(url_for('user_profile', user_id=user_id))
    username = request.form['username']
    nickname = request.form['nickname']
    role = request.form['role']
    password = request.form.get('password')
    profile_image = request.files.get('profile_image')
    filename = None
    if profile_image and allowed_file(profile_image.filename):
        filename = secure_filename(f"{uuid.uuid4()}.{profile_image.filename.rsplit('.', 1)[1].lower()}")
        profile_image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    with get_db() as conn:
        c = conn.cursor()
        if password:
            c.execute('UPDATE users SET username = ?, nickname = ?, role = ?, password = ? WHERE id = ?',
                      (username, nickname, role, generate_password_hash(password), user_id))
        else:
            c.execute('UPDATE users SET username = ?, nickname = ?, role = ? WHERE id = ?',
                      (username, nickname, role, user_id))
        if filename:
            c.execute('UPDATE users SET profile_image = ? WHERE id = ?', (filename, user_id))
        conn.commit()
        log_activity(session['user_id'], f"Updated user {username}")
        flash('User updated successfully.', 'success')
    return redirect(url_for('user_profile', user_id=user_id))

@app.route('/users', methods=['GET'])
@login_required
def manage_users():
    if session.get('role') != 'O5':
        flash('Only O5 members can manage users.', 'error')
        return redirect(url_for('dashboard'))
    with get_db() as conn:
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE role != "O5"')
        users = c.fetchall()
    return render_template('users.html', users=users)

@app.route('/user/delete/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if session.get('role') != 'O5':
        flash('Only O5 members can delete users.', 'error')
        return redirect(url_for('dashboard'))
    with get_db() as conn:
        c = conn.cursor()
        c.execute('SELECT username FROM users WHERE id = ?', (user_id,))
        username = c.fetchone()['username']
        c.execute('DELETE FROM users WHERE id = ? AND role != "O5"', (user_id,))
        conn.commit()
        log_activity(session['user_id'], f"Deleted user {username}")
        flash('User deleted successfully.', 'success')
    return redirect(url_for('manage_users'))



@app.route('/generate_report', methods=['POST'])
@login_required
def generate_report():
    if session.get('role') != 'O5':
        logger.warning("Unauthorized access attempt to /generate_report by user %s", session.get('username'))
        return jsonify({'success': False, 'message': 'Access denied.'}), 403

    logger.info("Generating report for user %s", session.get('username'))

    # Collect data
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute('SELECT scp_id, class, containment_status FROM scps')
            scps = c.fetchall()
            c.execute('SELECT class, COUNT(*) as count FROM scps GROUP BY class')
            class_stats = c.fetchall()
            c.execute('SELECT containment_status, COUNT(*) as count FROM scps GROUP BY containment_status')
            status_stats = c.fetchall()
            c.execute('SELECT COUNT(*) as count FROM users WHERE role = ?', ('Scientist',))
            scientist_count = c.fetchone()['count']
            c.execute('SELECT COUNT(*) as count FROM users WHERE role = ?', ('Security',))
            security_count = c.fetchone()['count']
            c.execute('SELECT COUNT(*) as count FROM tasks')
            task_count = c.fetchone()['count']
            c.execute('SELECT a.action, a.timestamp, u.username FROM activities a JOIN users u ON a.user_id = u.id ORDER BY a.timestamp DESC LIMIT 10')
            activities = c.fetchall()
    except sqlite3.Error as e:
        logger.error("Database error: %s", e)
        return jsonify({'success': False, 'message': 'Database error occurred.'}), 500

    # Generate PDF with reportlab
    try:
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        elements = []

        # Title
        elements.append(Paragraph("SCP Foundation System Report", styles['Title']))
        elements.append(Paragraph(f"Generated on {datetime.now().strftime('%Y-%m-%d')}", styles['Normal']))
        elements.append(Spacer(1, 12))

        # System Overview
        elements.append(Paragraph("System Overview", styles['Heading2']))
        overview_data = [
            ['Total SCPs', len(scps)],
            ['Scientists', scientist_count],
            ['Security Personnel', security_count],
            ['Active Tasks', task_count]
        ]
        overview_table = Table(overview_data)
        overview_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(overview_table)
        elements.append(Spacer(1, 12))

        # SCP Statistics: By Class
        elements.append(Paragraph("SCP Statistics: By Class", styles['Heading2']))
        class_data = [['Class', 'Count']] + [[stat['class'], stat['count']] for stat in class_stats]
        class_table = Table(class_data)
        class_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(class_table)
        elements.append(Spacer(1, 12))

        # SCP Statistics: By Containment Status
        elements.append(Paragraph("SCP Statistics: By Containment Status", styles['Heading2']))
        status_data = [['Containment Status', 'Count']] + [[stat['containment_status'], stat['count']] for stat in status_stats]
        status_table = Table(status_data)
        status_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(status_table)
        elements.append(Spacer(1, 12))

        # Recent Activities
        elements.append(Paragraph("Recent Activities", styles['Heading2']))
        activity_data = [['Username', 'Action', 'Timestamp']] + [[activity['username'], activity['action'], activity['timestamp']] for activity in activities]
        activity_table = Table(activity_data)
        activity_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(activity_table)

        # Build PDF
        doc.build(elements)
        buffer.seek(0)
        logger.info("Report generated successfully with ReportLab")
        return Response(
            buffer.read(),
            mimetype='application/pdf',
            headers={'Content-Disposition': 'attachment; filename=SCP_Foundation_Report.pdf'}
        )
    except Exception as e:
        logger.error("Error generating PDF with ReportLab: %s", e)
        return jsonify({'success': False, 'message': f'Failed to generate PDF report: {str(e)}'}), 500
    


if __name__ == '__main__':
    app.run(debug=True)