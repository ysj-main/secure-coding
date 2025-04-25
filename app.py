import os
import sqlite3
import uuid
from functools import wraps
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, g, abort
)
from flask_socketio import SocketIO, send, join_room, emit
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash

# ===== app configuration =====
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret')
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB upload limit
csrf = CSRFProtect(app)

DATABASE = 'market.db'
socketio = SocketIO(app)
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

ALLOWED_EXT = {'png', 'jpg', 'jpeg', 'gif'}


def allowed_file(fname):
    return (
        '.' in fname and
        fname.rsplit('.', 1)[1].lower() in ALLOWED_EXT
    )


def is_valid_uuid(val):
    try:
        uuid.UUID(val)
        return True
    except Exception:
        return False


# ===== database helpers =====
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


# ===== user loading & admin check =====
@app.before_request
def load_current_user():
    g.current_user = None
    if session.get('user_id'):
        cur = get_db().cursor()
        cur.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
        g.current_user = cur.fetchone()


def admin_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not g.current_user or not g.current_user['is_admin']:
            abort(403)
        return f(*args, **kwargs)
    return wrapped


@app.context_processor
def inject_user():
    return dict(current_user=g.get('current_user'))


# ===== initialize tables =====
def init_db():
    with app.app_context():
        db = get_db()
        c = db.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT,
                is_admin INTEGER NOT NULL DEFAULT 0
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS product_images (
                id TEXT PRIMARY KEY,
                product_id TEXT NOT NULL,
                filename TEXT NOT NULL,
                FOREIGN KEY(product_id) REFERENCES product(id) ON DELETE CASCADE
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS private_messages (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                content TEXT NOT NULL,
                timestamp DATETIME NOT NULL
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS blocked_users (
                user_id TEXT PRIMARY KEY,
                blocked_at DATETIME NOT NULL
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS blocked_products (
                product_id TEXT PRIMARY KEY,
                blocked_at DATETIME NOT NULL
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS user_balances (
                user_id TEXT PRIMARY KEY,
                balance INTEGER NOT NULL
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                amount INTEGER NOT NULL,
                timestamp DATETIME NOT NULL
            )
        """)
        db.commit()


# ===== routes =====

@app.route('/')
def index():
    if session.get('user_id'):
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        db = get_db(); cur = db.cursor()
        cur.execute("SELECT 1 FROM user WHERE username = ?", (username,))
        if cur.fetchone():
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))
        user_id = str(uuid.uuid4())
        hashed = generate_password_hash(password)
        cur.execute(
            "INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
            (user_id, username, hashed)
        )
        cur.execute(
            "INSERT INTO user_balances (user_id, balance) VALUES (?, 0)",
            (user_id,)
        )
        db.commit()
        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        db = get_db(); cur = db.cursor()
        cur.execute("SELECT id, password FROM user WHERE username = ?", (username,))
        row = cur.fetchone()
        if row and check_password_hash(row['password'], password):
            session['user_id'] = row['id']
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))
        flash('아이디 또는 비밀번호가 올바르지 않습니다.')
        return redirect(url_for('login'))
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))


@app.route('/dashboard')
def dashboard():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    db = get_db(); cur = db.cursor()
    cur.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cur.fetchone()

    q = request.args.get('q', '').strip()
    per_page = 10
    try:
        page = max(int(request.args.get('page', 1)), 1)
    except ValueError:
        page = 1
    offset = (page - 1) * per_page

    base = "FROM product WHERE id NOT IN (SELECT product_id FROM blocked_products)"
    params = ()
    if q:
        base = ("FROM product WHERE (title LIKE ? OR description LIKE ?) "
                "AND id NOT IN (SELECT product_id FROM blocked_products)")
        params = (f"%{q}%", f"%{q}%")

    cur.execute(f"SELECT COUNT(*) {base}", params)
    total = cur.fetchone()[0]
    cur.execute(
        f"SELECT * {base} ORDER BY title LIMIT ? OFFSET ?",
        params + (per_page, offset)
    )
    products = cur.fetchall()

    cur.execute("SELECT product_id FROM blocked_products")
    blocked_products = cur.fetchall()

    total_pages = (total + per_page - 1) // per_page
    return render_template(
        'dashboard.html',
        user=current_user,
        products=products,
        blocked_products=blocked_products,
        search_query=q,
        page=page,
        total_pages=total_pages
    )

# ── 프로필 보기/수정 ──
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    db = get_db()
    cur = db.cursor()

    if request.method == 'POST':
        # 소개글(bio) 수정
        if 'bio' in request.form:
            bio = request.form.get('bio', '').strip()
            cur.execute(
                "UPDATE user SET bio = ? WHERE id = ?",
                (bio, session['user_id'])
            )
            db.commit()
            flash('소개글이 업데이트되었습니다.')
        # 비밀번호 변경
        elif 'current_password' in request.form:
            current = request.form['current_password']
            new_pw  = request.form['new_password']
            confirm = request.form['confirm_password']

            # 현재 비밀번호 검증
            cur.execute("SELECT password FROM user WHERE id = ?", (session['user_id'],))
            stored = cur.fetchone()['password']
            if not check_password_hash(stored, current):
                flash('현재 비밀번호가 올바르지 않습니다.')
            elif new_pw != confirm:
                flash('새 비밀번호와 확인이 일치하지 않습니다.')
            else:
                cur.execute(
                    "UPDATE user SET password = ? WHERE id = ?",
                    (generate_password_hash(new_pw), session['user_id'])
                )
                db.commit()
                flash('비밀번호가 변경되었습니다.')
        return redirect(url_for('profile'))

    # GET: 프로필 폼 렌더
    cur.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    user = cur.fetchone()
    return render_template('profile.html', user=user)


@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form['title'].strip()
        description = request.form['description'].strip()
        price = request.form['price'].strip()
        product_id = str(uuid.uuid4())
        db = get_db(); cur = db.cursor()
        cur.execute(
            "INSERT INTO product (id, title, description, price, seller_id) "
            "VALUES (?, ?, ?, ?, ?)",
            (product_id, title, description, price, session['user_id'])
        )
        for file in request.files.getlist('images'):
            if file and allowed_file(file.filename):
                safe_name = secure_filename(file.filename)
                ext = safe_name.rsplit('.', 1)[1].lower()
                img_id = str(uuid.uuid4())
                filename = f"{img_id}.{ext}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                cur.execute(
                    "INSERT INTO product_images (id, product_id, filename) "
                    "VALUES (?, ?, ?)",
                    (img_id, product_id, filename)
                )
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('new_product.html')


@app.route('/product/<product_id>')
def view_product(product_id):
    if not is_valid_uuid(product_id):
        abort(404)
    db = get_db(); cur = db.cursor()
    cur.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cur.fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    cur.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cur.fetchone()
    cur.execute(
        "SELECT filename FROM product_images WHERE product_id = ?",
        (product_id,)
    )
    images = cur.fetchall()
    return render_template(
        'view_product.html',
        product=product,
        seller=seller,
        images=images
    )


@app.route('/product/<product_id>/edit', methods=['GET', 'POST'])
def edit_product(product_id):
    if not is_valid_uuid(product_id):
        abort(404)
    if not session.get('user_id'):
        return redirect(url_for('login'))
    db = get_db(); cur = db.cursor()
    cur.execute(
        "SELECT * FROM product WHERE id = ? AND seller_id = ?",
        (product_id, session['user_id'])
    )
    prod = cur.fetchone()
    if not prod:
        flash('권한이 없거나 상품을 찾을 수 없습니다.')
        return redirect(url_for('my_products'))

    if request.method == 'POST':
        # 이미지 삭제
        for img_id in request.form.getlist('delete_images'):
            if is_valid_uuid(img_id):
                cur.execute(
                    "SELECT filename FROM product_images WHERE id = ?", (img_id,)
                )
                row = cur.fetchone()
                if row:
                    try:
                        os.remove(os.path.join(
                            app.config['UPLOAD_FOLDER'], row['filename']
                        ))
                    except OSError:
                        pass
                    cur.execute(
                        "DELETE FROM product_images WHERE id = ?", (img_id,)
                    )
        # 기본 정보 업데이트
        title = request.form['title'].strip()
        description = request.form['description'].strip()
        price = request.form['price'].strip()
        cur.execute(
            "UPDATE product SET title=?, description=?, price=? WHERE id=?",
            (title, description, price, product_id)
        )
        # 새 이미지 업로드
        for file in request.files.getlist('images'):
            if file and allowed_file(file.filename):
                safe_name = secure_filename(file.filename)
                ext = safe_name.rsplit('.', 1)[1].lower()
                img_id = str(uuid.uuid4())
                filename = f"{img_id}.{ext}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                cur.execute(
                    "INSERT INTO product_images (id, product_id, filename) "
                    "VALUES (?, ?, ?)",
                    (img_id, product_id, filename)
                )
        db.commit()
        flash('상품이 수정되었습니다.')
        return redirect(url_for('view_product', product_id=product_id))

    cur.execute(
        "SELECT id, filename FROM product_images WHERE product_id = ?",
        (product_id,)
    )
    images = cur.fetchall()
    return render_template(
        'edit_product.html',
        product=prod,
        images=images
    )


@app.route('/product/<product_id>/delete', methods=['POST'])
def delete_product(product_id):
    if not is_valid_uuid(product_id):
        abort(404)
    if not session.get('user_id'):
        return redirect(url_for('login'))
    db = get_db(); cur = db.cursor()
    cur.execute(
        "DELETE FROM product WHERE id = ? AND seller_id = ?",
        (product_id, session['user_id'])
    )
    if cur.rowcount:
        db.commit()
        flash('상품이 삭제되었습니다.')
    else:
        flash('삭제 권한이 없거나 상품을 찾을 수 없습니다.')
    return redirect(url_for('my_products'))


@app.route('/my_products')
def my_products():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    db = get_db(); cur = db.cursor()
    cur.execute(
        "SELECT * FROM product WHERE seller_id = ?",
        (session['user_id'],)
    )
    prods = cur.fetchall()
    return render_template('my_products.html', products=prods)


@app.route('/report', methods=['GET', 'POST'])
def report():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    if request.method == 'POST':
        target_id = request.form['target_id']
        reason = request.form['reason'].strip()
        if not is_valid_uuid(target_id):
            abort(400)
        db = get_db(); cur = db.cursor()
        report_id = str(uuid.uuid4())
        cur.execute(
            "INSERT INTO report (id, reporter_id, target_id, reason) "
            "VALUES (?, ?, ?, ?)",
            (report_id, session['user_id'], target_id, reason)
        )
        db.commit()
        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('report.html')


@app.route('/private_chat')
def private_chat():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    db = get_db(); cur = db.cursor()
    cur.execute("SELECT id, username FROM user")
    users = cur.fetchall()
    return render_template(
        'private_chat.html',
        users=users,
        current_user_id=session['user_id']
    )


@app.route('/blocked_products')
def blocked_products_page():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    db = get_db(); cur = db.cursor()
    cur.execute("""
        SELECT p.id AS product_id, p.title, p.price
        FROM product p
        JOIN blocked_products bp ON p.id = bp.product_id
    """)
    blocked_list = cur.fetchall()
    return render_template('blocked_products.html', blocked_products=blocked_list)


@app.route('/manage_users')
def manage_users():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    db = get_db(); cur = db.cursor()
    cur.execute("""
        SELECT * FROM user WHERE id NOT IN (SELECT user_id FROM blocked_users)
    """)
    active = cur.fetchall()
    cur.execute("""
        SELECT u.id, u.username
        FROM user u
        JOIN blocked_users bp ON u.id = bp.user_id
    """)
    blocked = cur.fetchall()
    return render_template(
        'manage_users.html',
        active_users=active,
        blocked_users=blocked
    )


@app.route('/block_user/<user_id>')
def block_user(user_id):
    if not is_valid_uuid(user_id):
        abort(404)
    db = get_db(); cur = db.cursor()
    cur.execute("""
        INSERT OR IGNORE INTO blocked_users (user_id, blocked_at)
        VALUES (?, ?)
    """, (user_id, datetime.utcnow().isoformat()))
    db.commit()
    flash('사용자가 차단되었습니다.')
    return redirect(request.referrer or url_for('dashboard'))


@app.route('/unblock_user/<user_id>')
def unblock_user(user_id):
    if not is_valid_uuid(user_id):
        abort(404)
    db = get_db(); cur = db.cursor()
    cur.execute("DELETE FROM blocked_users WHERE user_id = ?", (user_id,))
    db.commit()
    flash('사용자 차단이 해제되었습니다.')
    return redirect(request.referrer or url_for('dashboard'))


@app.route('/block_product/<product_id>')
def block_product(product_id):
    if not is_valid_uuid(product_id):
        abort(404)
    db = get_db(); cur = db.cursor()
    cur.execute("""
        INSERT OR IGNORE INTO blocked_products (product_id, blocked_at)
        VALUES (?, ?)
    """, (product_id, datetime.utcnow().isoformat()))
    db.commit()
    flash('상품이 차단되었습니다.')
    return redirect(request.referrer or url_for('dashboard'))


@app.route('/unblock_product/<product_id>')
def unblock_product(product_id):
    if not is_valid_uuid(product_id):
        abort(404)
    db = get_db(); cur = db.cursor()
    cur.execute("DELETE FROM blocked_products WHERE product_id = ?", (product_id,))
    db.commit()
    flash('상품 차단이 해제되었습니다.')
    return redirect(request.referrer or url_for('dashboard'))


@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    db = get_db(); cur = db.cursor()
    user_id = session['user_id']

    if request.method == 'POST':
        receiver = request.form['receiver_id']
        if not is_valid_uuid(receiver):
            abort(400)
        try:
            amount = int(request.form['amount'])
        except ValueError:
            flash('올바른 금액을 입력하세요.')
            return redirect(url_for('transfer'))

        cur.execute(
            "SELECT balance FROM user_balances WHERE user_id = ?",
            (user_id,)
        )
        sender_balance = cur.fetchone()['balance']
        if amount <= 0 or amount > sender_balance:
            flash('잔액이 부족하거나 올바르지 않은 금액입니다.')
            return redirect(url_for('transfer'))

        cur.execute(
            "UPDATE user_balances SET balance = balance - ? WHERE user_id = ?",
            (amount, user_id)
        )
        cur.execute(
            "UPDATE user_balances SET balance = balance + ? WHERE user_id = ?",
            (amount, receiver)
        )
        tx_id = str(uuid.uuid4())
        ts = datetime.utcnow().isoformat()
        cur.execute("""
            INSERT INTO transactions (id, sender_id, receiver_id, amount, timestamp)
            VALUES (?, ?, ?, ?, ?)
        """, (tx_id, user_id, receiver, amount, ts))
        db.commit()
        flash(f'{amount}원 송금 완료!')
        return redirect(url_for('dashboard'))

    cur.execute("SELECT id, username FROM user WHERE id != ?", (user_id,))
    users = cur.fetchall()
    cur.execute("SELECT balance FROM user_balances WHERE user_id = ?", (user_id,))
    balance = cur.fetchone()['balance']
    return render_template('transfer.html', users=users, balance=balance)


@app.route('/admin/products')
@admin_required
def admin_products():
    cur = get_db().cursor()
    cur.execute("SELECT * FROM product")
    products = cur.fetchall()
    return render_template('admin_products.html', products=products)


@app.route('/admin/product/<product_id>/delete', methods=['POST'])
@admin_required
def admin_delete_product(product_id):
    if not is_valid_uuid(product_id):
        abort(404)
    db = get_db(); cur = db.cursor()
    cur.execute("DELETE FROM product WHERE id = ?", (product_id,))
    if cur.rowcount:
        db.commit()
        flash('상품이 삭제되었습니다. (관리자)')
    else:
        flash('삭제할 상품을 찾을 수 없습니다.')
    return redirect(url_for('admin_products'))


@app.route('/admin/reports')
@admin_required
def admin_reports():
    cur = get_db().cursor()
    cur.execute("""
        SELECT
            r.id, r.reporter_id,
            rep.username AS reporter_name,
            r.target_id,
            tgt.title   AS target_product,
            tgt_usr.username AS target_user,
            r.reason
        FROM report r
        LEFT JOIN user rep    ON r.reporter_id = rep.id
        LEFT JOIN product tgt ON r.target_id    = tgt.id
        LEFT JOIN user tgt_usr ON r.target_id   = tgt_usr.id
        ORDER BY r.id DESC
    """)
    reports = cur.fetchall()
    return render_template('admin_reports.html', reports=reports)


@app.route('/admin/report/<report_id>/resolve', methods=['POST'])
@admin_required
def admin_resolve_report(report_id):
    if not is_valid_uuid(report_id):
        abort(404)
    db = get_db(); cur = db.cursor()
    cur.execute("DELETE FROM report WHERE id = ?", (report_id,))
    db.commit()
    flash('신고가 처리되었습니다.')
    return redirect(url_for('admin_reports'))


@app.route('/admin/manage', methods=['GET', 'POST'])
@admin_required
def admin_manage():
    db = get_db(); cur = db.cursor()
    if request.method == 'POST':
        user_id = request.form['user_id']
        role = request.form['role']
        if not is_valid_uuid(user_id) or role not in ('admin', 'user'):
            abort(400)
        is_admin = 1 if role == 'admin' else 0
        cur.execute("UPDATE user SET is_admin = ? WHERE id = ?", (is_admin, user_id))
        db.commit()
        flash(f'유저({user_id}) 권한이 "{role}"로 변경되었습니다.')
        return redirect(url_for('admin_manage'))

    cur.execute("SELECT id, username, is_admin FROM user")
    users = cur.fetchall()
    cur.execute("SELECT id, title, price, seller_id FROM product")
    products = cur.fetchall()
    return render_template('admin_manage.html', users=users, products=products)


# ===== real-time chat handlers =====
@socketio.on('send_message')
def handle_send_message_event(data):
    data['message_id'] = str(uuid.uuid4())
    send(data, broadcast=True)


@socketio.on('join_private')
def handle_join_private(data):
    sender = data['sender_id']
    receiver = data['receiver_id']
    if not (is_valid_uuid(sender) and is_valid_uuid(receiver)):
        return
    room = f"private_{min(sender, receiver)}_{max(sender, receiver)}"
    join_room(room)
    cur = get_db().cursor()
    cur.execute("""
        SELECT sender_id, receiver_id, content, timestamp
        FROM private_messages
        WHERE (sender_id=? AND receiver_id=?)
           OR (sender_id=? AND receiver_id=?)
        ORDER BY timestamp
    """, (sender, receiver, sender, receiver))
    for m in cur.fetchall():
        emit('new_private_message', dict(m), room=room)
    emit('status', {'msg': f'User {sender} entered private chat.'}, room=room)


@socketio.on('private_message')
def handle_private_message(data):
    sender = data['sender_id']
    receiver = data['receiver_id']
    content = data['content']
    if not (is_valid_uuid(sender) and is_valid_uuid(receiver)):
        return
    room = f"private_{min(sender, receiver)}_{max(sender, receiver)}"
    msg_id = str(uuid.uuid4())
    ts = datetime.utcnow().isoformat()
    db = get_db(); cur = db.cursor()
    cur.execute("""
        INSERT INTO private_messages (id, sender_id, receiver_id, content, timestamp)
        VALUES (?, ?, ?, ?, ?)
    """, (msg_id, sender, receiver, content, ts))
    db.commit()
    emit('new_private_message', {
        'sender_id': sender,
        'receiver_id': receiver,
        'content': content,
        'timestamp': ts
    }, room=room)


if __name__ == '__main__':
    init_db()
    socketio.run(app, debug=True)