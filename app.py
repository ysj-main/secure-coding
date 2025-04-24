import sqlite3
import uuid
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_socketio import SocketIO, send, join_room, emit
from datetime import datetime


app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
DATABASE = 'market.db'
socketio = SocketIO(app)

# 데이터베이스 연결 관리: 요청마다 연결 생성 후 사용, 종료 시 close
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # 결과를 dict처럼 사용하기 위함
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# 테이블 생성 (최초 실행 시에만)
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # 사용자 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT
            )
        """)
        # 상품 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL
            )
        """)
        # 신고 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL
            )
        """)
        # 1:1 채팅 메시지 테이블
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS private_messages (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                content TEXT NOT NULL,
                timestamp DATETIME NOT NULL    
            )
        """)
        # 유저 차단 테이블
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS blocked_users (
            user_id TEXT PRIMARY KEY,
            blocked_at DATETIME NOT NULL
        )""")

        # 상품 차단 테이블
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS blocked_products (
            product_id TEXT PRIMARY KEY,
            blocked_at DATETIME NOT NULL
        )""")

        # 잔액 테이블
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_balances (
            user_id TEXT PRIMARY KEY,
            balance INTEGER NOT NULL
        )
        """)
        
        # 거래 기록 테이블
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id TEXT PRIMARY KEY,
            sender_id TEXT NOT NULL,
            receiver_id TEXT NOT NULL,
            amount INTEGER NOT NULL,
            timestamp DATETIME NOT NULL
        )
        """)
        db.commit()

# 기본 라우트
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# 회원가입
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        # 중복 사용자 체크
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone() is not None:
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))
        user_id = str(uuid.uuid4())
        cursor.execute("INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
                       (user_id, username, password))
        db.commit()
        # — 회원가입 직후 잔액 테이블 초기화
        cursor.execute(
            "INSERT INTO user_balances (user_id, balance) VALUES (?, 0)",
            (user_id,)
            )
        db.commit()
        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))
    return render_template('register.html')

# 로그인
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ? AND password = ?", (username, password))
        user = cursor.fetchone()
        if user:
            session['user_id'] = user['id']
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))
        else:
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))
    return render_template('login.html')

# 로그아웃
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

# 대시보드: 사용자 정보, 상품 검색 및 차단 관리
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 현재 로그인한 사용자 정보
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()

    # 검색어 파라미터
    q = request.args.get('q', '').strip()

    # 차단되지 않은 상품을 검색어로 필터링하여 조회
    if q:
        cursor.execute(
            """
            SELECT * FROM product
            WHERE (title LIKE ? OR description LIKE ?)
              AND id NOT IN (SELECT product_id FROM blocked_products)
            """,
            (f"%{q}%", f"%{q}%")
        )
    else:
        cursor.execute(
            """
            SELECT * FROM product
            WHERE id NOT IN (SELECT product_id FROM blocked_products)
            """
        )
    all_products = cursor.fetchall()

    # 차단된 상품 ID 목록 (템플릿에서 '차단'/'차단 해제' 판단용)
    cursor.execute("SELECT product_id FROM blocked_products")
    blocked_products = cursor.fetchall()

    return render_template(
        'dashboard.html',
        products=all_products,
        blocked_products=blocked_products,
        user=current_user,
        search_query=q
    )

# 프로필 페이지: bio 업데이트 가능
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    if request.method == 'POST':
        # 소개글 수정 요청인지 확인
        if 'bio' in request.form:
            bio = request.form.get('bio', '')
            cursor.execute(
                "UPDATE user SET bio = ? WHERE id = ?",
                (bio, session['user_id'])
            )
            db.commit()
            flash('소개글이 업데이트되었습니다.')
        
        # 비밀번호 변경 요청인지 확인
        elif 'current_password' in request.form:
            current = request.form['current_password']
            new_pw  = request.form['new_password']
            confirm = request.form['confirm_password']
        
            # 현재 비밀번호 확인
            cursor.execute(
                "SELECT password FROM user WHERE id = ?",
                (session['user_id'],)
            )
            stored = cursor.fetchone()['password']
            
            if current != stored:
                flash('현재 비밀번호가 올바르지 않습니다.')
            elif new_pw != confirm:
                flash('새 비밀번호와 확인이 일치하지 않습니다.')
            else:
                cursor.execute(
                    "UPDATE user SET password = ? WHERE id = ?",
                    (new_pw, session['user_id'])
                )
                db.commit()
                flash('비밀번호가 변경되었습니다.')
        return redirect(url_for('profile'))

    # 현재 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    return render_template('profile.html', user=current_user)

# 상품 등록
@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = request.form['price']
        db = get_db()
        cursor = db.cursor()
        product_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO product (id, title, description, price, seller_id) VALUES (?, ?, ?, ?, ?)",
            (product_id, title, description, price, session['user_id'])
        )
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('new_product.html')

# 상품 상세보기
@app.route('/product/<product_id>')
def view_product(product_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    # 판매자 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()
    return render_template('view_product.html', product=product, seller=seller)

# 신고하기
@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        target_id = request.form['target_id']
        reason = request.form['reason']
        db = get_db()
        cursor = db.cursor()
        report_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO report (id, reporter_id, target_id, reason) VALUES (?, ?, ?, ?)",
            (report_id, session['user_id'], target_id, reason)
        )
        db.commit()
        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('report.html')

# 1대1채팅 페이지
@app.route('/private_chat')
def private_chat():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, username FROM user")
    users = cursor.fetchall()
    return render_template(
        'private_chat.html',
        users=users,
        current_user_id=session['user_id']
    )

# 차단된 상품 목록 페이지
@app.route('/blocked_products')
def blocked_products_page():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db(); cursor = db.cursor()
    cursor.execute(
        """
        SELECT p.id AS product_id, p.title, p.price
        FROM product p
        JOIN blocked_products bp ON p.id = bp.product_id
        """
    )
    blocked_list = cursor.fetchall()
    return render_template('blocked_products.html',
                           blocked_products=blocked_list)

# ── 사용자 관리 페이지
@app.route('/manage_users')
def manage_users():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db(); cursor = db.cursor()
    # 차단되지 않은 사용자
    cursor.execute(
        """
        SELECT * FROM user
        WHERE id NOT IN (SELECT user_id FROM blocked_users)
        """
    )
    active = cursor.fetchall()
    # 차단된 사용자
    cursor.execute(
        """
        SELECT u.id, u.username
        FROM user u
        JOIN blocked_users bp ON u.id = bp.user_id
        """
    )
    blocked = cursor.fetchall()
    return render_template('manage_users.html',
                           active_users=active,
                           blocked_users=blocked)


# 사용자 차단/해제
@app.route('/block_user/<user_id>')
def block_user(user_id):
    db = get_db(); cursor = db.cursor()
    cursor.execute("""
        INSERT OR IGNORE INTO blocked_users (user_id, blocked_at)
        VALUES (?, ?)
    """, (user_id, datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')))
    db.commit()
    flash('사용자가 차단되었습니다.')
    return redirect(request.referrer or url_for('dashboard'))

@app.route('/unblock_user/<user_id>')
def unblock_user(user_id):
    db = get_db(); cursor = db.cursor()
    cursor.execute("DELETE FROM blocked_users WHERE user_id = ?", (user_id,))
    db.commit()
    flash('사용자 차단이 해제되었습니다.')
    return redirect(request.referrer or url_for('dashboard'))

# 상품 차단
@app.route('/block_product/<product_id>')
def block_product(product_id):
    db = get_db(); cursor = db.cursor()
    cursor.execute("""
        INSERT OR IGNORE INTO blocked_products (product_id, blocked_at)
        VALUES (?, ?)
    """, (product_id, datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')))
    db.commit()
    flash('상품이 차단되었습니다.')
    return redirect(request.referrer or url_for('dashboard'))

# 상품 차단 해제
@app.route('/unblock_product/<product_id>')
def unblock_product(product_id):
    db = get_db(); cursor = db.cursor()
    cursor.execute("DELETE FROM blocked_products WHERE product_id = ?", (product_id,))
    db.commit()
    flash('상품 차단이 해제되었습니다.')
    return redirect(request.referrer or url_for('dashboard'))

# ── 송금 뷰: GET→폼, POST→잔액 이전 및 거래 기록 ──
@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db(); cursor = db.cursor()
    user_id = session['user_id']

    if request.method == 'POST':
        receiver = request.form['receiver_id']
        try:
            amount = int(request.form['amount'])
        except ValueError:
            flash('올바른 금액을 입력하세요.')
            return redirect(url_for('transfer'))

        # 송금 가능 여부 검사
        cursor.execute(
            "SELECT balance FROM user_balances WHERE user_id = ?",
            (user_id,)
        )
        sender_balance = cursor.fetchone()['balance']
        if amount <= 0 or amount > sender_balance:
            flash('잔액이 부족하거나 올바르지 않은 금액입니다.')
            return redirect(url_for('transfer'))

        # 잔액 차감・증가
        cursor.execute(
            "UPDATE user_balances SET balance = balance - ? WHERE user_id = ?",
            (amount, user_id)
        )
        cursor.execute(
            "UPDATE user_balances SET balance = balance + ? WHERE user_id = ?",
            (amount, receiver)
        )
        # 거래 기록
        tx_id = str(uuid.uuid4())
        ts = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute(
            "INSERT INTO transactions (id, sender_id, receiver_id, amount, timestamp) VALUES (?,?,?,?,?)",
            (tx_id, user_id, receiver, amount, ts)
        )
        db.commit()
        flash(f'{amount}원 송금 완료!')
        return redirect(url_for('dashboard'))

    # 송금 폼 준비
    cursor.execute(
        "SELECT id, username FROM user WHERE id != ?",
        (user_id,)
    )
    users = cursor.fetchall()
    cursor.execute(
        "SELECT balance FROM user_balances WHERE user_id = ?",
        (user_id,)
    )
    balance = cursor.fetchone()['balance']
    return render_template(
        'transfer.html',
        users=users,
        balance=balance
    )

# 실시간 채팅: 클라이언트가 메시지를 보내면 전체 브로드캐스트
@socketio.on('send_message')
def handle_send_message_event(data):
    data['message_id'] = str(uuid.uuid4())
    send(data, broadcast=True)

@socketio.on('join_private')
def handle_join_private(data):
    sender = data['sender_id']
    receiver = data['receiver_id']
    room = f"private_{min(sender, receiver)}_{max(sender, receiver)}"
    join_room(room)
    db = get_db(); cursor = db.cursor()
    cursor.execute(
        """
        SELECT sender_id, receiver_id, content, timestamp
        FROM private_messages
        WHERE (sender_id=? AND receiver_id=?)
           OR (sender_id=? AND receiver_id=?)
        ORDER BY timestamp
        """,
        (sender, receiver, sender, receiver)
    )
    for m in cursor.fetchall():
        emit('new_private_message', {
            'sender_id': m['sender_id'],
            'receiver_id': m['receiver_id'],
            'content': m['content'],
            'timestamp': m['timestamp']
        }, room=room)
    emit('status', {'msg': f'User {sender} entered private chat.'}, room=room)

@socketio.on('private_message')
def handle_private_message(data):
    sender = data['sender_id']
    receiver = data['receiver_id']
    content = data['content']
    room = f"private_{min(sender, receiver)}_{max(sender, receiver)}"
    msg_id = str(uuid.uuid4())
    ts = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    db = get_db(); cursor = db.cursor()
    cursor.execute(
        "INSERT INTO private_messages (id, sender_id, receiver_id, content, timestamp) "
        "VALUES (?,?,?,?,?)",
        (msg_id, sender, receiver, content, ts)
    )
    db.commit()
    emit('new_private_message', {
        'sender_id': sender,
        'receiver_id': receiver,
        'content': content,
        'timestamp': ts
    }, room=room)

if __name__ == '__main__':
    init_db()  # 앱 컨텍스트 내에서 테이블 생성
    socketio.run(app, debug=True)
