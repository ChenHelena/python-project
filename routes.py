import os
from flask import Blueprint, render_template, request, jsonify, session, redirect, url_for, flash, current_app
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from flask_mail import Message
from datetime import datetime
from models import Customer, db
from authlib.integrations.flask_client import OAuth
from flask_login import LoginManager


# 创建一个蓝图对象，将路由关联到该蓝图
routes_bp = Blueprint('routes', __name__)

oauth = OAuth(current_app)

# google 第三方登入
google = oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_OAUTH_ID'),
    client_secret=os.getenv('GOOGLE_OAUTH_KEY'),
    authorize_url='https://accounts.google.com/o/oauth2/auth',  # 添加 authorize_url
    access_token_url='https://oauth2.googleapis.com/token',
    server_metadata_uri='https://accounts.google.com/.well-known/openid-configuration',
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs',
    client_kwargs={'scope': 'openid profile email'}
)

# 初始化 LoginManager
login_manager = LoginManager()  # 初始化 LoginManager


# 這個函數用於通過 user_id 加載用戶對象，並與登入系統綁定
@login_manager.user_loader
def load_user(user_id):
    return Customer.query.get(int(user_id))

# 定义初始化函数
def init_app(app):
    login_manager.init_app(app)  # 将其与应用绑定
    login_manager.login_view = 'routes.login_page'  # 设置未登录时的重定向页面

# 根目录路由
@routes_bp.route("/")
def index():
    return render_template('index.html')


# RESTful API 登录端点
@routes_bp.route("/login", methods=["POST"])
def member_login():
    data = request.json  # 從 POST 請求中獲取 JSON 數據
    print(f"Received data: {data}")

    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        flash('Email and password are required', category='danger')
        return jsonify({"status": "error", "message": "Email and password are required"}), 400

    # 從數據庫查找用戶
    user = Customer.query.filter_by(email=email).first()  # 使用 SQLAlchemy 查询数据库
    print(f"User found: {user}")
    if user:
        # 仅在用户存在时检查密码是否匹配，是 Werkzeug 提供的函数，用于密码验证
        if check_password_hash(user.password, password):
            # 如果密码匹配，则登录用户
            login_user(user)
            return jsonify({"status": "success", "message": "Login successful!", "redirect_url": url_for('routes.dashboard')}), 200
        else:
            # 如果密码不匹配，则返回错误消息
            return jsonify({"status": "error", "message": "帳號密碼錯誤"}), 401
    else:
        # 如果用户不存在，则返回错误消息
        return jsonify({"status": "error", "message": "用戶不存在"}), 401


# 返回登录页面
@routes_bp.route("/login")
def login_page():
    if current_user.is_authenticated:
        return redirect(url_for('routes.dashboard'))
    return render_template('login.html')


# 模拟的登录成功后的页面
@routes_bp.route("/dashboard")
def dashboard():
    if 'email' in session:
        return render_template('dashboard.html', email=session['email'])
    return redirect(url_for('routes.index'))

# 自定义404页面


@routes_bp.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@routes_bp.route("/logout")
@login_required
def logout():
    session.pop('google_token', None)
    logout_user()
    flash('登出成功!', category='success')
    return redirect(url_for('routes.login_page'))


@routes_bp.route("/register")
def register_page():
    return render_template('register.html')


# 增加新的使用者
@routes_bp.route("/register", methods=["POST"])
def register():
    try:
        # 從請求中提取數據
        data = request.json
        name = data.get("name")  # 對應的是 POST 請求中的 "name" 字段
        email = data.get("email")  # 對應的是 POST 請求中的 "email" 字段
        phone = data.get("phone")  # 對應的是 POST 請求中的 "phone" 字段
        password = data.get("password")  # 對應的是 POST 請求中的 "password" 字段
        confirm_password = data.get("confirmPassword")
        role = data.get("role", "customer")  # 默認角色為 customer

        # 检查是否所有必填字段都填写
        if not name or not email or not password or not confirm_password:
            return jsonify({"status": "error", "message": "Missing required fields"}), 400

        if password != confirm_password:
            return jsonify({"status": "error", "message": "Passwords do not match"}), 400

        # 检查用户是否已存在
        existing_user = Customer.query.filter_by(email=email).first()
        if existing_user:
            return jsonify({"status": "error", "message": "信箱已經註冊過"}), 400

        hashed_password = generate_password_hash(
            password)  # 使用 werkzeug.security 生成密碼哈希

        # 創建新的 Customer 實例
        new_customer = Customer(
            name=name,
            email=email,
            phone=phone,
            password=hashed_password,
            is_verified=False,  # 初始設置為未驗證
            role=role,
            created_at=datetime.utcnow()
        )

        # 將新使用者添加到資料庫
        db.session.add(new_customer)
        db.session.commit()  # 提交更改

        # 發送驗證郵件
        with current_app.app_context():
            # 发送验证邮件
            email_response_data = send_verification_email(email)
            print("Email response data:", email_response_data)

        # 根据邮件发送结果生成响应
        if email_response_data['status'] == 'success':
            return jsonify({
                "status": "success",
                "message": "Registration successful, please check your email to verify your account.",
                "redirect_url": url_for('routes.login_page'),
                "type": "verification_email_sent"
            }), 201
        else:
            return jsonify({
                "status": "error",
                "message": email_response_data['message']
            }), 500

    except Exception as e:
        db.session.rollback()  # 如果有錯誤，回滾事務
        return jsonify({"status": "error", "message": f"註冊失敗： 請稍後再試。"}), 500


# 定义发送验证邮件的函数
def send_verification_email(email):
    print("Attempting to send verification email to:", email)  # 添加调试信息
    # 生成一个简单的验证链接
    verification_link = url_for(
        'routes.verify_email', email=email, _external=True)

    msg = Message(
        subject="Please Verify Your Email Address",
        recipients=[email],
        body=f"Hi,\n\nPlease verify your email address by clicking the following link:\n{verification_link}\n\nThank you!"
    )

    try:
        with current_app.app_context():  # 确保在应用上下文中发送邮件
            current_app.extensions['mail'].send(msg)
        return {"status": "success", "message": "Verification email sent successfully."}
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to send email: 請稍後再試。"})

# 定义验证邮件的路由
@routes_bp.route('/verify/<email>', methods=['GET'])
def verify_email(email):
    user = Customer.query.filter_by(email=email).first()
    if user:
        if user.is_verified:
            return jsonify({"status": "error", "message": "User not found"}), 404
        else:
            user.is_verified = True
            db.session.commit()
            return jsonify({"status": "error", "message": "User already verified"}), 400
    return redirect(url_for('routes.login_page'))  # 将用户重定向到登录页面


@routes_bp.route("/customers")
def get_customers():
    try:
        customers = Customer.query.all()  # 使用 SQLAlchemy 的查詢 API
        customer_list = [{
            "id": customer.id,
            "name": customer.name,
            "email": customer.email,
            "phone": customer.phone,
            "role": customer.role,
            "created_at": customer.created_at
        } for customer in customers]  # 創建一個新的列表: 是為了將數據格式化為一個適合返回給客戶端的格式
        return jsonify(customer_list), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Google 授權處理
@routes_bp.route("/authorize/google")
def authorize_google():
    token = google.authorize_access_token()  # 從 Google 拿到訪問令牌
    current_app.logger.info(f"Token: {token}")
    user_info = token['userinfo']
    current_app.logger.info(f"User info: {user_info}")
    email = user_info['email']
    name = user_info['name']

    user = Customer.query.filter_by(email=email).first()  # 從數據庫查找該 email 的用戶
    if not user:  # 如果用戶不存在，則創建新用戶
        user = Customer(email=email, name=name)
        db.session.add(user)
        db.session.commit()

    session['email'] = email
    session['oauth_token'] = token

    return redirect(url_for('routes.dashboard'))

# Google 登錄重定向


@routes_bp.route("/login/google")
def login_google():
    try:
        redirect_uri = url_for(
            'routes.authorize_google', _external=True)  # 構建 Google 重定向 URI
        current_app.logger.info(f"Redirect URI: {redirect_uri}")
        return google.authorize_redirect(redirect_uri)  # 重定向用戶到 Google 的授權頁面
    except Exception as e:
        current_app.logger.error(f"error:請稍後再試。")
        return "Error", 500
