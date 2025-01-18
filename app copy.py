# from flask import Flask, render_template, request, jsonify, url_for
# from flask_login import LoginManager
# login_manager = LoginManager()
# app=Flask(__name__)

# me1 = {
#     'email': 'jj@gmail.com',
#     'password': '123'
# }

# @app.route("/")
# def index():
#     return render_template('index.html')

# @app.route("/login", methods=['POST'])
# def member_login():
#     data = request.json #檢查接收到的內容
#     print(f"Received data: {data}")

#     email = data.get("email")
#     password = data.get("password")

#     if email == me1['email'] and password == me1['password']:
#         # 登录成功，重定向到另一个页面（例如 "/dashboard"）
#         return jsonify({"status": "success", "message": "Login successful!", "redirect_url": url_for('dashboard')}), 200
#     else:
#         # 登录失败，返回 401 状态码和错误消息
#         return jsonify({"status": "error", "message": "Invalid credentials, please try again."}), 401
# # 返回登录页面
# @app.route("/login")
# def login_page():
#     return render_template('login.html')

# # 模拟的登录成功后的页面
# @app.route("/dashboard")
# def dashboard():
#     return render_template('dashboard.html')

    
# if __name__ =='__main__':
#     app.run(debug=True)



import os
# models.py
from datetime import datetime
# from flask_login import UserMixin
from flask import Blueprint, Flask, render_template, request, jsonify, url_for, abort, flash, redirect, session
from flask_sqlalchemy import SQLAlchemy  # 用於整合 SQLAlchemy ORM，以便更方便地與數據庫進行交互
from flask_migrate import Migrate  # 數據庫遷移，幫助管理數據庫結構的變化
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from dotenv import load_dotenv # 用來讀取 .env 文件中的環境變量
# 使用 werkzeug.security 進行密碼哈希和驗證
from werkzeug.security import generate_password_hash, check_password_hash
# 创建 Google 和 Facebook 的 OAuth 客户端
from authlib.integrations.flask_client import OAuth
from flask_mail import Mail, Message

from models import Customer
# 从 routes 导入蓝图
from routes import routes_bp


# 載入 .env 文件中的環境變數
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')   # 設置應用的密鑰



# 配置郵件設置
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')  
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')  

mail = Mail(app)

# 初始化 LoginManager
login_manager = LoginManager()  # 初始化 LoginManager
login_manager.init_app(app)  # 將其與應用綁定
login_manager.login_view = 'routes.login_page'  # 設置未登入時的重定向頁面

# 注册蓝图
app.register_blueprint(routes_bp)

oauth = OAuth(app)

# google 第三方登入
google = oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_OAUTH_ID'),
    client_secret=os.getenv('GOOGLE_OAUTH_KEY'),
    authorize_url='https://accounts.google.com/o/oauth2/auth',  # 添加 authorize_url
    access_token_url='https://oauth2.googleapis.com/token',
    server_metadata_uri='https://accounts.google.com/.well-known/openid-configuration',
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs',
    client_kwargs={'scope':'openid profile email'}
)

# 配置 PostgreSQL 數據庫 URI
# 從環境變量中讀取數據庫 URI
#app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres@localhost:5432/pigout_db'
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')

# 禁用 SQLAlchemy 的對象修改追蹤功能，以提高性能並減少內存使用
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

#1. 檢查資料庫連線配置
print(f"Database URI: {app.config['SQLALCHEMY_DATABASE_URI']}")

# 初始化資料庫和遷移工具
db = SQLAlchemy(app) # 初始化 SQLAlchemy 並將其與 Flask 應用綁定
migrate = Migrate(app, db) # 初始化 Flask-Migrate 並將其與 Flask 應用和 SQLAlchemy 綁定



# 2.建立簡單的資料庫查詢來測試連線
# Customer 模型 --- Customer 資料表(對應欄位Column)

# 這個函數用於通過 user_id 加載用戶對象，並與登入系統綁定
@login_manager.user_loader
def load_user(user_id):
    return Customer.query.get(int(user_id))


@app.route("/")
def index():
    return render_template('index.html')


# RESTful API 登录端点
@app.route("/login", methods=["POST"])
def member_login():
    data = request.json # 從 POST 請求中獲取 JSON 數據
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
            return jsonify({"status": "success", "message": "Login successful!", "redirect_url": url_for('dashboard')}), 200
        else:
            # 如果密码不匹配，则返回错误消息
            return jsonify({"status": "error", "message": "帳號密碼錯誤"}), 401
    else:
        # 如果用户不存在，则返回错误消息
        return jsonify({"status": "error", "message": "用戶不存在"}), 401


# 返回登录页面
@app.route("/login")
def login_page():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('login.html')


# 模拟的登录成功后的页面
@app.route("/dashboard")
def dashboard():
    if 'email' in session:
        return render_template('dashboard.html', email=session['email'])
    return redirect(url_for('index'))

# 自定义404页面
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.route("/logout")
@login_required
def logout():
    session.pop('google_token', None)
    logout_user()
    flash('登出成功!', category='success')
    return redirect(url_for('login_page'))


@app.route("/register")
def register_page():
    return render_template('register.html')


# 增加新的使用者
@app.route("/register", methods=["POST"])
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

        hashed_password = generate_password_hash(password)  # 使用 werkzeug.security 生成密碼哈希
        

        
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
        with app.app_context():
            # 发送验证邮件
            email_response_data = send_verification_email(email)
            print("Email response data:", email_response_data)

        # 根据邮件发送结果生成响应
        if email_response_data['status'] == 'success':
            return jsonify({
                "status": "success",
                "message": "Registration successful, please check your email to verify your account.",
                "redirect_url": url_for('login_page'),
                "type": "verification_email_sent"
            }), 201
        else:
            return jsonify({
                "status": "error",
                "message": email_response_data['message']
            }), 500
        
    except Exception as e:
        db.session.rollback()  # 如果有錯誤，回滾事務
        return jsonify({"status": "error", "message": f"註冊失敗： {str(e)}"}), 500
    
    
# 定义发送验证邮件的函数
def send_verification_email(email):
    print("Attempting to send verification email to:", email)  # 添加调试信息
    # 生成一个简单的验证链接
    verification_link = url_for('verify_email', email=email, _external=True)

    msg = Message(
        subject="Please Verify Your Email Address",
        recipients=[email],
        body=f"Hi,\n\nPlease verify your email address by clicking the following link:\n{verification_link}\n\nThank you!"
    )

    try:
        with app.app_context():  # 确保在应用上下文中发送邮件
            mail.send(msg)
        return {"status": "success", "message": "Verification email sent successfully."}
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to send email: {str(e)}"})

# 定义验证邮件的路由
@app.route('/verify/<email>', methods=['GET'])
def verify_email(email):
    user = Customer.query.filter_by(email=email).first()
    if user:
        if user.is_verified:
            return jsonify({"status": "error", "message": "User not found"}), 404
        else:
            user.is_verified = True
            db.session.commit()
            return jsonify({"status": "error", "message": "User already verified"}), 400
    return redirect(url_for('login_page'))  # 将用户重定向到登录页面

@app.route("/customers")
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
@app.route("/authorize/google")
def authorize_google():
    token = google.authorize_access_token()  # 從 Google 拿到訪問令牌
    app.logger.info(f"Token: {token}")
    user_info = token['userinfo']
    app.logger.info(f"User info: {user_info}")
    email = user_info['email']
    name = user_info['name']

    user = Customer.query.filter_by(email=email).first()  # 從數據庫查找該 email 的用戶
    if not user:  # 如果用戶不存在，則創建新用戶
        user = Customer(email=email, name=name)
        db.session.add(user)
        db.session.commit()

    session['email'] = email
    session['oauth_token'] = token

    return redirect(url_for('dashboard'))

# Google 登錄重定向
@app.route("/login/google")
def login_google():
    try:
        redirect_uri = url_for(
            'authorize_google', _external=True)  # 構建 Google 重定向 URI
        app.logger.info(f"Redirect URI: {redirect_uri}")
        return google.authorize_redirect(redirect_uri)  # 重定向用戶到 Google 的授權頁面
    except Exception as e:
        app.logger.error(f"error:{str(e)}")
        return "Error", 500



if __name__ == "__main__":
    app.run(debug=True)


