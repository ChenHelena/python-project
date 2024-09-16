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
from datetime import datetime
from flask import Flask, render_template, request, jsonify, url_for, abort, flash, redirect
from flask_sqlalchemy import SQLAlchemy  # 用於整合 SQLAlchemy ORM，以便更方便地與數據庫進行交互
from flask_migrate import Migrate  # 數據庫遷移，幫助管理數據庫結構的變化
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from dotenv import load_dotenv # 用來讀取 .env 文件中的環境變量
# 使用 werkzeug.security 進行密碼哈希和驗證
from werkzeug.security import generate_password_hash, check_password_hash


# 載入 .env 文件中的環境變數
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')   # 設置應用的密鑰

# 初始化 LoginManager
login_manager = LoginManager()  # 初始化 LoginManager
login_manager.init_app(app)  # 將其與應用綁定
login_manager.login_view = 'login_page'  # 設置未登入時的重定向頁面

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
class Customer(db.Model, UserMixin):
    __tablename__ = 'Customer'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

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
        flash('Email and password are required', category='error')
        return jsonify({"status": "error", "message": "Email and password are required"}), 400

    # 從數據庫查找用戶
    user = Customer.query.filter_by(email=email).first()  # 使用 SQLAlchemy 查询数据库
    print(f"User found: {user}")
    if user:
        # 仅在用户存在时检查密码是否匹配，是 Werkzeug 提供的函数，用于密码验证
        if check_password_hash(user.password, password):
            # 如果密码匹配，则登录用户
            login_user(user)
            flash('Welcome back!', category='success')  # 登录成功消息
            return jsonify({"status": "success", "message": "Login successful!", "redirect_url": url_for('dashboard')}), 200
        else:
            # 如果密码不匹配，则返回错误消息
            flash('Invalid credentials, please try again.', category='error')
            return jsonify({"status": "error", "message": "Invalid credentials, please try again."}), 401
    else:
        # 如果用户不存在，则返回错误消息
        flash('Invalid credentials, please try again.', category='error')
        return jsonify({"status": "error", "message": "Invalid credentials, please try again."}), 401
        

# 返回登录页面
@app.route("/login")
def login_page():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

# 模拟的登录成功后的页面
@app.route("/dashboard")
def dashboard():
    return render_template('dashboard.html')

# 自定义404页面
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash('登出成功!', category='success')
    return redirect(url_for('login_page'))

# 增加新的使用者
@app.route("/add_customer", methods=["POST"])
def add_customer():
    try:
        # 從請求中提取數據
        data = request.json
        name = data.get("name")  # 對應的是 POST 請求中的 "name" 字段
        email = data.get("email")  # 對應的是 POST 請求中的 "email" 字段
        phone = data.get("phone")  # 對應的是 POST 請求中的 "phone" 字段
        password = data.get("password")  # 對應的是 POST 請求中的 "password" 字段
        role = data.get("role", "customer")  # 默認角色為 customer
        
        # 檢查是否所有必填欄位都有填寫
        if not name or not email or not password:
            return jsonify({"error": "Missing required fields"}), 400

        hashed_password = generate_password_hash(password)  # 使用 werkzeug.security 生成密碼哈希
        

        
        # 創建新的 Customer 實例
        new_customer = Customer(
            name=name,
            email=email,
            phone=phone,
            password=hashed_password,
            role=role,
            created_at=datetime.utcnow()
        )
        
        # 將新使用者添加到資料庫
        db.session.add(new_customer)
        db.session.commit()  # 提交更改
        
        return jsonify({"message": "Customer added successfully!"}), 201
    except Exception as e:
        db.session.rollback()  # 如果有錯誤，回滾事務
        return jsonify({"error": str(e)}), 500

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



if __name__ == "__main__":
    app.run(debug=True)


