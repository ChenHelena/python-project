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
from flask import Blueprint, Flask, render_template, request, jsonify, url_for, abort, flash, redirect, session
from flask_sqlalchemy import SQLAlchemy  # 用於整合 SQLAlchemy ORM，以便更方便地與數據庫進行交互
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from dotenv import load_dotenv # 用來讀取 .env 文件中的環境變量
# 使用 werkzeug.security 進行密碼哈希和驗證
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from models import db, migrate
# 从 routes 导入蓝图
from routes import routes_bp, init_app



# 邮件初始化
mail = Mail()


def create_app():

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


    # 配置 PostgreSQL 數據庫 URI
    # 從環境變量中讀取數據庫 URI
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')

    # 禁用 SQLAlchemy 的對象修改追蹤功能，以提高性能並減少內存使用
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # 1. 檢查資料庫連線配置
    print(f"Database URI: {app.config['SQLALCHEMY_DATABASE_URI']}")

    # 初始化扩展
    db.init_app(app)
    migrate.init_app(app, db)
    mail.init_app(app)

    # 调用 init_app 初始化 LoginManager
    init_app(app)

    # 注册蓝图
    app.register_blueprint(routes_bp)   

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)


