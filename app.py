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

