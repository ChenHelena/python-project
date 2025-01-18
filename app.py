import os
import sys
sys.path.append('/Users/helenachen/Documents/python-project')
from flask import Flask
from dotenv import load_dotenv # 用來讀取 .env 文件中的環境變量
from flask_mail import Mail
from models import db, migrate
from flask_redis import FlaskRedis




# 邮件初始化
mail = Mail()

# 初始化 Redis 客户端
redis_client = FlaskRedis()

# 定義 create_app 函數，這是 Flask 的工廠模式，用於創建並配置應用實例
def create_app():
    
    # 載入 .env 文件中的環境變數
    load_dotenv()

    app = Flask(__name__)
    app.secret_key = os.getenv('SECRET_KEY')   # 設置應用的密鑰
    print(f"SECRET_KEY: {app.secret_key}")


    # 配置郵件設置
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')

    # 設置 Redis 的 URL
    app.config['REDIS_URL'] = "redis://localhost:6379/0"  

    # 獲取 Line pay id & key
    app.config['LINE_PAY_ID'] = os.getenv('LINE_PAY_ID')
    app.config['LINE_PAY_KEY'] = os.getenv('LINE_PAY_KEY')

    # 建立應用程式時配置 OAUTH2_PROVIDERS
    app.config['OAUTH2_PROVIDERS'] = {
        'google': {
            'client_id': os.getenv('GOOGLE_OAUTH_ID'),
            'client_secret': os.getenv('GOOGLE_OAUTH_KEY'),
            'authorize_url': 'https://accounts.google.com/o/oauth2/auth',
            'access_token_url': 'https://oauth2.googleapis.com/token',
            'refresh_token_url': None,
            'server_metadata_uri': 'https://accounts.google.com/.well-known/openid-configuration',
            'jwks_uri': 'https://www.googleapis.com/oauth2/v3/certs',
            'client_kwargs': {'scope': 'openid profile email'},
            'redirect_uri': 'http://127.0.0.1:5000/authorize/google'
        }
    }



    # 配置 PostgreSQL 數據庫 URI
    # 從環境變量中讀取數據庫 URI
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')

    # 禁用 SQLAlchemy 的對象修改追蹤功能，以提高性能並減少內存使用
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # 1. 檢查資料庫連線配置
    print(f"Database URI: {app.config['SQLALCHEMY_DATABASE_URI']}")

    # 初始化扩展，init_app() 函數調用 Flask 擴展（SQLAlchemy、Flask-Migrate 和 Flask-Mail）的初始化方法
    db.init_app(app)
    migrate.init_app(app, db)
    mail.init_app(app)
    redis_client.init_app(app)


    # 从 routes 导入蓝图
    from routes import routes_bp, init_app
    # 调用 init_app 初始化 LoginManager，調用 routes.py 的 init_app() 函數
    init_app(app)

    

    # 注册蓝图
    app.register_blueprint(routes_bp)   

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)

