# import os # 用於處理操作系統的功能
# from flask import Flask
# from flask_sqlalchemy import SQLAlchemy # 用於整合 SQLAlchemy ORM，以便更方便地與數據庫進行交互
# from flask_migrate import Migrate # 數據庫遷移，幫助管理數據庫結構的變化
# from flask_login import LoginManager
# from dotenv import load_dotenv

# # 加載 .env 文件中的環境變量
# load_dotenv()

# app = Flask(__name__)

# # 從環境變量中讀取密鑰，如果環境變量不存在，則使用預設值
# app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'defaultsecretkey')

# # 配置 PostgreSQL 數據庫 URI
# # 設置 SQLAlchemy 的數據庫 URI，用於連接 PostgreSQL 數據庫
# app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')

# # 禁用 SQLAlchemy 的對象修改追蹤功能，以提高性能並減少內存使用
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# # 初始化資料庫和遷移工具
# db = SQLAlchemy(app) # 初始化 SQLAlchemy 並將其與 Flask 應用綁定
# migrate = Migrate(app, db) # 初始化 Flask-Migrate 並將其與 Flask 應用和 SQLAlchemy 綁定

# # 初始化登入管理
# login_manager = LoginManager() # 創建 LoginManager 實例
# login_manager.init_app(app) # 將 LoginManager 實例初始化並與 Flask 應用綁定
# login_manager.login_view = 'login' # 設置當用戶嘗試訪問受保護頁面但尚未登錄時，重定向的登錄頁面


