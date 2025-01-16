import os
from flask import Blueprint, render_template, request, jsonify, session, redirect, url_for, flash, current_app, abort
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from flask_mail import Message
from datetime import datetime
from models import Customer, DeliveryPerson, Vendor, MenuItem, CartItem, Payment, Order, OrderItem, db
from authlib.integrations.flask_client import OAuth
from flask_login import LoginManager
import requests
import uuid
import hmac
import hashlib
import json
import base64
import secrets
from urllib.parse import urlencode

# 建立一個藍圖對象，將路由關聯到該藍圖
routes_bp = Blueprint('routes', __name__)

oauth = OAuth(current_app)

# google 第三方登入
google = oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_OAUTH_ID'),
    client_secret=os.getenv('GOOGLE_OAUTH_KEY'),
    authorize_url='https://accounts.google.com/o/oauth2/auth',  # 添加 authorize_url
    access_token_url='https://oauth2.googleapis.com/token',
    refresh_token_url=None,  # 如果需要刷新令牌，可以提供 URL
    server_metadata_uri='https://accounts.google.com/.well-known/openid-configuration',
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs',
    client_kwargs={'scope': 'openid profile email'},
    redirect_uri=None # 默認的重定向可以不指定
)

# 初始化 LoginManager
login_manager = LoginManager()  # 初始化 LoginManager


# 這個函數用於通過 user_id 加載用戶對象，並與登入系統綁定
@login_manager.user_loader
def load_user(user_id):
    role = session.get('role')  # 从 session 获取用户角色
    if role == 'customer':
        return Customer.query.get(user_id)
    elif role == 'vendor':
        return Vendor.query.get(user_id)
    elif role == 'delivery':
        return DeliveryPerson.query.get(user_id)

# 定義初始化函數
def init_app(app):
    login_manager.init_app(app)  # 将其与应用绑定
    login_manager.login_view = 'routes.login_page'  # 设置未登录时的重定向页面

# 根目錄路由
@routes_bp.route("/")
def index():
    vendors = Vendor.query.all()
    return render_template('index.html', vendors=vendors)

# 渲染訂單頁面資料
@routes_bp.route("/order/<int:vendor_id>")
def order(vendor_id):
    # 將 vendor_id 儲存到 session 中，以便後續使用
    session['vendor_id'] = vendor_id

    menu_items = MenuItem.query.filter_by(vendor_id=vendor_id, available=True).all()
    data = {
        "vendor_id": vendor_id,
        "menu_items": menu_items,
    } 
    
    # ** 用於將字典中的內容作為關鍵字參數傳遞給 render_template 函數，以便在模板中訪問這些值
    return render_template('customer/order.html', **data)


# RESTful API 登录端点
@routes_bp.route("/login", methods=["POST"])
def member_login():
    data = request.json  # 從 POST 請求中獲取 JSON 數據
    print(f"Received data: {data}")
    role = request.args.get("role")  # 从查询参数获取 role
    print(f"Received role: {role}")

    if not role:
        return jsonify({"status": "error", "message": "Role is required"}), 400

    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        flash('Email and password are required', category='danger')
        return jsonify({"status": "error", "message": "Email and password are required"}), 400

    # 從數據庫查找用戶
    # 根据角色来查询不同的表
    if role == 'vendor':
        user = Vendor.query.filter_by(email=email).first()
    elif role == 'deliveryPerson':
        user = DeliveryPerson.query.filter_by(email=email).first()
    elif role == 'customer':
        user = Customer.query.filter_by(email=email).first()
    print(f"User found: {user}")
    if user:
        # 仅在用户存在时检查密码是否匹配，是 Werkzeug 提供的函数，用于密码验证
        if check_password_hash(user.password, password):
            session['role'] = user.role
            session['customer_id'] = user.id
            # 如果密码匹配，则登录用户
            login_user(user)

            if user.role == 'customer':
                return render_template('dashboard.html')  # 直接渲染客户仪表板
            elif user.role == 'vendor':
                return render_template('vendor/dashboard.html')  # 直接渲染商家仪表板
            elif user.role == 'deliveryPerson':
                return render_template('dashboard.html')  # 直接渲染外送员仪表板
            
            flash('登入成功!', category='success')
        else:
            # 如果密码不匹配，则返回错误消息
            flash('帳號密碼錯誤', category='danger')
            return redirect(url_for('login_page'))
    else:
        # 如果用户不存在，则返回错误消息
        flash('用戶不存在', category='danger')


# 消費者返回登录页面
@routes_bp.route("/login")
def login_page():
    print(f"User authenticated: {current_user.is_authenticated}")
    if current_user.is_authenticated:
        return redirect(url_for('routes.dashboard'))
    flash('請先登入', category='danger')
    return render_template('shared/login.html')

# 模拟的登录成功后的页面
@routes_bp.route("/dashboard")
@login_required  # 需要用户登录
def dashboard():
    print(f"Current user: {current_user}")
    if current_user.is_authenticated:
        # 根据用户角色重定向到不同的 Dashboard
        if current_user.role == 'customer':
            return render_template('dashboard.html', email=current_user.email, user=current_user)
        elif current_user.role == 'vendor':
            return render_template('vendor/dashboard.html', email=current_user.email, user=current_user)
        elif current_user.role == 'delivery':
            return render_template('dashboard.html', email=current_user.email, user=current_user)
        else:
            flash('找不到角色', category='danger')
            return redirect(url_for('routes.login_page'))
    return redirect(url_for('routes.index'))

# 自定義404頁面
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
    return render_template('shared/register.html')


# 增加新的使用者
@routes_bp.route("/register", methods=["POST"])
def register():
    try:
        current_app.logger.info(f"Role in session: {session.get('role')}")
        # 從請求中提取數據
        data = request.json
        name = data.get("name")  # 對應的是 POST 請求中的 "name" 字段
        email = data.get("email")  # 對應的是 POST 請求中的 "email" 字段
        phone = data.get("phone")  # 對應的是 POST 請求中的 "phone" 字段
        password = data.get("password")  # 對應的是 POST 請求中的 "password" 字段
        confirm_password = data.get("confirmPassword")
        role = session.get('role')  # 默認角色為 customer
        current_app.logger.info(f"Role received in session: {role}")


        # 检查是否所有必填字段都填写
        if not name or not email or not password or not confirm_password:
            return jsonify({"status": "error", "message": "Missing required fields"}), 400

        if password != confirm_password:
            return jsonify({"status": "error", "message": "Passwords do not match"}), 400

        # 检查用户是否已存在
        if role == 'vendor':
            existing_user = Vendor.query.filter_by(email=email).first()
        elif role == 'delivery':
            existing_user = DeliveryPerson.query.filter_by(email=email).first()
        elif role == 'customer':
            existing_user = Customer.query.filter_by(email=email).first()

        if existing_user:
            return jsonify({"status": "error", "message": "信箱已經註冊過"}), 400

        hashed_password = generate_password_hash(
            password)  # 使用 werkzeug.security 生成密碼哈希

        # 創建新的實例
        if role == 'vendor':
            new_user = Vendor(name=name, email=email, phone=phone, password=hashed_password, is_verified=False, role=role, created_at=datetime.utcnow())
        elif role == 'delivery':
            new_user = DeliveryPerson(name=name, email=email, phone=phone,           password=hashed_password, is_verified=False, role=role, created_at=datetime.utcnow())
        else:
            new_user = Customer(name=name, email=email, phone=phone,password=hashed_password, is_verified=False, role=role, created_at=datetime.utcnow())

        # 將新使用者添加到資料庫
        db.session.add(new_user)
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
        return jsonify({"status": "success", "message": "Verification email sent successfully."})
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to send email: 請稍後再試。"})

# 定义验证邮件的路由
@routes_bp.route('/verify/<email>', methods=['GET'])
def verify_email(email):
    current_app.logger.info(f"Verifying email: {email}")  # 添加调试信息
    user = Customer.query.filter_by(email=email).first() or \
        Vendor.query.filter_by(email=email).first() or \
        DeliveryPerson.query.filter_by(email=email).first()

    if user:
        if not user.is_verified:
            user.is_verified = True  # 将用户的is_verified状态设置为True
            db.session.commit()  # 提交数据库更改
            flash("验证成功，请登录。", category='success')  # 显示验证成功消息
        else:
            flash("邮箱已验证，请直接登录。", category='info')  # 如果已验证，提示用户直接登录

        return redirect(url_for('routes.login_page'))  # 重定向到登录页面
    else:
        flash("未找到用户，请重新注册。", category='danger')  # 如果未找到用户，显示相应消息
        return redirect(url_for('routes.register'))  # 重定向到注册页面


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
@routes_bp.route('/authorize/<provider>')
def oauth2_authorize(provider):
    # 用戶已登入，則導向 index 頁面
    if not current_user.is_anonymous:
        return redirect(url_for('routes.index'))
    
    # 從配置中獲取 OAuth2 訊息
    provider_data = current_app.config['OAUTH2_PROVIDERS'].get(provider)
    if provider_data is None:
        abort(404)  # 如果資訊不存在，回傳 404

    # 創建了隨機的 state 參數，防止 CSRF 攻擊
    session['oauth2_state'] = secrets.token_urlsafe(16)

    # 建置 OAuth2 請求參數
    qs = urlencode({
        'client_id': provider_data['client_id'],  # 客戶端 ID
        'redirect_uri': url_for('oauth2_callback', provider=provider, _external=True),  # 回調 URI
        'response_type': 'code',  # 請求授權碼
        'scope': ' '.join(provider_data['scopes']),  # 請求的權限範圍（將 scope 列表合併為一個空格分隔的字串）
        'state': session['oauth2_state'],  # 防止 CSRF 攻擊的隨機值
    })

    # 產生授權請求 URL，例如：google 授權頁面 URL
    authorization_url = f"{provider_data['authorization_endpoint']}?{qs}"

    # 重定向到 OAuth2 授權頁面
    return redirect(authorization_url)

# Google callback 回調
@routes_bp.route('/callback/<provider>', methods=['GET'])
def oauth2_callback(provider):
    if provider != 'google':
        flash("不支持的授权提供商", category="danger")
        return redirect(url_for('routes.index'))  # 如果不是 Google，重定向到首頁
    
    try:
        token = google.authorize_access_token()  # 從 Google 拿到訪問令牌
        user_info = token['userinfo']
        current_app.logger.info(f"User info: {user_info}")
        email = user_info['email']
        name = user_info['name']
        role = session.get('role')
        action = request.args.get('action')

        if role not in ['delivery', 'vendor', 'customer']:
            flash('無效的使用者', category='danger')
            return jsonify({"status": "danger", "message": "無效的使用者"}), 400  # 处理无效角色
        
        # 查找用户
        if role == 'delivery':  # 如果是外送员
            user = DeliveryPerson.query.filter_by(email=email).first()
        elif role == 'vendor':  # 如果是商家
            user = Vendor.query.filter_by(email=email).first()
        elif role == 'customer':  # 如果是消费者
            user = Customer.query.filter_by(email=email).first()
        else:
            return "Invalid role", 400  # 处理无效角色

        if action == 'login':
            if user:
                # 用户已存在，直接登录
                login_user(user) 
                flash("欢迎回来！", category='success')  # 显示欢迎消息
                if user.role == 'customer':
                    # 直接重定向到顧客 Dashboard
                    session['customer_id'] = user.id
                    return render_template('dashboard.html')  # 直接渲染商家仪表板
                elif user.role == 'vendor':
                    # 直接重定向到商家 Dashboard
                    return render_template('vendor/dashboard.html')  # 直接渲染商家仪表板
                elif user.role == 'delivery':
                    return render_template('dashboard.html')  # 直接渲染商家仪表板
            else:
                flash("用户不存在，请注册。", category='danger')
                return redirect(url_for('routes.register'))  # 跳转到注册页面
        elif action == 'register':
            if user:
                flash("用户已存在，正在跳转到登录页面。", category='info')
                return redirect(url_for('routes.login_page'))  # 跳转到登录页面
            else:
                # 用户不存在，创建新用户并登录
                if role == 'delivery':
                    user = DeliveryPerson(
                        email=email, name=name, role=role, is_verified=False)
                elif role == 'vendor':
                    user = Vendor(email=email, name=name,
                                role=role, is_verified=False)
                elif role == 'customer':
                    user = Customer(email=email, name=name,
                                    role=role, is_verified=False)


            db.session.add(user)
            db.session.commit()
            send_verification_email(user.email)  # 发送验证邮件
            flash("已发送验证邮件，请检查您的邮箱。", category='info')  # 添加发送邮件的消息

            return redirect(url_for('routes.register'))
    except Exception as e:
        current_app.logger.error(f"OAuth2 回調出錯: {str(e)}")
        flash("授權失敗請重試", category="danger")
        return redirect(url_for('routes.index'))  # 授權失敗，重定向到首頁


# Google 登錄重定向
@routes_bp.route("/login/google")
def login_google():
    try:
        role = request.args.get('role')
        session['role'] = role
        current_app.logger.info(f"Google OAuth client_id: {os.getenv('GOOGLE_OAUTH_ID')}")
        current_app.logger.info(f"Google OAuth client_secret: {os.getenv('GOOGLE_OAUTH_KEY')}")

        provider = 'google'
        redirect_uri = url_for('routes.oauth2_authorize', provider=provider, _external=True)
        current_app.logger.info(f"Redirect URI: {redirect_uri}")
        return google.authorize_redirect(redirect_uri)
    except Exception as e:
        current_app.logger.error(f"Error in login_google: {str(e)}")
        return f"Error: {str(e)}", 500
    
# Google 註冊重定向
@routes_bp.route("/register/google")
def login_register():
    try:
        role = request.args.get('role')
        session['role'] = role
        provider = 'google'
        redirect_uri = url_for('routes.oauth2_authorize', provider=provider, _external=True)
        return google.authorize_redirect(redirect_uri)  # 重定向用戶到 Google 的授權頁面
    except Exception as e:
        current_app.logger.error(f"error:請稍後再試。")
        return "Error", 500
    
# 生成隨機 nonce 使用 UUID
def generate_nonce():
    return str(uuid.uuid4()) 

# 計算 HMAC SHA256
def calculate_hmac(channel_key, uri, body, nonce):
    body_str = json.dumps(body)  # 将请求体转换为标准的 JSON 字符串
    message = f"{channel_key}{uri}{body_str}{nonce}"  # 构建用于 HMAC 的消息
    
    # 打印调试信息
    print(f"Channel Key: {channel_key}")
    print(f"URI: {uri}")
    print(f"Body String: {body_str}")
    print(f"Nonce: {nonce}")
    print(f"Message for HMAC: {message}")
    
    # 计算 HMAC
    hmac_hash = hmac.new(channel_key.encode('utf-8'), message.encode('utf-8'), hashlib.sha256).digest()
    
    # 转换为 Base64 编码
    hmac_base64 = base64.b64encode(hmac_hash).decode()
    print(f"HMAC Hash: {hmac_hash}")
    print(f"HMAC Base64: {hmac_base64}")
    return hmac_base64

# 串接 line pay
@routes_bp.route("/linepay/request", methods=['POST'])
def line_pay_connection():
    LINE_PAY_ID = current_app.config['LINE_PAY_ID']
    LINE_PAY_KEY = current_app.config['LINE_PAY_KEY']
    print(f"Channel ID: {LINE_PAY_ID}, Channel Key: {LINE_PAY_KEY}") 
    url = "https://sandbox-api-pay.line.me/v3/payments/request"
    # 生成 nonce
    nonce = generate_nonce()

    # 从请求中获取购物车数据
    cart_items = request.json.get('cart', [])
    print("cart_items", cart_items)
    
    # 计算总金额
    total_price = sum(int(float(item['price'])) * int(item['quantity']) for item in cart_items)
    
    
    customer_id = session.get('customer_id')
    vendor_id = session.get('vendor_id')
    print('customer_id:', customer_id, 'vendor_id', vendor_id)

    
    # 创建订单并保存到数据库
    order = Order(total_price=total_price, customer_id=customer_id, vendor_id=vendor_id, status='pending', order_time=datetime.utcnow())
    db.session.add(order)  # 将订单添加到数据库

    # 提交事务，保存到数据库
    db.session.commit()  # 提交事务，生成 order.id

    # 在提交后获取 order.id
    order_id = order.id

    # 创建订单项并保存到数据库
    for item in cart_items:
        order_item = OrderItem(
            order_id=order_id,  # 使用正确的 order_id
            quantity=item['quantity'],
            price=int(float(item['price']))  # 转换为整数以匹配你的数据库字段
        )
        db.session.add(order_item)

    # 提交订单项
    db.session.commit()
    # 构建 packages 信息
    packages = [
        {
            "id": f"package_{i+1:03}",
            "amount": int(float(item['price']) * int(item['quantity'])),
            "name": f"{item['name']} Package",
            "products": [
                {
                    "id": item['id'],
                    "name": item['name'],
                    "quantity": int(item['quantity']),
                    "price": int(float(item['price']))
                }
            ]
        }
        for i, item in enumerate(cart_items)
    ]
    
    body = {
        "amount": total_price,
        "currency": "TWD",
        "orderId": order.id,
        "packages": packages,
        "redirectUrls": {
            "confirmUrl": "http://127.0.0.1:5000/payment/confirm",
            "cancelUrl": "http://127.0.0.1:5000/payment/cancel"
        },
        "extras": {
            "amountDetail": {
                "subtotal": total_price,
                "shippingFee": 0,
                "tax": 0,
                "totalAmount": total_price
            }
        }
    }

    # 打印请求体，便于调试
    print(f"Request Body: {json.dumps(body)}")

    
    # 計算 HMAC
    uri = "/v3/payments/request"
    hmac_hash = calculate_hmac(LINE_PAY_KEY, uri, body, nonce)
    

    headers = {
        "Content-Type": "application/json",
        "X-LINE-ChannelId": LINE_PAY_ID,
        'X-LINE-Authorization-Nonce': nonce,
        'X-LINE-Authorization': hmac_hash,
    }


    print(f"Request Body: {json.dumps(body)}")
    print(f"Headers: {headers}")

    response = requests.post(url, json=body, headers=headers)
    print(f"Response Status: {response.status_code}, Body: {response.text}")
    
    return jsonify(response.json())

@routes_bp.route("/check-login-status")
def check_login_status():
    if not current_user.is_authenticated:
        flash('請先登入', category='danger')
        return redirect(url_for('routes.login_page'))  # 重定向到登入頁面
    else:
        return jsonify({'isLoggedIn': True}), 200

# line pay 付款確認
@routes_bp.route("/payment/confirm", methods=['GET'])
def payment_confirm():
    # 处理 GET 请求和 POST 请求
    transaction_id = request.args.get('transactionId')
    order_id = request.args.get('orderId')
    print(f"Received transactionId: {transaction_id}, orderId: {order_id}")

    if not transaction_id or not order_id:
        return jsonify({"error": "Missing transactionId or orderId"}), 400
    
    LINE_PAY_ID = current_app.config['LINE_PAY_ID']
    LINE_PAY_KEY = current_app.config['LINE_PAY_KEY']
    
    # 获取所有与该订单相关的订单项
    order_items = OrderItem.query.filter_by(order_id=order_id).all()
    if not order_items:
        return jsonify({"error": "Order items not found"}), 404


    # LINE Pay 确认支付的 URL
    url = f"https://sandbox-api-pay.line.me/v3/payments/{transaction_id}/confirm"
    
    # 计算总金额（去掉小数点）
    total_price = sum(item.price * item.quantity for item in order_items)
    total_price = int(total_price)

    body = {
        "amount": total_price,
        "currency": "TWD",
    }

    # 计算 HMAC
    nonce = generate_nonce()
    uri = f"/v3/payments/{transaction_id}/confirm"
    hmac_hash = calculate_hmac(LINE_PAY_KEY, uri, body, nonce)

    headers = {
        "Content-Type": "application/json",
        "X-LINE-ChannelId": LINE_PAY_ID,
        'X-LINE-Authorization-Nonce': nonce,
        'X-LINE-Authorization': hmac_hash,
    }

    # 发起确认支付请求
    response = requests.post(url, json=body, headers=headers)
    print(f"Confirm Payment Response Status: {response.status_code}, Body: {response.text}")

    # 处理 Line Pay 返回的数据
    line_pay_data = response.json()

    if line_pay_data.get("returnCode") == "0000":
        # 创建支付记录
        payment = Payment(
            order_id=order_id,
            payment_method="LINE PAY",
            payment_status="SUCCESS",
            total_price=total_price
        )
        db.session.add(payment)
        db.session.commit()
        flash('建立訂單成功!', category='success')
        return redirect(url_for('routes.index'))
    else:
        # 支付失败，更新支付记录
        payment = Payment.query.filter_by(order_id=order_id).first()
        if payment:
            payment.payment_status = "FAILED"
            db.session.commit()

        return jsonify({"error": "Payment confirmation failed", "details": line_pay_data}), 400