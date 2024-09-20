import rsa
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt 
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user 
import random

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Để sử dụng session

# Cấu hình ứng dụng
app.config["SECRET_KEY"] = "system_self_defence_martial_arts"
app.config["SQLALCHEMY_DATABASE_URI"] = "mariadb+mariadbconnector://root:123@localhost/sdmas"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

bcrypt = Bcrypt(app)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Mã RSA
(public_key, private_key) = rsa.newkeys(512)
with open('public_key.pem', 'wb') as p_file:
    p_file.write(public_key.save_pkcs1('PEM'))
with open('private_key.pem', 'wb') as p_file:
    p_file.write(private_key.save_pkcs1('PEM'))


class User(UserMixin, db.Model):
    __tablename__ = 'Userss'    
    User_id = db.Column(db.Integer, primary_key=True)
    sdmas_id = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(50), nullable=False)
    phone = db.Column(db.String(50), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    
    def get_id(self):
        return str(self.User_id) 


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def home():
    return render_template('landing-page.html')
    #return render_template('login.html')


def check_login(sdmas_id, password):
  #  password = str(hashlib.md5(password.strip().encode(('utf-8').hexdigest)))
    user = User.query.filter_by(sdmas_id=sdmas_id).first()
    if user and bcrypt.check_password_hash(user.password, password):
        return user  
    else:
        return None  
 

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        
        if current_user.role.lower() == 'admin':
            return redirect(url_for('dashboard_admin'))
        
        elif current_user.role.lower() == 'member':
            return redirect(url_for('dashboard_user'))
    
    if request.method == 'POST':
       
        sdmas_id = request.form.get('sdmas_id')
        password = request.form.get('password')   
        user = check_login(sdmas_id, password)
      
        if user:
            login_user(user)
            flash('Đăng nhập thành công!', 'success')
            
            if user.role.lower() == 'admin':
                return redirect(url_for('dashboard_admin'))
            
            elif user.role.lower() == 'member':
                return redirect(url_for('dashboard_user'))
            
            else:
                flash('Loại tài khoản không hợp lệ.', 'danger')
                return redirect(url_for('login'))  
                  
        else:
            flash('Tài khoản hoặc mật khẩu không chính xác', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    if 'user_class' in session and session['user_class'] == 'guest':
        session.clear()  # Xóa session của khách
    else:
        logout_user()
    flash('Bạn đã đăng xuất!', 'info')
    return redirect(url_for('login'))


@app.route("/guest_login", methods=["POST", "GET"])
def guest_login():
    if request.method == "POST":
        user_gmail = request.form.get("gmail")  # Lấy Gmail từ form
        if user_gmail:
            # Lưu thông tin của người dùng guest vào session
            session['logged_in'] = True
            session['user_class'] = 'guest'
            session['user_gmail'] = user_gmail  # Sử dụng 'user_gmail' thay vì 'sdmas_id'
            return redirect(url_for("dashboard_user"))    
    # Nếu là GET request hoặc không nhập Gmail, hiển thị lại form đăng nhập của khách
    return render_template("guest-login.html")


# @app.route('/dashboard-user')
# @login_required
# def dashboard_user():
#     if 'user_class' in session and session['user_class'] == 'guest':
#         # Guest user
#         user_email = session.get('user_gmail', 'Guest')
#         return render_template('dashboard_user.html', user={'sdmas_id': user_email})
      
#     if current_user.role.lower() != 'member':
#         flash('Bạn không có quyền truy cập trang này.', 'danger')
    
#         return redirect(url_for('login'))
#     return render_template('dashboard_user.html', user=current_user)

@app.route('/dashboard-user')
def dashboard_user():
    
    if 'user_class' in session and session['user_class'] == 'guest':
        # Guest user
        user_email = session.get('user_gmail', 'Guest')
        return render_template('dashboard_user.html', user={'sdmas_id': user_email})
    # Nếu không phải là khách, kiểm tra đăng nhập thông thường
    if current_user.is_authenticated and current_user.role.lower() == 'member':
        return render_template('dashboard_user.html', user=current_user)

    flash('Bạn không có quyền truy cập trang này.', 'danger')
    return redirect(url_for('login'))
   

@app.route('/dashboard-admin')
@login_required
def dashboard_admin():
    if current_user.role.lower() != 'admin':
        flash('Bạn không có quyền truy cập trang này.', 'danger')
        return redirect(url_for('login'))
    return render_template('dashboard_admin.html', user=current_user)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':      
        sdmas_id = request.form.get('sdmas_id')
        phone = request.form.get('phone')    
        user = User.query.filter_by(sdmas_id=sdmas_id, phone=phone).first() # Tìm tài khoản
        
        if user:            
            otp_code = random.randint(100000, 999999)            
            # Mã hóa mã OTP bằng RSA
            encrypted_otp = rsa.encrypt(str(otp_code).encode(), public_key)                       
            session['encrypted_otp'] = encrypted_otp
            session['sdmas_id'] = sdmas_id              
            print(f'Mã OTP của {user.email} là: {otp_code}')  # Lưu OTP đã mã hóa
            
            return redirect(url_for('reset_password'))
        else:            
            flash('Thông tin không hợp lệ. Vui lòng kiểm tra lại.', 'danger')

    return render_template('forgot-password.html')


# Tải private key từ file để giải mã OTP
with open('private_key.pem', 'rb') as p_file:
    private_key = rsa.PrivateKey.load_pkcs1(p_file.read())


@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':  
        entered_otp = request.form.get('otp')                      
        new_password = request.form.get('new_password')            
        encrypted_otp = session.get('encrypted_otp')  # Lấy mã OTP đã mã hóa từ session
               
        try:            
            decrypted_otp = rsa.decrypt(encrypted_otp, private_key).decode()    # Giải mã OTP   
                      
            if str(decrypted_otp) == entered_otp:  # So sánh OTP đã giải mã với OTP nhập vào             
                sdmas_id = session.get('sdmas_id')
                user = User.query.filter_by(sdmas_id=sdmas_id).first()
                
                if user: 
                    # Mã hóa mật khẩu mới trước khi lưu vào cơ sở dữ liệu
                    hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
                    user.password = hashed_password
                    db.session.commit()
                    
                    flash('Mật khẩu đã được cập nhật thành công!', 'success')
                    return redirect(url_for('login'))
                else:
                    flash('Không tìm thấy người dùng.', 'danger')
            else:
                flash('Mã OTP không chính xác.', 'danger')
        except rsa.DecryptionError:  
            flash('Có lỗi trong quá trình giải mã OTP.', 'danger')

    return render_template('reset-password.html')

@app.route('/history')
def history():
    return render_template('history.html')

@app.route('/organizational-chart')
def organizationalChart():
    return render_template('organizational-chart.html')

if __name__ == '__main__':
    app.run(debug=True)
