from flask_socketio import SocketIO, emit, join_room, leave_room
import rsa
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt 
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user 
import random

app = Flask(__name__)
socketio = SocketIO(app)
app.secret_key = 'systemselfdenfencemaritalarts88889999'

#Cấu hình ứng dụng
app.config["SECRET_KEY"] = "system_self_defence_martial_arts"
app.config["SQLALCHEMY_DATABASE_URI"] = "mariadb+mariadbconnector://root:123@localhost/sdmas"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

bcrypt = Bcrypt(app)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

#RSA
(public_key, private_key) = rsa.newkeys(512)
with open('public_key.pem', 'wb') as p_file:
    p_file.write(public_key.save_pkcs1('PEM'))
with open('private_key.pem', 'wb') as p_file:
    p_file.write(private_key.save_pkcs1('PEM'))

class User(UserMixin, db.Model):
    __tablename__ = 'Userss'    
    sdmas_id = db.Column(db.String(50), primary_key=True)
    password = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(50), nullable=False)
    phone = db.Column(db.String(50), nullable=False)
    role = db.Column(db.String(50), nullable=False)

    def get_id(self):
        return str(self.sdmas_id) 

class HistoryText(db.Model):
    __tablename__ = 'blog'
    id_text = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)

class Members(db.Model):
    __tablename__ = 'members'
    sdmas_id = db.Column(db.String(50), primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    level = db.Column(db.Integer, nullable=False)
    birthday = db.Column(db.Date, nullable=False)
    phone = db.Column(db.String(15), nullable=False)
    address = db.Column(db.String(100), nullable=False)
    joined_date = db.Column(db.Date, nullable=False)
    bio = db.Column(db.String(200), nullable=False)  # 
 
class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('Userss.sdmas_id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('Userss.sdmas_id'))
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

@socketio.on('connect')
def handle_connect():
    print('Client đã kết nối')
    emit('message', {'msg': 'Chào mừng đến với phòng chat!'})

@socketio.on('disconnect')
def handle_disconnect():
    print('Client đã ngắt kết nối')

@socketio.on('join')
def on_join(data):
    username = data['username']
    room = data['room']
    join_room(room)
    emit('message', {'msg': f'{username} đã vào phòng.'}, room=room)

@socketio.on('leave')
def on_leave(data):
    username = data['username']
    room = data['room']
    leave_room(room)
    emit('message', {'msg': f'{username} đã rời phòng.'}, room=room)

@socketio.on('send_message')
def handle_message(data):
    room = data['room']
    message = data['message']
    username = data['username']
    emit('receive_message', {'username': username, 'message': message}, room=room)


@login_manager.user_loader
def load_user(sdmas_id):
    return User.query.get(sdmas_id)

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
        session.clear()  #
    else:
        logout_user()
    flash('Bạn đã đăng xuất!', 'info')
    return redirect(url_for('login'))

@app.route("/guest_login", methods=["POST", "GET"])
def guest_login():
    if request.method == "POST":
        user_gmail = request.form.get("gmail")
        if user_gmail:
            session['logged_in'] = True
            session['user_class'] = 'guest'
            session['user_gmail'] = user_gmail  
            return redirect(url_for("dashboard_user"))    
    return render_template("guest-login.html")

@app.route('/dashboard-user')
def dashboard_user():
    
    if 'user_class' in session and session['user_class'] == 'guest':
        user_email = session.get('user_gmail', 'Guest')
        return render_template('dashboard_user.html', user={'sdmas_id': user_email})

    if current_user.is_authenticated and current_user.role.lower() == 'member':
        members = Members.query.all()  
        return render_template('dashboard_user.html', user=current_user, members=members)


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
        user = User.query.filter_by(sdmas_id=sdmas_id, phone=phone).first() 
        
        if user:            
            otp_code = random.randint(100000, 999999) 
            encrypted_otp = rsa.encrypt(str(otp_code).encode(), public_key)                       
            session['encrypted_otp'] = encrypted_otp
            session['sdmas_id'] = sdmas_id              
            print(f'Mã OTP của {user.email} là: {otp_code}') 
            
            return redirect(url_for('reset_password'))
        else:            
            flash('Thông tin không hợp lệ. Vui lòng kiểm tra lại.', 'danger')

    return render_template('forgot-password.html')


with open('private_key.pem', 'rb') as p_file:
    private_key = rsa.PrivateKey.load_pkcs1(p_file.read())


@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':  
        entered_otp = request.form.get('otp')                      
        new_password = request.form.get('new_password')            
        encrypted_otp = session.get('encrypted_otp')  
               
        try:            
            decrypted_otp = rsa.decrypt(encrypted_otp, private_key).decode()   
                      
            if str(decrypted_otp) == entered_otp:           
                sdmas_id = session.get('sdmas_id')
                user = User.query.filter_by(sdmas_id=sdmas_id).first()
                
                if user:                     
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


@app.route('/history/<int:id_text>')
def history(id_text):
    history_entry = HistoryText.query.filter_by(id_text=id_text).first()

    if history_entry:
        return render_template('history.html', content=history_entry.content)
    else:
        return render_template('history.html', content="Không tìm thấy nội dung.")

@app.route('/organizational-chart')
def organizationalChart():
    return render_template('organizational-chart.html')

@app.route("/message")
@login_required
def message():
  
    return render_template('chat.html')

@app.route('/view-activity')
def viewActivity():
    return render_template('view-activity.html')
@app.route('/view-activity-admin')
def viewActivityAdmin():
    return render_template('view-activity-admin.html')


if __name__ == '__main__':
    app.run(debug=True)
