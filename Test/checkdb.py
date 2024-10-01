# Module Imports
import mariadb
import sys
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text  

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "mariadb+mariadbconnector://root:123@localhost/sdmas"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

#----Connect to MariaDB Platform
# try:
#     conn = mariadb.connect(
#         user="root",
#         password="123",
#         host="127.0.0.1",
#         port=3306,
#         database="sdmas"
#     )
# except mariadb.Error as e:
#     print(f"Error connecting to MariaDB Platform: {e}")
#     sys.exit(1)

# Get Cursor
# cur = conn.cursor()

@app.route('/')
def home():
    try:
        # Sử dụng text() để thực hiện truy vấn SQL thuần
        db.session.execute(text('SELECT 1'))
        return "Đã kết nối thành công với cơ sở dữ liệu!"
    except Exception as e:
        return f"Lỗi kết nối: {str(e)}"

if __name__ == '__main__':
    app.run(debug=True)
