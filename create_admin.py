from init import create_app, db
from models import User
import bcrypt

def create_admin(username, password):
    app = create_app()
    with app.app_context():
        # 检查是否已有管理员存在
        if User.query.filter_by(username=username).first():
            print(f"Admin user {username} already exists.")
            return

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        new_admin = User(username=username, password=hashed_password, is_active=True, is_admin=True)
        db.session.add(new_admin)
        db.session.commit()
        print(f"Admin user {username} created successfully.")

if __name__ == '__main__':
    import sys
    if len(sys.argv) != 3:
        print("Usage: python create_admin.py <username> <password>")
    else:
        username = sys.argv[1]
        password = sys.argv[2]
        create_admin(username, password)
