from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify, send_file
from init import create_app, db
from models import User, Checkin
from forms import LoginForm, DistanceForm, VerifyForm, RegistrationForm
from utils import generate_captcha, verify_captcha, generate_qrcode
import bcrypt
from flask_paginate import Pagination, get_page_parameter
import logging
from logging.handlers import RotatingFileHandler
import os
from datetime import datetime, timedelta  # Add timedelta import here

app = create_app()

# Configure logging
log_handler = RotatingFileHandler('attendence.log', maxBytes=10000, backupCount=1)
log_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
log_handler.setFormatter(formatter)
app.logger.addHandler(log_handler)
app.logger.propagate = False # debug logger
app.logger.info("Logging setup complete")

with app.app_context():
    db.create_all()

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login'))
    admin_user = db.session.get(User, session['user_id'])
    if not admin_user:
        flash("Admin user not found")
        return redirect(url_for('login'))
    
    date_filter = request.form.get('date_filter')
    if not date_filter:
        date_filter = datetime.today().strftime('%Y-%m-%d')
 
    checkins = Checkin.query.filter(Checkin.timestamp.like(f'{date_filter}%')).all()
    users = {checkin.user_id: (checkin.user.username, checkin.distance) for checkin in checkins}
    
    # Calculate distance distribution for the selected date
    distance_distribution = [0] * 5
    for checkin in checkins:
        if 1 <= checkin.distance <= 5:
            distance_distribution[int(checkin.distance) - 1] += 1
    
    # Calculate check-ins for the last 30 days
    labels = []
    checkins_last_30_days = []
    today = datetime.today()
    for i in range(30):
        day = today - timedelta(days=i)
        day_str = day.strftime('%Y-%m-%d')
        count = Checkin.query.filter(Checkin.timestamp.like(f'{day_str}%')).count()
        labels.append(day_str)
        checkins_last_30_days.append(count)
    
    labels.reverse()
    checkins_last_30_days.reverse()
    
    form = VerifyForm()  # Create an instance of VerifyForm
    
    return render_template('admin_dashboard.html', date_filter=date_filter, users=users, username=admin_user.username, distance_distribution=distance_distribution, labels=labels, checkins_last_30_days=checkins_last_30_days, form=form)

@app.route('/delete_account', methods=['POST'])
def delete_account():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login'))
    admin_password = request.form.get('admin_password')
    user_id = request.form.get('user_id')
    
    admin_user = db.session.get(User, session['user_id'])
    if bcrypt.checkpw(admin_password.encode('utf-8'), admin_user.password):
        user = db.session.get(User, user_id)
        if user:
            db.session.delete(user)
            db.session.commit()
            app.logger.info(f'Delete user - Success: admin = {admin_user.username}, user = {user.username}')
            return '', 204
        return 'User not found', 404
    app.logger.warning(f'Delete user - Failed: Incorrect password, admin = {admin_user.username}, user = {user_id}')
    return 'Invalid password', 403

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    admin_user = db.session.get(User, session['user_id'])
    if form.validate_on_submit():
        hashed_password = bcrypt.hashpw(form.password.data.encode('utf-8'), bcrypt.gensalt())
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        app.logger.info(f'User register - Success: admin = {admin_user.username}, user = {new_user.username}')
        flash('Registration successful, waiting for admin approval')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.checkpw(form.password.data.encode('utf-8'), user.password):
            if user.is_active:
                if verify_captcha(form.captcha.data, session['captcha_text']):
                    session['user_id'] = user.id
                    session['username'] = user.username  # 存储用户名
                    session['is_admin'] = user.is_admin  # 存储管理员状态
                    app.logger.info(f'User login - Success: username = {user.username}')
                    if user.is_admin:
                        return redirect(url_for('admin_dashboard'))
                    else:
                        return redirect(url_for('user_dashboard'))
                else:
                    flash('Invalid captcha')
                    app.logger.warning(f'User login - Failed: Invalid captcha, username = {user.username}')
            else:
                flash('Your account is not yet activated by the admin')
                app.logger.warning(f'User login - Failed: Account not activated, username = {user.username}')
        else:
            flash('Invalid username or password')
            app.logger.warning(f'User login - Failed: Incorrect username or password, username = {form.username.data}')
    session['captcha_text'], captcha_image = generate_captcha()
    return render_template('login.html', form=form, captcha_image=captcha_image)

@app.route('/user_dashboard', methods=['GET', 'POST'])
def user_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = db.session.get(User, session['user_id'])
    if user.is_admin:
        return redirect(url_for('admin_dashboard'))
    
    form = DistanceForm()
    form.distance.choices = [(str(i), f'{i} km') for i in range(1, 6)]
    qrcode_image = None
    if form.validate_on_submit():
        distance = int(form.distance.data)
        qrcode_image = generate_qrcode(distance, user.id)
        app.logger.info(f'QR code generated - Success: user = {user.username}, distance = {distance} km')

    checkins = Checkin.query.filter_by(user_id=user.id).all()
    labels = [checkin.timestamp.strftime('%Y-%m-%d') for checkin in checkins] if checkins else []
    
    distances = []
    cumulative_distance = 0
    for checkin in checkins:
        cumulative_distance += checkin.distance
        distances.append(cumulative_distance)
    
    # Calculate the distribution of distances
    distance_distribution = [0] * 5
    for checkin in checkins:
        if 1 <= checkin.distance <= 5:
            distance_distribution[int(checkin.distance) - 1] += 1

    # Pagination
    page = request.args.get(get_page_parameter(), type=int, default=1)
    per_page = 10
    pagination = Pagination(page=page, total=len(checkins), record_name='checkins', per_page=per_page)
    checkins_paginated = checkins[(page - 1) * per_page: page * per_page]

    return render_template('user_dashboard.html', user=user, form=form, qrcode_image=qrcode_image, labels=labels, distances=distances, distance_distribution=distance_distribution, checkins=checkins_paginated, pagination=pagination)

@app.route('/activate_user/<int:user_id>')
def activate_user(user_id):
    if 'user_id' not in session or not session.get('is_admin'):
        app.logger.info(f'Activate user - Failed: User not found, admin = {session["username"]}')
        return redirect(url_for('login'))
    user = db.session.get(User, user_id)
    if user:
        user.is_active = True
        db.session.commit()
        flash(f'User {user.username} has been activated')
        app.logger.info(f'Activate user - Success: admin = {session["username"]}, user = {user.username}')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin_add_user', methods=['GET', 'POST'])
def admin_add_user():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login'))
    user = db.session.get(User, session['user_id'])
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.hashpw(form.password.data.encode('utf-8'), bcrypt.gensalt())
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('User added successfully')
        app.logger.info(f'Add user - Success: admin = {user.username}, user = {new_user.username}')
        return redirect(url_for('admin_dashboard'))
    return render_template('admin_add_user.html', form=form, username=user.username)

@app.route('/admin_delete_user/<int:user_id>')
def admin_delete_user(user_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login'))
    user = db.session.get(User, session['user_id'])
    user_to_delete = db.session.get(User, user_id)
    if user_to_delete:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash(f'User {user_to_delete.username} has been deleted')
        app.logger.info(f'Delete user - Success: admin = {user.username}, user = {user_to_delete.username}')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin_edit_user/<int:user_id>', methods=['POST'])
def admin_edit_user(user_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login'))
    user = db.session.get(User, user_id)
    if user:
        password = request.form.get('password')
        checkin_count = request.form.get('checkin_count')
        total_distance = request.form.get('total_distance')

        if password:
            user.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        user.checkin_count = int(checkin_count)
        user.total_distance = float(total_distance)
        db.session.commit()
        app.logger.info(f'Edit user - Success: admin = {session["username"]}, user {user.username}')
        return '', 204
    return 'User not found', 404

@app.route('/admin_view_user/<int:user_id>', methods=['GET', 'POST'])
def admin_view_user(user_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login'))
    admin_user = db.session.get(User, session['user_id'])
    user = db.session.get(User, user_id)
    checkins = Checkin.query.filter_by(user_id=user_id).all()
    if request.method == 'POST':
        user.username = request.form.get('username')
        password = request.form.get('password')
        if password:
            user.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        user.checkin_count = request.form.get('checkin_count')
        user.total_distance = request.form.get('total_distance')
        user.is_active = request.form.get('is_active') == 'on'
        user.is_admin = request.form.get('is_admin') == 'on'
        db.session.commit()
        flash('User updated successfully')
        app.logger.info(f'Update user - Success: admin = {admin_user.username}, user = {user.username}')
        return redirect(url_for('admin_view_user', user_id=user.id))
    return render_template('admin_view_user.html', user=user, checkins=checkins, username=admin_user.username)

@app.route('/admin_edit_checkin/<int:checkin_id>', methods=['POST'])
def admin_edit_checkin(checkin_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login'))
    checkin = db.session.get(Checkin, checkin_id)
    if checkin:
        checkin.distance = request.form.get('distance')
        checkin.verified = request.form.get('verified') == 'on'
        checkin.verified_by = request.form.get('verified_by')
        db.session.commit()
        flash('Check-in record updated successfully')
        app.logger.info(f'Edit check-in - Success: admin = {session["username"]}, user = {checkin.user_id}')
    return redirect(url_for('admin_view_user', user_id=checkin.user_id))

@app.route('/admin_delete_checkin/<int:checkin_id>')
def admin_delete_checkin(checkin_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login'))
    checkin = db.session.get(Checkin, checkin_id)
    if checkin:
        db.session.delete(checkin)
        db.session.commit()
        flash('Check-in record deleted successfully')
        app.logger.info(f'Delete check-in - Success: admin = {session["username"]}, user = {checkin.user_id}')
    return redirect(url_for('admin_view_user', user_id=checkin.user_id))

@app.route('/verify_qr_code', methods=['POST'])
def verify_qr_code():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login'))
    qr_code_content = request.form.get('qr_code')
    if qr_code_content:
        try:
            user_id, distance = qr_code_content.split('-')
            user_id = int(user_id)
            distance = float(distance)
            user = db.session.get(User, user_id)
            if user:
                new_checkin = Checkin(user_id=user_id, distance=distance, verified=True, verified_by='admin')
                user.checkin_count += 1
                user.total_distance += distance
                db.session.add(new_checkin)
                db.session.commit()
                flash(f'User {user.username} check-in verified successfully.')
                app.logger.info(f'QR code verify - Success: admin = {session["username"]}, user = {user.username}')
            else:
                flash('User not found.')
                app.logger.warning(f'QR code verify - Failed: User not found, admin {session["username"]}')
        except ValueError:
            flash('Invalid QR code content.')
            app.logger.warning(f'QR code verify - Failed: Invalid code, admin {session["username"]}')
    else:
        flash('QR code content is required.')
        app.logger.warning(f'QR code verify - Failed: QR code content missing, admin {session["username"]}')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin_manage_users', methods=['GET', 'POST'])
def admin_manage_users():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login'))

    if request.method == 'POST':
        user_id = request.form.get('user_id')
        password = request.form.get('password')
        checkin_count = request.form.get('checkin_count')
        total_distance = request.form.get('total_distance')

        user = db.session.get(User, user_id)
        if user:
            if password:
                user.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            user.checkin_count = int(checkin_count)
            user.total_distance = float(total_distance)
            db.session.commit()
            app.logger.info(f'Update user - Success: admin = {session["username"]}, user = {user.username}')
            return '', 204
        app.logger.warning(f'Update user - Failed: User not found, admin = {session["username"]}')
        return 'User not found', 404

    users = User.query.all()
    return render_template('admin_manage_users.html', users=users, username=session.get('username', 'Admin'))

@app.route('/toggle_active', methods=['POST'])
def toggle_active():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login'))
    user_id = request.form.get('user_id')
    user = db.session.get(User, user_id)
    if user:
        user.is_active = not user.is_active
        db.session.commit()
        app.logger.info(f'Activate user - Success: admin = {session["username"]}, user = {user.username}')
        return '', 204
    app.logger.warning(f'Activate user - Failed: User not found, admin = {session["username"]}, user = {user_id}')
    return 'User not found', 404

@app.route('/toggle_admin', methods=['POST'])
def toggle_admin():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login'))
    user_id = request.form.get('user_id')
    user = db.session.get(User, user_id)
    if user:
        user.is_admin = not user.is_admin
        db.session.commit()
        app.logger.info(f'Admin status toggle - Success: admin = {session["username"]}, user = {user.username}')
        return '', 204
    app.logger.warning(f'Admin status toggle - Failed: User not found, admin = {session["username"]}, user = {user_id}')
    return 'User not found', 404

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/refresh_captcha')
def refresh_captcha():
    captcha_text, captcha_image = generate_captcha()
    session['captcha_text'] = captcha_text
    return jsonify({'captcha_image': captcha_image})

@app.route('/sync_checkin_data', methods=['POST'])
def sync_checkin_data():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login'))
    user_id = request.form.get('user_id')
    user = db.session.get(User, user_id)
    if user:
        checkins = Checkin.query.filter_by(user_id=user_id).all()
        total_distance = sum(checkin.distance for checkin in checkins)
        checkin_count = len(checkins)
        user.total_distance = total_distance
        user.checkin_count = checkin_count
        db.session.commit()
        app.logger.info(f'Sync checkin data - Success: admin = {session["username"]}, user = {user.username}')
        return '', 204
    app.logger.warning(f'Sync checkin data - Failed: User not found, admin = {session["username"]}, user = {user_id}')
    return 'User not found', 404

@app.route('/logs')
def view_logs():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login'))
    log_path = 'attendance.log'
    if os.path.exists(log_path):
        return send_file(log_path, as_attachment=True)
    return 'Log file not found', 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
