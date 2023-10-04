from flask import Blueprint, render_template, redirect, url_for, request, flash
from werkzeug.security import check_password_hash
from flask_login import login_user, logout_user, login_required, current_user
from models import User

import logging

auth = Blueprint('auth', __name__)

@auth.route('/logout')
@login_required
def logout():
    try:
        logout_user()
        app.logger.info("User logged out successfully.")
    except Exception as e:
        app.logger.error(f"Error logging out: {e}")
    return redirect(url_for('auth.login'))

@auth.route('/login')
def login():
    return render_template('login.html')

@auth.route('/login', methods=['POST'])
def login_post():
    try:
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if not user or not check_password_hash(user.password, password):
            flash('Please check your login details and try again.')
            app.logger.warning(f"Login failed for user with email: {email}")
            return redirect(url_for('auth.login'))

        login_user(user)

        if user.new_user:
            return redirect(url_for('welcome'))
        else:
            app.logger.info(f"User {user.id} logged in successfully.")
            return redirect(url_for('homepage'))
    except Exception as e:
        app.logger.error(f"Error during login: {e}")
        flash('An error occurred during login. Please try again later.')
        return redirect(url_for('auth.login'))