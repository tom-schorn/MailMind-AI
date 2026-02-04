from flask import Flask, render_template, request, redirect, url_for, flash
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from Entities import EmailCredential, init_db, create_session
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev-secret-key-change-in-production')

# Convert DATABASE_DEBUG to boolean
database_debug_value = os.environ.get('DATABASE_DEBUG', 'false')
database_debug = database_debug_value.lower() in ('true', '1', 'yes')
engine = create_engine(os.environ.get('DATABASE_URL', 'sqlite:///storage.db'), echo=database_debug)
init_db(engine)


@app.route('/')
def index():
    return redirect(url_for('list_accounts'))


@app.route('/accounts')
def list_accounts():
    session = create_session(engine)
    try:
        accounts = session.query(EmailCredential).all()
        return render_template('accounts/list.html', accounts=accounts)
    finally:
        session.close()


@app.route('/accounts/add', methods=['GET', 'POST'])
def add_account():
    if request.method == 'POST':
        session = create_session(engine)
        try:
            encryption = request.form.get('encryption', 'none')
            account = EmailCredential(
                email_address=request.form['email_address'],
                host=request.form['host'],
                port=int(request.form['port']),
                username=request.form['username'],
                password=request.form['password'],
                use_ssl=encryption == 'ssl',
                use_tls=encryption == 'tls'
            )
            session.add(account)
            session.commit()
            flash('Email account added successfully!', 'success')
            return redirect(url_for('list_accounts'))
        except Exception as e:
            session.rollback()
            flash(f'Error adding account: {str(e)}', 'danger')
        finally:
            session.close()

    return render_template('accounts/add.html')


@app.route('/accounts/edit/<int:id>', methods=['GET', 'POST'])
def edit_account(id):
    session = create_session(engine)
    try:
        account = session.query(EmailCredential).filter_by(id=id).first()
        if not account:
            flash('Account not found!', 'danger')
            return redirect(url_for('list_accounts'))

        if request.method == 'POST':
            encryption = request.form.get('encryption', 'none')
            account.email_address = request.form['email_address']
            account.host = request.form['host']
            account.port = int(request.form['port'])
            account.username = request.form['username']

            if request.form.get('password'):
                account.password = request.form['password']

            account.use_ssl = encryption == 'ssl'
            account.use_tls = encryption == 'tls'

            session.commit()
            flash('Email account updated successfully!', 'success')
            return redirect(url_for('list_accounts'))

        return render_template('accounts/edit.html', account=account)
    except Exception as e:
        session.rollback()
        flash(f'Error updating account: {str(e)}', 'danger')
        return redirect(url_for('list_accounts'))
    finally:
        session.close()


@app.route('/accounts/delete/<int:id>', methods=['POST'])
def delete_account(id):
    session = create_session(engine)
    try:
        account = session.query(EmailCredential).filter_by(id=id).first()
        if account:
            session.delete(account)
            session.commit()
            flash('Email account deleted successfully!', 'success')
        else:
            flash('Account not found!', 'danger')
    except Exception as e:
        session.rollback()
        flash(f'Error deleting account: {str(e)}', 'danger')
    finally:
        session.close()

    return redirect(url_for('list_accounts'))


if __name__ == '__main__':
    # Convert FLASK_DEBUG to boolean
    flask_debug = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 'yes')
    flask_host = os.environ.get('FLASK_HOST', '0.0.0.0')
    flask_port = int(os.environ.get('FLASK_PORT', '5000'))

    app.run(
        debug=flask_debug,
        host=flask_host,
        port=flask_port
    )
