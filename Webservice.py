from flask import Flask, render_template, request, redirect, url_for, flash
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from Entities import EmailCredential, EmailRule, RuleCondition, RuleAction, init_db, create_session
import os
from dotenv import load_dotenv
from config_manager import load_config, save_config
from env_manager import load_env_settings, save_env_settings, validate_env_value

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


# Email Rules Management
@app.route('/rules')
def list_rules():
    session = create_session(engine)
    try:
        rules = session.query(EmailRule).all()
        return render_template('rules/list.html', rules=rules)
    finally:
        session.close()


@app.route('/rules/add', methods=['GET', 'POST'])
def add_rule():
    if request.method == 'POST':
        session = create_session(engine)
        try:
            # Create EmailRule
            rule = EmailRule(
                email_credential_id=int(request.form['email_account_id']),
                name=request.form['name'],
                enabled='enabled' in request.form,
                condition=request.form.get('logic', 'AND'),
                actions=''  # Not used, but required
            )
            session.add(rule)
            session.flush()  # Get rule.id

            # Parse and create conditions
            condition_fields = [k for k in request.form.keys() if k.startswith('condition_field_')]
            for field_key in condition_fields:
                index = field_key.split('_')[-1]
                condition = RuleCondition(
                    rule_id=rule.id,
                    field=request.form[f'condition_field_{index}'],
                    operator=request.form[f'condition_operator_{index}'],
                    value=request.form[f'condition_value_{index}']
                )
                session.add(condition)

            # Parse and create actions
            action_types = [k for k in request.form.keys() if k.startswith('action_type_')]
            for type_key in action_types:
                index = type_key.split('_')[-1]
                action_type = request.form[f'action_type_{index}']
                action_value = request.form.get(f'action_value_{index}', '')

                action = RuleAction(
                    rule_id=rule.id,
                    action_type=action_type,
                    action_value=action_value,
                    folder=action_value if action_type in ['move_to_folder', 'copy_to_folder'] else None,
                    label=action_value if action_type == 'add_label' else None
                )
                session.add(action)

            session.commit()
            flash('Email rule added successfully!', 'success')
            return redirect(url_for('list_rules'))
        except Exception as e:
            session.rollback()
            flash(f'Error adding rule: {str(e)}', 'danger')
        finally:
            session.close()

    # GET request - show form
    session = create_session(engine)
    try:
        accounts = session.query(EmailCredential).all()
        return render_template('rules/add.html', accounts=accounts)
    finally:
        session.close()


@app.route('/rules/edit/<int:id>', methods=['GET', 'POST'])
def edit_rule(id):
    session = create_session(engine)
    try:
        rule = session.query(EmailRule).filter_by(id=id).first()
        if not rule:
            flash('Rule not found!', 'danger')
            return redirect(url_for('list_rules'))

        if request.method == 'POST':
            # Update rule basics
            rule.email_credential_id = int(request.form['email_account_id'])
            rule.name = request.form['name']
            rule.enabled = 'enabled' in request.form
            rule.condition = request.form.get('logic', 'AND')

            # Delete existing conditions and actions
            session.query(RuleCondition).filter_by(rule_id=rule.id).delete()
            session.query(RuleAction).filter_by(rule_id=rule.id).delete()

            # Parse and create new conditions
            condition_fields = [k for k in request.form.keys() if k.startswith('condition_field_')]
            for field_key in condition_fields:
                index = field_key.split('_')[-1]
                condition = RuleCondition(
                    rule_id=rule.id,
                    field=request.form[f'condition_field_{index}'],
                    operator=request.form[f'condition_operator_{index}'],
                    value=request.form[f'condition_value_{index}']
                )
                session.add(condition)

            # Parse and create new actions
            action_types = [k for k in request.form.keys() if k.startswith('action_type_')]
            for type_key in action_types:
                index = type_key.split('_')[-1]
                action_type = request.form[f'action_type_{index}']
                action_value = request.form.get(f'action_value_{index}', '')

                action = RuleAction(
                    rule_id=rule.id,
                    action_type=action_type,
                    action_value=action_value,
                    folder=action_value if action_type in ['move_to_folder', 'copy_to_folder'] else None,
                    label=action_value if action_type == 'add_label' else None
                )
                session.add(action)

            session.commit()
            flash('Email rule updated successfully!', 'success')
            return redirect(url_for('list_rules'))

        # GET request - show form
        accounts = session.query(EmailCredential).all()
        return render_template('rules/edit.html', rule=rule, accounts=accounts)
    except Exception as e:
        session.rollback()
        flash(f'Error updating rule: {str(e)}', 'danger')
        return redirect(url_for('list_rules'))
    finally:
        session.close()


@app.route('/rules/delete/<int:id>', methods=['POST'])
def delete_rule(id):
    session = create_session(engine)
    try:
        rule = session.query(EmailRule).filter_by(id=id).first()
        if rule:
            # Delete related conditions and actions first (if not using cascade)
            session.query(RuleCondition).filter_by(rule_id=id).delete()
            session.query(RuleAction).filter_by(rule_id=id).delete()
            session.delete(rule)
            session.commit()
            flash('Email rule deleted successfully!', 'success')
        else:
            flash('Rule not found!', 'danger')
    except Exception as e:
        session.rollback()
        flash(f'Error deleting rule: {str(e)}', 'danger')
    finally:
        session.close()

    return redirect(url_for('list_rules'))


@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if request.method == 'POST':
        try:
            # Validate and save .env settings
            env_data = {
                'FLASK_SECRET_KEY': request.form['FLASK_SECRET_KEY'],
                'FLASK_DEBUG': 'True' if 'FLASK_DEBUG' in request.form else 'False',
                'FLASK_HOST': request.form['FLASK_HOST'],
                'FLASK_PORT': request.form['FLASK_PORT'],
                'DATABASE_URL': request.form['DATABASE_URL'],
                'DATABASE_DEBUG': 'True' if 'DATABASE_DEBUG' in request.form else 'False'
            }

            # Validate critical values
            for key, value in env_data.items():
                is_valid, error_msg = validate_env_value(key, value)
                if not is_valid:
                    flash(f'Validation error for {key}: {error_msg}', 'danger')
                    env_settings = load_env_settings()
                    app_settings = load_config()
                    return render_template('settings.html',
                                         env_settings=env_settings,
                                         app_settings=app_settings)

            save_env_settings(env_data)

            # Save config.json settings
            config_data = {
                'email_check_interval': int(request.form['email_check_interval']),
                'log_level': request.form['log_level'],
                'log_to_file': 'log_to_file' in request.form,
                'log_file_path': request.form['log_file_path'],
                'auto_apply_rules': 'auto_apply_rules' in request.form
            }

            # Validate application settings
            if config_data['email_check_interval'] < 1:
                flash('Email check interval must be at least 1 minute', 'danger')
                env_settings = load_env_settings()
                app_settings = load_config()
                return render_template('settings.html',
                                     env_settings=env_settings,
                                     app_settings=app_settings)

            if config_data['log_level'] not in ['DEBUG', 'INFO', 'WARNING', 'ERROR']:
                flash('Invalid log level', 'danger')
                env_settings = load_env_settings()
                app_settings = load_config()
                return render_template('settings.html',
                                     env_settings=env_settings,
                                     app_settings=app_settings)

            save_config(config_data)

            flash('Settings saved successfully! Restart required for Flask configuration changes.', 'success')
            return redirect(url_for('settings'))
        except Exception as e:
            flash(f'Error saving settings: {str(e)}', 'danger')

    # GET request
    env_settings = load_env_settings()
    app_settings = load_config()

    return render_template('settings.html',
                         env_settings=env_settings,
                         app_settings=app_settings)


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
