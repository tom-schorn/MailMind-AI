from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from Entities import EmailCredential, EmailRule, RuleCondition, RuleAction, init_db, create_session
from Entities import DryRunRequest, DryRunResult, ServiceStatus
import os
import json
from dotenv import load_dotenv
from config_manager import load_config, save_config
from env_manager import load_env_settings, save_env_settings, validate_env_value
from path_manager import get_env_file, get_database_url

# Load environment variables from .env file
env_file = get_env_file()
load_dotenv(env_file)

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev-secret-key-change-in-production')

# Convert DATABASE_DEBUG to boolean
database_debug_value = os.environ.get('DATABASE_DEBUG', 'false')
database_debug = database_debug_value.lower() in ('true', '1', 'yes')
engine = create_engine(get_database_url(), echo=database_debug)
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
            encryption = request.form.get('encryption', 'auto')

            account = EmailCredential(
                email_address=request.form['email_address'],
                host=request.form['host'],
                port=int(request.form['port']),
                username=request.form['username'],
                password=request.form['password'],
                use_ssl=encryption == 'ssl',
                use_tls=encryption == 'tls'
            )

            if encryption == 'auto':
                from imap_test_connection import test_imap_connection
                success, message, settings = test_imap_connection(account)

                if success and settings:
                    account.use_ssl = settings['use_ssl']
                    account.use_tls = settings['use_tls']
                    flash(f'Connection test successful! Using {message}', 'success')
                else:
                    flash(f'Connection test failed: {message}', 'danger')
                    session.close()
                    return render_template('accounts/add.html')

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


@app.route('/api/folders/<int:credential_id>')
def get_folders(credential_id):
    """Get list of available IMAP folders for a credential."""
    session = create_session(engine)
    try:
        credential = session.query(EmailCredential).filter_by(id=credential_id).first()
        if not credential:
            return jsonify({'error': 'Credential not found'}), 404

        config = load_config()
        from logger_config import setup_logging
        logger = setup_logging(config)
        from imap_client import IMAPClient

        imap_client = IMAPClient(credential, config, logger)
        imap_client.connect()

        try:
            folders = imap_client.list_folders()

            folder_list = [
                {
                    'name': f['name'],
                    'selectable': '\\Noselect' not in f['flags']
                }
                for f in folders
            ]

            return jsonify({
                'status': 'success',
                'folders': folder_list
            })
        finally:
            imap_client.disconnect()

    except Exception as e:
        return jsonify({'error': str(e)}), 500
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
                actions='',  # Not used, but required
                monitored_folder=request.form.get('monitored_folder', 'INBOX')
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
            rule.monitored_folder = request.form.get('monitored_folder', 'INBOX')

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
                'auto_apply_rules': 'auto_apply_rules' in request.form,
                'service': {
                    'heartbeat_interval': int(request.form.get('heartbeat_interval', 10)),
                    'dry_run_poll_interval': int(request.form.get('dry_run_poll_interval', 5)),
                    'imap_reconnect_delay': int(request.form.get('imap_reconnect_delay', 30)),
                    'use_imap_idle': 'use_imap_idle' in request.form,
                    'imap_poll_interval': int(request.form.get('imap_poll_interval', 60))
                }
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


# Dry-Run Testing
@app.route('/rules/test/<int:id>', methods=['GET', 'POST'])
def test_rule(id):
    session = create_session(engine)
    try:
        rule = session.query(EmailRule).filter_by(id=id).first()
        if not rule:
            flash('Rule not found!', 'danger')
            return redirect(url_for('list_rules'))

        if request.method == 'POST':
            max_emails = int(request.form.get('max_emails', 10))

            dry_run_request = DryRunRequest(
                rule_id=rule.id,
                email_credential_id=rule.email_credential_id,
                status='pending',
                max_emails=max_emails
            )
            session.add(dry_run_request)
            session.commit()

            flash(f'Dry-run test started for rule "{rule.name}"', 'info')
            return redirect(url_for('view_dry_run_results', request_id=dry_run_request.id))

        return render_template('rules/test.html', rule=rule)
    except Exception as e:
        session.rollback()
        flash(f'Error starting dry-run test: {str(e)}', 'danger')
        return redirect(url_for('list_rules'))
    finally:
        session.close()


@app.route('/rules/test/results/<int:request_id>')
def view_dry_run_results(request_id):
    session = create_session(engine)
    try:
        dry_run_request = session.query(DryRunRequest).filter_by(id=request_id).first()
        if not dry_run_request:
            flash('Dry-run request not found!', 'danger')
            return redirect(url_for('list_rules'))

        results = session.query(DryRunResult).filter_by(request_id=request_id).all()

        results_data = []
        for result in results:
            condition_results = json.loads(result.condition_results) if result.condition_results else {}
            actions_would_apply = json.loads(result.actions_would_apply) if result.actions_would_apply else []

            results_data.append({
                'id': result.id,
                'email_uid': result.email_uid,
                'email_subject': result.email_subject,
                'email_from': result.email_from,
                'email_date': result.email_date,
                'matched': result.matched,
                'condition_results': condition_results,
                'actions_would_apply': actions_would_apply
            })

        return render_template('rules/test_results.html',
                             dry_run_request=dry_run_request,
                             results=results_data)
    finally:
        session.close()


@app.route('/rules/test/status/<int:request_id>')
def dry_run_status(request_id):
    """AJAX endpoint to check dry-run status."""
    session = create_session(engine)
    try:
        dry_run_request = session.query(DryRunRequest).filter_by(id=request_id).first()
        if not dry_run_request:
            return jsonify({'error': 'Request not found'}), 404

        result_count = session.query(DryRunResult).filter_by(request_id=request_id).count()

        return jsonify({
            'status': dry_run_request.status,
            'result_count': result_count,
            'processed_at': str(dry_run_request.processed_at) if dry_run_request.processed_at else None
        })
    finally:
        session.close()


@app.route('/rules/test-logs/<session_id>')
def get_test_logs(session_id):
    """Get logs for a test session."""
    from test_session import get_session_manager

    after_index = int(request.args.get('after', 0))

    session_mgr = get_session_manager()
    test_session = session_mgr.get_session(session_id)

    if not test_session:
        return jsonify({'error': 'Session not found'}), 404

    logs = test_session.get_logs(after_index)

    return jsonify({
        'status': test_session.status,
        'logs': logs,
        'total_logs': len(test_session.logs)
    })


@app.route('/service/status')
def service_status():
    """Display service status page."""
    session = create_session(engine)
    try:
        service_status = session.query(ServiceStatus).filter_by(
            service_name='EmailService'
        ).first()

        return render_template('service/status.html', service_status=service_status)
    finally:
        session.close()


@app.route('/rules/test-preview', methods=['POST'])
def test_rule_preview():
    """Test rule preview without saving."""
    from imap_client import IMAPClient, EmailMessage
    from rule_engine import RuleEngine, ConditionEvaluator
    from logger_config import setup_logging
    from datetime import datetime
    from test_session import get_session_manager
    import uuid

    try:
        data = request.get_json()
        credential_id = data.get('credential_id')
        logic = data.get('logic', 'AND')
        conditions = data.get('conditions', [])
        actions = data.get('actions', [])
        max_emails = data.get('max_emails', 10)

        session_id = str(uuid.uuid4())
        session_mgr = get_session_manager()
        test_session = session_mgr.create_session(session_id)

        session = create_session(engine)

        try:
            credential = session.query(EmailCredential).filter_by(id=credential_id).first()
            if not credential:
                return jsonify({'error': 'Credential not found'}), 404

            config = load_config()
            logger = setup_logging(config)

            imap_client = IMAPClient(credential, config, logger)
            imap_client.connect()

            try:
                test_session.add_log('INFO', 'Starting dry-run test...')
                logger.info("Starting dry-run test")

                test_session.add_log('INFO', 'Fetching emails from inbox...')
                uids = imap_client.get_all_uids(limit=100)
                logger.info(f"Found {len(uids)} total emails in inbox")
                test_session.add_log('INFO', f'Found {len(uids)} emails in inbox')

                evaluator = ConditionEvaluator(logger)
                results = []
                matched_count = 0
                max_matches = 10
                max_emails_to_check = 100
                emails_checked = 0

                for uid in uids:
                    if matched_count >= max_matches:
                        logger.info(f"Reached max matches ({max_matches}), stopping")
                        break

                    if emails_checked >= max_emails_to_check:
                        logger.info(f"Reached max emails to check ({max_emails_to_check}), stopping")
                        break

                    emails_checked += 1
                    logger.info(f"Checking email {emails_checked}/{min(len(uids), max_emails_to_check)}: UID {uid}")
                    test_session.add_log('INFO', f'Checking email {emails_checked}/{min(len(uids), max_emails_to_check)}')

                    email = imap_client.fetch_email(uid)
                    logger.debug(f"Email subject: {email.subject[:50]}")
                    test_session.add_log('DEBUG', f'Subject: {email.subject[:80]}')

                    condition_results = []
                    for cond in conditions:
                        cond_obj = type('Condition', (), cond)()
                        matched, reason = evaluator.evaluate(email, cond_obj)
                        condition_results.append({
                            'field': cond['field'],
                            'operator': cond['operator'],
                            'value': cond['value'],
                            'matched': matched,
                            'reason': reason
                        })

                    if logic == 'AND':
                        overall_match = all(c['matched'] for c in condition_results)
                    else:
                        overall_match = any(c['matched'] for c in condition_results)

                    logger.debug(f"Email {uid}: Match={overall_match}")

                    if overall_match:
                        matched_count += 1
                        logger.info(f"Match found! ({matched_count}/{max_matches}): {email.subject[:50]}")
                        test_session.add_log('SUCCESS', f'✓ MATCH {matched_count}/{max_matches}: {email.subject[:60]}')

                        actions_would_apply = []
                        for action in actions:
                            action_type = action.get('action_type')
                            action_value = action.get('action_value', '')

                            if action_type == 'move_to_folder':
                                actions_would_apply.append(f"move_to_folder: {action_value}")
                            elif action_type == 'copy_to_folder':
                                actions_would_apply.append(f"copy_to_folder: {action_value}")
                            elif action_type == 'add_label':
                                actions_would_apply.append(f"add_label: {action_value}")
                            elif action_type == 'mark_as_read':
                                actions_would_apply.append("mark_as_read")
                            elif action_type == 'delete':
                                actions_would_apply.append("delete")
                            elif action_type == 'modify_subject':
                                actions_would_apply.append(f"modify_subject: {action_value}")

                        results.append({
                            'email_uid': uid,
                            'email_subject': email.subject,
                            'email_from': email.sender,
                            'email_date': email.date.strftime('%Y-%m-%d %H:%M') if email.date else 'N/A',
                            'matched': overall_match,
                            'condition_results': condition_results,
                            'actions_would_apply': actions_would_apply
                        })

                logger.info(f"Dry-run complete: {matched_count} matches from {emails_checked} emails checked")
                test_session.add_log('INFO', f'Test complete: {matched_count} matches from {emails_checked} emails')
                test_session.set_status('completed')

                return jsonify({
                    'status': 'success',
                    'session_id': session_id,
                    'results': results,
                    'emails_checked': emails_checked,
                    'total_emails': min(len(uids), max_emails_to_check),
                    'inbox_total': len(uids)
                })

            finally:
                imap_client.disconnect()

        finally:
            session.close()

    except Exception as e:
        return jsonify({'error': str(e)}), 500


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
