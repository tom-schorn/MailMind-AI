from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from DatabaseService import EmailCredential, EmailRule, RuleCondition, RuleAction, DatabaseService
from DatabaseService import DryRunRequest, DryRunResult, ServiceStatus, Label, ProcessedEmail, EmailRuleApplication, WatcherReloadSignal
from DatabaseService import SpamConfig, SpamAnalysis, WhitelistEntry, BlacklistEntry
import os
import re
import json
import threading
from datetime import datetime, timedelta
from typing import Dict, List
from dotenv import load_dotenv
from config_manager import load_config, save_config
from utils import load_env_settings, save_env_settings, validate_env_value, get_env_file, get_database_url


# Test Session Management
class TestSession:
    """Stores logs for a test session."""

    def __init__(self, session_id: str):
        self.session_id = session_id
        self.logs: List[Dict] = []
        self.status = 'running'
        self.created_at = datetime.now()
        self.lock = threading.Lock()

    def add_log(self, level: str, message: str):
        """Add a log entry."""
        with self.lock:
            self.logs.append({
                'timestamp': datetime.now().isoformat(),
                'level': level,
                'message': message
            })

    def get_logs(self, after_index: int = 0) -> List[Dict]:
        """Get logs after a certain index."""
        with self.lock:
            return self.logs[after_index:]

    def set_status(self, status: str):
        """Update session status."""
        with self.lock:
            self.status = status


class TestSessionManager:
    """Manages test sessions."""

    def __init__(self):
        self.sessions: Dict[str, TestSession] = {}
        self.lock = threading.Lock()

    def create_session(self, session_id: str) -> TestSession:
        """Create a new test session."""
        with self.lock:
            session = TestSession(session_id)
            self.sessions[session_id] = session
            return session

    def get_session(self, session_id: str) -> TestSession:
        """Get a test session."""
        with self.lock:
            return self.sessions.get(session_id)

    def cleanup_old_sessions(self, max_age_minutes: int = 30):
        """Remove sessions older than max_age_minutes."""
        with self.lock:
            cutoff = datetime.now() - timedelta(minutes=max_age_minutes)
            to_remove = [
                sid for sid, session in self.sessions.items()
                if session.created_at < cutoff
            ]
            for sid in to_remove:
                del self.sessions[sid]


# Global session manager
_session_manager = TestSessionManager()


def get_session_manager() -> TestSessionManager:
    """Get the global session manager."""
    return _session_manager


def _signal_watcher_reload(session, credential_id: int) -> None:
    """Signal the email watcher to reload rules for a credential."""
    existing = session.query(WatcherReloadSignal).filter_by(credential_id=credential_id).first()
    if existing:
        existing.signaled_at = datetime.now()
    else:
        session.add(WatcherReloadSignal(credential_id=credential_id))
    session.commit()


def _delete_spam_auto_rules(session, credential_id: int) -> None:
    """Delete all auto-generated spam rules for a credential."""
    auto_rules = session.query(EmailRule).filter(
        EmailRule.email_credential_id == credential_id,
        EmailRule.name.like('[Auto-Spam]%')
    ).all()
    for rule in auto_rules:
        session.delete(rule)
    session.flush()


def _create_spam_auto_rules(session, credential_id: int, spam_config) -> None:
    """Create auto-generated spam rules based on spam config settings."""
    spam_folder = spam_config.spam_folder or 'Spam'

    if spam_config.auto_categorize:
        categories = [
            ('Phishing', 'phishing'),
            ('Scam', 'scam'),
            ('Spam', 'spam'),
            ('Malware', 'malware'),
            ('Adult', 'adult'),
        ]
        subfolder_map = {
            'Phishing': 'Phishing',
            'Scam': 'Scam',
            'Spam': 'General',
            'Malware': 'Malware',
            'Adult': 'Adult',
        }
        for label, category in categories:
            rule = EmailRule(
                email_credential_id=credential_id,
                name=f"[Auto-Spam] {label}",
                enabled=True,
                condition="AND",
                actions="",
                monitored_folder="INBOX"
            )
            session.add(rule)
            session.flush()

            session.add(RuleCondition(
                rule_id=rule.id,
                field="spam_category",
                operator="equals",
                value=category
            ))

            target_folder = f"{spam_folder}/{subfolder_map[label]}"
            session.add(RuleAction(
                rule_id=rule.id,
                action_type="move_to_folder",
                action_value=target_folder,
                folder=target_folder
            ))
    else:
        rule = EmailRule(
            email_credential_id=credential_id,
            name="[Auto-Spam] Filter",
            enabled=True,
            condition="AND",
            actions="",
            monitored_folder="INBOX"
        )
        session.add(rule)
        session.flush()

        session.add(RuleCondition(
            rule_id=rule.id,
            field="spam_score",
            operator="greater_than",
            value="0.5"
        ))

        session.add(RuleAction(
            rule_id=rule.id,
            action_type="move_to_folder",
            action_value=spam_folder,
            folder=spam_folder
        ))

    session.flush()


def _format_actions(actions_json: str) -> str:
    """Format raw actions JSON into human-readable text."""
    if not actions_json:
        return 'N/A'
    try:
        actions = json.loads(actions_json)
    except (json.JSONDecodeError, TypeError):
        return actions_json[:80] if actions_json else 'N/A'

    labels = {
        'move_to_folder': 'Moved to',
        'copy_to_folder': 'Copied to',
        'add_label': 'Label:',
        'mark_as_read': 'Marked as read',
        'delete': 'Deleted',
        'modify_subject': 'Subject modified:',
        'save_attachments': 'Attachments saved',
    }

    formatted = []
    for action in actions:
        if isinstance(action, str):
            if ':' in action:
                action_type, _, value = action.partition(':')
                action_type = action_type.strip()
                value = value.strip()
                label = labels.get(action_type, action_type)
                if value:
                    formatted.append(f"{label} {value}")
                else:
                    formatted.append(label)
            else:
                formatted.append(labels.get(action.strip(), action))
        else:
            formatted.append(str(action))

    return ', '.join(formatted) if formatted else 'N/A'


# Load environment variables from .env file
env_file = get_env_file()
load_dotenv(env_file)

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev-secret-key-change-in-production')

# Convert DATABASE_DEBUG to boolean
database_debug_value = os.environ.get('DATABASE_DEBUG', 'false')
database_debug = database_debug_value.lower() in ('true', '1', 'yes')
engine = create_engine(get_database_url(), echo=database_debug)

db_service = DatabaseService(get_database_url())
db_service.init_db()


@app.route('/')
def index():
    return redirect(url_for('list_accounts'))


@app.route('/accounts')
def list_accounts():
    session = db_service.get_session()
    try:
        accounts = session.query(EmailCredential).all()
        return render_template('accounts/list.html', accounts=accounts)
    finally:
        session.close()


@app.route('/accounts/add', methods=['GET', 'POST'])
def add_account():
    if request.method == 'POST':
        session = db_service.get_session()
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
                from EMailService import test_imap_connection
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
    session = db_service.get_session()
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
    session = db_service.get_session()
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


# Account Dashboard & Scoped Routes
@app.route('/accounts/<int:id>')
def account_dashboard(id):
    session = db_service.get_session()
    try:
        account = session.query(EmailCredential).filter_by(id=id).first()
        if not account:
            flash('Account not found!', 'danger')
            return redirect(url_for('list_accounts'))

        rules_count = session.query(EmailRule).filter_by(email_credential_id=id).count()
        labels_count = session.query(Label).filter_by(credential_id=id).count()

        spam_config = session.query(SpamConfig).filter_by(credential_id=id).first()

        service_status = session.query(ServiceStatus).filter_by(
            service_name='EmailService'
        ).first()

        recent_activity_raw = session.query(EmailRuleApplication).filter_by(
            email_credential_id=id
        ).order_by(EmailRuleApplication.applied_at.desc()).limit(10).all()

        recent_activity = []
        for activity in recent_activity_raw:
            rule_name = activity.rule.name if activity.rule else f'Rule #{activity.rule_id}'
            actions_display = _format_actions(activity.actions_taken)
            recent_activity.append({
                'email_subject': activity.email_subject or f'UID {activity.email_uid}',
                'rule_name': rule_name,
                'actions_display': actions_display,
                'applied_at': activity.applied_at
            })

        return render_template('accounts/dashboard.html',
                             account=account,
                             rules_count=rules_count,
                             labels_count=labels_count,
                             spam_config=spam_config,
                             service_status=service_status,
                             recent_activity=recent_activity)
    finally:
        session.close()


@app.route('/accounts/<int:id>/rules')
def account_rules(id):
    session = db_service.get_session()
    try:
        account = session.query(EmailCredential).filter_by(id=id).first()
        if not account:
            flash('Account not found!', 'danger')
            return redirect(url_for('list_accounts'))

        rules = session.query(EmailRule).filter_by(email_credential_id=id).order_by(EmailRule.monitored_folder).all()
        grouped_rules = {}
        for rule in rules:
            folder = rule.monitored_folder or 'INBOX'
            grouped_rules.setdefault(folder, []).append(rule)
        return render_template('accounts/rules/list.html', account=account, grouped_rules=grouped_rules)
    finally:
        session.close()


@app.route('/accounts/<int:id>/rules/add', methods=['GET', 'POST'])
def account_add_rule(id):
    if request.method == 'POST':
        session = db_service.get_session()
        try:
            account = session.query(EmailCredential).filter_by(id=id).first()
            if not account:
                flash('Account not found!', 'danger')
                return redirect(url_for('list_accounts'))

            rule = EmailRule(
                email_credential_id=id,
                name=request.form['name'],
                enabled='enabled' in request.form,
                condition=request.form.get('logic', 'AND'),
                actions='',
                monitored_folder=request.form.get('monitored_folder', 'INBOX')
            )
            session.add(rule)
            session.flush()

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

            action_types = [k for k in request.form.keys() if k.startswith('action_type_')]
            for type_key in action_types:
                index = type_key.split('_')[-1]
                action_type = request.form[f'action_type_{index}']
                action_value = request.form.get(f'action_value_{index}', '')

                action = RuleAction(
                    rule_id=rule.id,
                    action_type=action_type,
                    action_value=action_value or '',
                    folder=action_value if action_type in ['move_to_folder', 'copy_to_folder'] else None,
                    label=action_value if action_type == 'add_label' else None
                )
                session.add(action)

            session.commit()
            _signal_watcher_reload(session, id)
            flash('Email rule added successfully!', 'success')
            return redirect(url_for('account_rules', id=id))
        except Exception as e:
            session.rollback()
            flash(f'Error adding rule: {str(e)}', 'danger')
        finally:
            session.close()

    session = db_service.get_session()
    try:
        account = session.query(EmailCredential).filter_by(id=id).first()
        if not account:
            flash('Account not found!', 'danger')
            return redirect(url_for('list_accounts'))
        return render_template('accounts/rules/add.html', account=account)
    finally:
        session.close()


@app.route('/accounts/<int:id>/rules/edit/<int:rule_id>', methods=['GET', 'POST'])
def account_edit_rule(id, rule_id):
    session = db_service.get_session()
    try:
        account = session.query(EmailCredential).filter_by(id=id).first()
        if not account:
            flash('Account not found!', 'danger')
            return redirect(url_for('list_accounts'))

        rule = session.query(EmailRule).filter_by(id=rule_id, email_credential_id=id).first()
        if not rule:
            flash('Rule not found!', 'danger')
            return redirect(url_for('account_rules', id=id))

        if request.method == 'POST':
            rule.name = request.form['name']
            rule.enabled = 'enabled' in request.form
            rule.condition = request.form.get('logic', 'AND')
            rule.monitored_folder = request.form.get('monitored_folder', 'INBOX')

            session.query(RuleCondition).filter_by(rule_id=rule.id).delete()
            session.query(RuleAction).filter_by(rule_id=rule.id).delete()

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

            action_types = [k for k in request.form.keys() if k.startswith('action_type_')]
            for type_key in action_types:
                index = type_key.split('_')[-1]
                action_type = request.form[f'action_type_{index}']
                action_value = request.form.get(f'action_value_{index}', '')

                action = RuleAction(
                    rule_id=rule.id,
                    action_type=action_type,
                    action_value=action_value or '',
                    folder=action_value if action_type in ['move_to_folder', 'copy_to_folder'] else None,
                    label=action_value if action_type == 'add_label' else None
                )
                session.add(action)

            session.commit()
            _signal_watcher_reload(session, id)
            flash('Email rule updated successfully!', 'success')
            return redirect(url_for('account_rules', id=id))

        return render_template('accounts/rules/edit.html', account=account, rule=rule)
    except Exception as e:
        session.rollback()
        flash(f'Error updating rule: {str(e)}', 'danger')
        return redirect(url_for('account_rules', id=id))
    finally:
        session.close()


@app.route('/accounts/<int:id>/rules/delete/<int:rule_id>', methods=['POST'])
def account_delete_rule(id, rule_id):
    session = db_service.get_session()
    try:
        rule = session.query(EmailRule).filter_by(id=rule_id, email_credential_id=id).first()
        if rule:
            session.query(RuleCondition).filter_by(rule_id=rule_id).delete()
            session.query(RuleAction).filter_by(rule_id=rule_id).delete()
            credential_id = rule.email_credential_id
            session.delete(rule)
            session.commit()
            _signal_watcher_reload(session, credential_id)
            flash('Email rule deleted successfully!', 'success')
        else:
            flash('Rule not found!', 'danger')
    except Exception as e:
        session.rollback()
        flash(f'Error deleting rule: {str(e)}', 'danger')
    finally:
        session.close()

    return redirect(url_for('account_rules', id=id))


@app.route('/accounts/<int:id>/rules/test/<int:rule_id>', methods=['GET', 'POST'])
def account_test_rule(id, rule_id):
    session = db_service.get_session()
    try:
        account = session.query(EmailCredential).filter_by(id=id).first()
        if not account:
            flash('Account not found!', 'danger')
            return redirect(url_for('list_accounts'))

        rule = session.query(EmailRule).filter_by(id=rule_id, email_credential_id=id).first()
        if not rule:
            flash('Rule not found!', 'danger')
            return redirect(url_for('account_rules', id=id))

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
            return redirect(url_for('account_test_results', id=id, request_id=dry_run_request.id))

        return render_template('accounts/rules/test.html', account=account, rule=rule)
    except Exception as e:
        session.rollback()
        flash(f'Error starting dry-run test: {str(e)}', 'danger')
        return redirect(url_for('account_rules', id=id))
    finally:
        session.close()


@app.route('/accounts/<int:id>/rules/test/results/<int:request_id>')
def account_test_results(id, request_id):
    session = db_service.get_session()
    try:
        account = session.query(EmailCredential).filter_by(id=id).first()
        if not account:
            flash('Account not found!', 'danger')
            return redirect(url_for('list_accounts'))

        dry_run_request = session.query(DryRunRequest).filter_by(id=request_id, email_credential_id=id).first()
        if not dry_run_request:
            flash('Dry-run request not found!', 'danger')
            return redirect(url_for('account_rules', id=id))

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

        return render_template('accounts/rules/test_results.html',
                             account=account,
                             dry_run_request=dry_run_request,
                             results=results_data)
    finally:
        session.close()


@app.route('/accounts/<int:id>/rules/test/status/<int:request_id>')
def account_dry_run_status(id, request_id):
    """AJAX endpoint to check dry-run status."""
    session = db_service.get_session()
    try:
        dry_run_request = session.query(DryRunRequest).filter_by(id=request_id, email_credential_id=id).first()
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


# Account Labels
@app.route('/accounts/<int:id>/labels')
def account_labels(id):
    session = db_service.get_session()
    try:
        account = session.query(EmailCredential).filter_by(id=id).first()
        if not account:
            flash('Account not found!', 'danger')
            return redirect(url_for('list_accounts'))

        labels = session.query(Label).filter_by(credential_id=id).all()
        return render_template('accounts/labels/list.html', account=account, labels=labels)
    finally:
        session.close()


@app.route('/accounts/<int:id>/labels/add', methods=['GET', 'POST'])
def account_add_label(id):
    if request.method == 'POST':
        session = db_service.get_session()
        try:
            account = session.query(EmailCredential).filter_by(id=id).first()
            if not account:
                flash('Account not found!', 'danger')
                return redirect(url_for('list_accounts'))

            label = Label(
                credential_id=id,
                name=request.form['name'],
                color=request.form.get('color', '#0d6efd'),
                is_imap_flag=False
            )
            session.add(label)
            session.commit()
            flash('Label created successfully!', 'success')
            return redirect(url_for('account_labels', id=id))
        except Exception as e:
            session.rollback()
            flash(f'Error creating label: {str(e)}', 'danger')
        finally:
            session.close()

    session = db_service.get_session()
    try:
        account = session.query(EmailCredential).filter_by(id=id).first()
        if not account:
            flash('Account not found!', 'danger')
            return redirect(url_for('list_accounts'))
        return render_template('accounts/labels/add.html', account=account)
    finally:
        session.close()


@app.route('/accounts/<int:id>/labels/edit/<int:label_id>', methods=['GET', 'POST'])
def account_edit_label(id, label_id):
    session = db_service.get_session()
    try:
        account = session.query(EmailCredential).filter_by(id=id).first()
        if not account:
            flash('Account not found!', 'danger')
            return redirect(url_for('list_accounts'))

        label = session.query(Label).filter_by(id=label_id, credential_id=id).first()
        if not label:
            flash('Label not found!', 'danger')
            return redirect(url_for('account_labels', id=id))

        if request.method == 'POST':
            label.name = request.form['name']
            label.color = request.form.get('color', '#0d6efd')
            session.commit()
            flash('Label updated successfully!', 'success')
            return redirect(url_for('account_labels', id=id))

        return render_template('accounts/labels/edit.html', account=account, label=label)
    except Exception as e:
        session.rollback()
        flash(f'Error updating label: {str(e)}', 'danger')
        return redirect(url_for('account_labels', id=id))
    finally:
        session.close()


@app.route('/accounts/<int:id>/labels/delete/<int:label_id>', methods=['POST'])
def account_delete_label(id, label_id):
    session = db_service.get_session()
    try:
        label = session.query(Label).filter_by(id=label_id, credential_id=id).first()
        if label:
            session.delete(label)
            session.commit()
            flash('Label deleted successfully!', 'success')
        else:
            flash('Label not found!', 'danger')
    except Exception as e:
        session.rollback()
        flash(f'Error deleting label: {str(e)}', 'danger')
    finally:
        session.close()
    return redirect(url_for('account_labels', id=id))


@app.route('/accounts/<int:id>/labels/sync', methods=['POST'])
def account_sync_labels(id):
    """Sync labels from IMAP flags for an account."""
    session = db_service.get_session()
    try:
        credential = session.query(EmailCredential).filter_by(id=id).first()
        if not credential:
            flash('Account not found!', 'danger')
            return redirect(url_for('list_accounts'))

        config = load_config()
        from LoggingService import LoggingService
        logger = LoggingService.setup(config)
        from EMailService import IMAPClient

        imap_client = IMAPClient(credential, config, logger)
        imap_client.connect()

        try:
            flags = imap_client.get_flags()
            existing_labels = session.query(Label).filter_by(credential_id=id).all()
            existing_names = {l.name for l in existing_labels}

            synced = 0
            for flag in flags:
                if flag not in existing_names:
                    label = Label(
                        credential_id=id,
                        name=flag,
                        color='#6c757d',
                        is_imap_flag=True
                    )
                    session.add(label)
                    synced += 1

            session.commit()
            flash(f'Synced {synced} new labels from IMAP flags.', 'success')
        finally:
            imap_client.disconnect()

    except Exception as e:
        session.rollback()
        flash(f'Error syncing labels: {str(e)}', 'danger')
    finally:
        session.close()

    return redirect(url_for('account_labels', id=id))


# Account Logs
@app.route('/accounts/<int:id>/logs')
def account_logs(id):
    session = db_service.get_session()
    try:
        account = session.query(EmailCredential).filter_by(id=id).first()
        if not account:
            flash('Account not found!', 'danger')
            return redirect(url_for('list_accounts'))

        return render_template('accounts/logs.html', account=account)
    finally:
        session.close()


@app.route('/accounts/<int:id>/spam', methods=['GET', 'POST'])
def account_spam_settings(id):
    session = db_service.get_session()
    try:
        account = session.query(EmailCredential).filter_by(id=id).first()
        if not account:
            flash('Account not found!', 'danger')
            return redirect(url_for('list_accounts'))

        if request.method == 'POST':
            spam_config = session.query(SpamConfig).filter_by(credential_id=id).first()
            if not spam_config:
                spam_config = SpamConfig(credential_id=id)
                session.add(spam_config)

            spam_config.enabled = 'enabled' in request.form
            spam_config.sensitivity = int(request.form.get('sensitivity', 5))
            spam_config.model = request.form.get('model', 'haiku')
            spam_config.spam_folder = request.form.get('spam_folder', 'Spam')
            spam_config.auto_categorize = 'auto_categorize' in request.form

            session.commit()

            _delete_spam_auto_rules(session, id)
            if spam_config.enabled:
                _create_spam_auto_rules(session, id, spam_config)
            session.commit()
            _signal_watcher_reload(session, id)

            flash('Spam detection settings saved!', 'success')
            return redirect(url_for('account_spam_settings', id=id))

        spam_config = session.query(SpamConfig).filter_by(credential_id=id).first()
        whitelist = session.query(WhitelistEntry).filter_by(credential_id=id).order_by(WhitelistEntry.added_at.desc()).all()
        blacklist = session.query(BlacklistEntry).filter_by(credential_id=id).order_by(BlacklistEntry.added_at.desc()).all()

        auto_rules = session.query(EmailRule).filter(
            EmailRule.email_credential_id == id,
            EmailRule.name.like('[Auto-Spam]%')
        ).all()

        api_key_configured = bool(os.environ.get('ANTHROPIC_API_KEY'))

        return render_template('accounts/spam/settings.html',
                             account=account,
                             spam_config=spam_config,
                             whitelist=whitelist,
                             blacklist=blacklist,
                             auto_rules=auto_rules,
                             api_key_configured=api_key_configured)
    except Exception as e:
        session.rollback()
        flash(f'Error saving spam settings: {str(e)}', 'danger')
        return redirect(url_for('account_dashboard', id=id))
    finally:
        session.close()


@app.route('/accounts/<int:id>/spam/log')
def account_spam_log(id):
    session = db_service.get_session()
    try:
        account = session.query(EmailCredential).filter_by(id=id).first()
        if not account:
            flash('Account not found!', 'danger')
            return redirect(url_for('list_accounts'))

        analyses = session.query(SpamAnalysis).filter_by(
            credential_id=id
        ).order_by(SpamAnalysis.analyzed_at.desc()).limit(100).all()

        analysis_data = []
        for a in analyses:
            step_results = []
            if a.analysis_json:
                try:
                    step_results = json.loads(a.analysis_json)
                except (json.JSONDecodeError, TypeError):
                    pass

            analysis_data.append({
                'id': a.id,
                'email_uid': a.email_uid,
                'email_subject': a.email_subject or f'UID {a.email_uid}',
                'email_from': a.email_from or 'Unknown',
                'spam_score': a.spam_score,
                'spam_category': a.spam_category,
                'step_results': step_results,
                'analyzed_at': a.analyzed_at,
            })

        return render_template('accounts/spam/log.html',
                             account=account,
                             analyses=analysis_data)
    finally:
        session.close()


@app.route('/api/spam/whitelist/<int:credential_id>')
def get_whitelist(credential_id):
    session = db_service.get_session()
    try:
        entries = session.query(WhitelistEntry).filter_by(credential_id=credential_id).all()
        return jsonify({
            'status': 'success',
            'entries': [{'id': e.id, 'domain': e.domain, 'added_at': str(e.added_at), 'reason': e.reason} for e in entries]
        })
    finally:
        session.close()


@app.route('/api/spam/whitelist/<int:credential_id>', methods=['POST'])
def add_whitelist(credential_id):
    session = db_service.get_session()
    try:
        data = request.get_json()
        domain = data.get('domain', '').strip().lower()
        reason = data.get('reason', '').strip()

        if not domain:
            return jsonify({'error': 'Domain is required'}), 400

        existing = session.query(WhitelistEntry).filter_by(credential_id=credential_id, domain=domain).first()
        if existing:
            return jsonify({'error': 'Domain already whitelisted'}), 409

        entry = WhitelistEntry(credential_id=credential_id, domain=domain, reason=reason or None)
        session.add(entry)
        session.commit()
        return jsonify({'status': 'success', 'entry': {'id': entry.id, 'domain': entry.domain}})
    except Exception as e:
        session.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()


@app.route('/api/spam/whitelist/<int:entry_id>', methods=['DELETE'])
def delete_whitelist(entry_id):
    session = db_service.get_session()
    try:
        entry = session.query(WhitelistEntry).filter_by(id=entry_id).first()
        if not entry:
            return jsonify({'error': 'Entry not found'}), 404
        session.delete(entry)
        session.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        session.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()


@app.route('/api/spam/blacklist/<int:credential_id>')
def get_blacklist(credential_id):
    session = db_service.get_session()
    try:
        entries = session.query(BlacklistEntry).filter_by(credential_id=credential_id).all()
        return jsonify({
            'status': 'success',
            'entries': [{'id': e.id, 'domain': e.domain, 'added_at': str(e.added_at), 'reason': e.reason} for e in entries]
        })
    finally:
        session.close()


@app.route('/api/spam/blacklist/<int:credential_id>', methods=['POST'])
def add_blacklist(credential_id):
    session = db_service.get_session()
    try:
        data = request.get_json()
        domain = data.get('domain', '').strip().lower()
        reason = data.get('reason', '').strip()

        if not domain:
            return jsonify({'error': 'Domain is required'}), 400

        existing = session.query(BlacklistEntry).filter_by(credential_id=credential_id, domain=domain).first()
        if existing:
            return jsonify({'error': 'Domain already blacklisted'}), 409

        entry = BlacklistEntry(credential_id=credential_id, domain=domain, reason=reason or None)
        session.add(entry)
        session.commit()
        return jsonify({'status': 'success', 'entry': {'id': entry.id, 'domain': entry.domain}})
    except Exception as e:
        session.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()


@app.route('/api/spam/blacklist/<int:entry_id>', methods=['DELETE'])
def delete_blacklist(entry_id):
    session = db_service.get_session()
    try:
        entry = session.query(BlacklistEntry).filter_by(id=entry_id).first()
        if not entry:
            return jsonify({'error': 'Entry not found'}), 404
        session.delete(entry)
        session.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        session.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()


@app.route('/api/spam/whitelist/import-defaults/<int:credential_id>', methods=['POST'])
def import_default_whitelist(credential_id):
    session = db_service.get_session()
    try:
        defaults = [
            'google.com', 'gmail.com', 'apple.com', 'icloud.com',
            'amazon.com', 'amazon.de', 'paypal.com', 'microsoft.com',
            'outlook.com', 'hotmail.com', 'github.com', 'linkedin.com',
            'twitter.com', 'x.com', 'facebook.com', 'instagram.com',
            'youtube.com', 'netflix.com', 'spotify.com', 'dropbox.com',
        ]

        added = 0
        for domain in defaults:
            existing = session.query(WhitelistEntry).filter_by(credential_id=credential_id, domain=domain).first()
            if not existing:
                session.add(WhitelistEntry(credential_id=credential_id, domain=domain, reason='Default import'))
                added += 1

        session.commit()
        return jsonify({'status': 'success', 'added': added})
    except Exception as e:
        session.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()


@app.route('/api/spam/whitelist/import-url/<int:credential_id>', methods=['POST'])
def import_whitelist_from_url(credential_id):
    """Import whitelist domains from a plaintext URL."""
    session = db_service.get_session()
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        if not url:
            return jsonify({'error': 'URL is required'}), 400

        import urllib.request
        req = urllib.request.Request(url, headers={'User-Agent': 'MailMind-AI/1.8.1'})
        with urllib.request.urlopen(req, timeout=15) as resp:
            content = resp.read().decode('utf-8', errors='ignore')

        added = 0
        skipped = 0
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('//'):
                continue
            domain = line.lower()
            # Basic domain validation
            if not re.match(r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*$', domain):
                continue
            existing = session.query(WhitelistEntry).filter_by(credential_id=credential_id, domain=domain).first()
            if existing:
                skipped += 1
                continue
            session.add(WhitelistEntry(credential_id=credential_id, domain=domain, reason=f'URL import: {url[:100]}'))
            added += 1

        session.commit()
        return jsonify({'status': 'success', 'added': added, 'skipped': skipped})
    except urllib.request.URLError as e:
        return jsonify({'error': f'Failed to fetch URL: {e}'}), 400
    except Exception as e:
        session.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()


@app.route('/api/spam/blacklist/import-url/<int:credential_id>', methods=['POST'])
def import_blacklist_from_url(credential_id):
    """Import blacklist domains from a plaintext URL."""
    session = db_service.get_session()
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        if not url:
            return jsonify({'error': 'URL is required'}), 400

        import urllib.request
        req = urllib.request.Request(url, headers={'User-Agent': 'MailMind-AI/1.8.1'})
        with urllib.request.urlopen(req, timeout=15) as resp:
            content = resp.read().decode('utf-8', errors='ignore')

        added = 0
        skipped = 0
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('//'):
                continue
            domain = line.lower()
            if not re.match(r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*$', domain):
                continue
            existing = session.query(BlacklistEntry).filter_by(credential_id=credential_id, domain=domain).first()
            if existing:
                skipped += 1
                continue
            session.add(BlacklistEntry(credential_id=credential_id, domain=domain, reason=f'URL import: {url[:100]}'))
            added += 1

        session.commit()
        return jsonify({'status': 'success', 'added': added, 'skipped': skipped})
    except urllib.request.URLError as e:
        return jsonify({'error': f'Failed to fetch URL: {e}'}), 400
    except Exception as e:
        session.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()


@app.route('/api/folders/<int:credential_id>')
def get_folders(credential_id):
    """Get list of available IMAP folders for a credential."""
    session = db_service.get_session()
    try:
        credential = session.query(EmailCredential).filter_by(id=credential_id).first()
        if not credential:
            return jsonify({'error': 'Credential not found'}), 404

        config = load_config()
        from LoggingService import LoggingService
        logger = LoggingService.setup(config)
        from EMailService import IMAPClient

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


# Label API endpoints
@app.route('/api/labels/<int:credential_id>')
def get_labels(credential_id):
    """Get labels for a credential."""
    session = db_service.get_session()
    try:
        labels = session.query(Label).filter_by(credential_id=credential_id).all()
        return jsonify({
            'status': 'success',
            'labels': [{'id': l.id, 'name': l.name, 'color': l.color, 'is_imap_flag': l.is_imap_flag} for l in labels]
        })
    finally:
        session.close()


@app.route('/api/labels/<int:credential_id>', methods=['POST'])
def create_label(credential_id):
    """Create a new label."""
    session = db_service.get_session()
    try:
        data = request.get_json()
        label = Label(
            credential_id=credential_id,
            name=data['name'],
            color=data.get('color', '#0d6efd'),
            is_imap_flag=False
        )
        session.add(label)
        session.commit()
        return jsonify({
            'status': 'success',
            'label': {'id': label.id, 'name': label.name, 'color': label.color}
        })
    except Exception as e:
        session.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()


@app.route('/api/labels/update/<int:label_id>', methods=['PUT'])
def update_label(label_id):
    """Update a label."""
    session = db_service.get_session()
    try:
        label = session.query(Label).filter_by(id=label_id).first()
        if not label:
            return jsonify({'error': 'Label not found'}), 404

        data = request.get_json()
        if 'name' in data:
            label.name = data['name']
        if 'color' in data:
            label.color = data['color']

        session.commit()
        return jsonify({'status': 'success', 'label': {'id': label.id, 'name': label.name, 'color': label.color}})
    except Exception as e:
        session.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()


@app.route('/api/labels/delete/<int:label_id>', methods=['DELETE'])
def delete_label_api(label_id):
    """Delete a label."""
    session = db_service.get_session()
    try:
        label = session.query(Label).filter_by(id=label_id).first()
        if not label:
            return jsonify({'error': 'Label not found'}), 404
        session.delete(label)
        session.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        session.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()


@app.route('/api/flags/<int:credential_id>')
def get_flags(credential_id):
    """Get IMAP flags from server."""
    session = db_service.get_session()
    try:
        credential = session.query(EmailCredential).filter_by(id=credential_id).first()
        if not credential:
            return jsonify({'error': 'Credential not found'}), 404

        config = load_config()
        from LoggingService import LoggingService
        logger = LoggingService.setup(config)
        from EMailService import IMAPClient

        imap_client = IMAPClient(credential, config, logger)
        imap_client.connect()

        try:
            flags = imap_client.get_flags()
            return jsonify({'status': 'success', 'flags': flags})
        finally:
            imap_client.disconnect()

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()


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


@app.route('/rules/test-logs/<session_id>')
def get_test_logs(session_id):
    """Get logs for a test session."""

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
    session = db_service.get_session()
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
    from EMailService import IMAPClient, EmailMessage, RuleEngine, ConditionEvaluator
    from LoggingService import LoggingService
    from datetime import datetime
    import uuid

    try:
        data = request.get_json()
        credential_id = data.get('credential_id')
        logic = data.get('logic', 'AND')
        conditions = data.get('conditions', [])
        actions = data.get('actions', [])
        max_emails = data.get('max_emails', 10)
        monitored_folder = data.get('monitored_folder', 'INBOX')

        session_id = str(uuid.uuid4())
        session_mgr = get_session_manager()
        test_session = session_mgr.create_session(session_id)

        session = db_service.get_session()

        try:
            credential = session.query(EmailCredential).filter_by(id=credential_id).first()
            if not credential:
                return jsonify({'error': 'Credential not found'}), 404

            config = load_config()
            logger = LoggingService.setup(config)

            imap_client = IMAPClient(credential, config, logger)
            imap_client.connect()

            try:
                test_session.add_log('INFO', 'Starting dry-run test...')
                logger.info("Starting dry-run test")

                test_session.add_log('INFO', f'Fetching emails from {monitored_folder}...')
                uids = imap_client.get_all_uids(folder=monitored_folder, limit=100)
                logger.info(f"Found {len(uids)} total emails in {monitored_folder}")
                test_session.add_log('INFO', f'Found {len(uids)} emails in {monitored_folder}')

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
                            elif action_type == 'save_attachments':
                                actions_would_apply.append("save_attachments")

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


def parse_log_file(path: str, level_filter: str = None, search_filter: str = None, account_filter: str = None) -> list:
    """Parse log file and return structured entries."""
    log_pattern = re.compile(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) - (\S+) - (\w+) - (.*)$')
    entries = []

    if not os.path.exists(path):
        return entries

    try:
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                match = log_pattern.match(line)
                if match:
                    timestamp, logger, level, message = match.groups()
                    if level_filter and level.upper() != level_filter.upper():
                        continue
                    if search_filter and search_filter.lower() not in message.lower():
                        continue
                    if account_filter:
                        account_lower = account_filter.lower()
                        if account_lower not in logger.lower() and account_lower not in message.lower():
                            continue
                    entries.append({
                        'timestamp': timestamp,
                        'logger': logger,
                        'level': level,
                        'message': message
                    })
    except Exception:
        pass

    return entries


@app.route('/api/logs')
def get_logs():
    """Get log entries with optional filtering."""
    level = request.args.get('level', '')
    search = request.args.get('search', '')
    account = request.args.get('account', '')
    limit = int(request.args.get('limit', 500))

    config = load_config()
    log_path = config.get('log_file_path', 'logs/mailmind.log')

    entries = parse_log_file(log_path, level or None, search or None, account or None)

    # Return last N entries (newest last)
    if len(entries) > limit:
        entries = entries[-limit:]

    return jsonify({
        'status': 'success',
        'entries': entries,
        'total': len(entries)
    })


@app.route('/api/logs/export/csv')
def export_logs_csv():
    """Export logs as CSV."""
    import csv
    import io

    level = request.args.get('level', '')
    search = request.args.get('search', '')
    account = request.args.get('account', '')

    config = load_config()
    log_path = config.get('log_file_path', 'logs/mailmind.log')

    entries = parse_log_file(log_path, level or None, search or None, account or None)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Timestamp', 'Logger', 'Level', 'Message'])
    for entry in entries:
        writer.writerow([entry['timestamp'], entry['logger'], entry['level'], entry['message']])

    response = app.response_class(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=mailmind-logs.csv'}
    )
    return response


@app.route('/api/logs/export/jsonl')
def export_logs_jsonl():
    """Export logs as JSONL."""
    level = request.args.get('level', '')
    search = request.args.get('search', '')
    account = request.args.get('account', '')

    config = load_config()
    log_path = config.get('log_file_path', 'logs/mailmind.log')

    entries = parse_log_file(log_path, level or None, search or None, account or None)

    lines = [json.dumps(entry) for entry in entries]
    content = '\n'.join(lines)

    response = app.response_class(
        content,
        mimetype='application/jsonl',
        headers={'Content-Disposition': 'attachment; filename=mailmind-logs.jsonl'}
    )
    return response


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
