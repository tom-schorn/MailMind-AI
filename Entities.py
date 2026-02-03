import flask_sqlalchemy

db = flask_sqlalchemy.SQLAlchemy()

class EmailRule(db.Model):
    __name__ = "emailrule"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    enabled = db.Column(db.Boolean, default=True)
    condition = db.Column(db.Text, nullable=False)
    actions = db.Column(db.Text, nullable=False)

    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    changed_at = db.Column(db.DateTime, onupdate=db.func.current_timestamp())

class RuleCondition(db.Model):
    __tablename__ = "rulecondition"

    id = db.Column(db.Integer, primary_key=True)
    rule_id = db.Column(db.Integer, ddb.ForeignKey('emailrule.id'), nullable=False)
    field = db.Column(db.String(100), nullable=False)
    operator = db.Column(db.String(20), nullable=False)
    value = db.Column(db.String(255), nullable=False)

class RuleAction(db.Model):
    __tablename__ = "ruleaction"

    id = flask_sqlalchemy.Column(db.Integer, primary_key=True)
    rule_id = db.Column(db.Integer, db.ForeignKey('emailrule.id'), nullable=False)
    action_type = db.Column(db.String(50), nullable=False)
    action_value = db.Column(db.String(255), nullable=False)
    action_type = db.Column(db.String(50), nullable=False)
    folder = db.Column(db.String(200), nullable=True)
    label = db.Column(db.String(200), nullable=True)