# --- Imports ---
import os, secrets, logging
from flask import Flask, jsonify
from flask_restx import Api, Resource, fields, Namespace
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required,
    get_jwt_identity, get_jwt
)
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from flask_cors import CORS
from datetime import timedelta, datetime
from sqlalchemy import create_engine, text
from functools import wraps
from flask import request
from apscheduler.schedulers.background import BackgroundScheduler
from flask import current_app
import requests
from datetime import datetime, timezone, timedelta
from sqlalchemy import or_

from datetime import datetime, timedelta
from sqlalchemy import or_


# --- ENV & Logging ---
load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- MySQL DB Setup ---
DATABASE_NAME = "auth"
MYSQL_USER = os.getenv("MYSQL_USER", "root")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "")
MYSQL_HOST = os.getenv("MYSQL_HOST", "localhost")
MYSQL_PORT = os.getenv("MYSQL_PORT", "3306")

temp_engine = create_engine(f"mysql+pymysql://{MYSQL_USER}:{MYSQL_PASSWORD}@{MYSQL_HOST}:{MYSQL_PORT}")
with temp_engine.connect() as conn:
    conn.execute(text(f"CREATE DATABASE IF NOT EXISTS {DATABASE_NAME}"))

DATABASE_URL = f"mysql+pymysql://{MYSQL_USER}:{MYSQL_PASSWORD}@{MYSQL_HOST}:{MYSQL_PORT}/{DATABASE_NAME}"
os.environ["DATABASE_URL"] = DATABASE_URL

# --- App Initialization ---
app = Flask(__name__)

CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY') or secrets.token_hex(32)
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

db = SQLAlchemy(app)
scheduler = BackgroundScheduler()
scheduler.start()
jwt = JWTManager(app)

api = Api(app, version="1.0", title="Service Risk API", description="API with JWT Auth, Risk Analysis & Swagger UI", prefix="/api")
auth_ns = Namespace('auth', description='Authentication operations')
service_ns = Namespace('services', description='Service and BIA operations')
risk_ns = Namespace('risk', description='Risk analysis')
audit_ns = Namespace('audit', description='Audit log operations')
alert_ns = Namespace('alerts', description='System alerts')

api.add_namespace(auth_ns)
api.add_namespace(service_ns)
api.add_namespace(risk_ns)
api.add_namespace(audit_ns)
api.add_namespace(alert_ns)

from datetime import datetime

# --- Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(100), nullable=False)
    entity = db.Column(db.String(50), nullable=False)
    entity_id = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=db.func.now())
    user_id = db.Column(db.Integer, nullable=False)

class Service(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    created_by = db.Column(db.String(100))
    
    # Relationships with cascade delete
    bia = db.relationship(
        "BIA", backref="service", uselist=False,
        cascade="all, delete-orphan", passive_deletes=True
    )
    status = db.relationship(
        "Status", backref="service", uselist=False,
        cascade="all, delete-orphan", passive_deletes=True
    )
    downtimes = db.relationship(
        'Downtime', backref='service',
        cascade='all, delete-orphan', passive_deletes=True
    )
    integrations = db.relationship(
        'Integration', backref='service',
        cascade='all, delete-orphan', passive_deletes=True
    )
    risks = db.relationship(
        'Risk', backref='service',
        cascade='all, delete-orphan', passive_deletes=True
    )
    alerts = db.relationship(
        'Alert', backref='service',
        cascade='all, delete-orphan', passive_deletes=True
    )
    sla_breaches = db.relationship(
        'SLABreach', backref='service',
        cascade='all, delete-orphan', passive_deletes=True
    )

# Association Table for many-to-many dependencies
service_dependencies = db.Table(
    'service_dependencies',
    db.Column('service_id', db.Integer, db.ForeignKey('service.id', ondelete='CASCADE'), primary_key=True),
    db.Column('dependency_id', db.Integer, db.ForeignKey('service.id', ondelete='CASCADE'), primary_key=True)
)

class BIA(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service_id = db.Column(
        db.Integer,
        db.ForeignKey('service.id', ondelete='CASCADE'),
        nullable=False
    )
    criticality = db.Column(db.String(20))
    impact = db.Column(db.String(50))
    rto = db.Column(db.Integer)
    rpo = db.Column(db.Integer)
    signed_off = db.Column(db.Boolean, default=False)
    
    dependencies = db.relationship(
        'Service',
        secondary=service_dependencies,
        primaryjoin=service_id == service_dependencies.c.service_id,
        secondaryjoin=service_dependencies.c.dependency_id == Service.id,
        backref='dependent_on',
        cascade="all"
    )

class Status(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service_id = db.Column(
        db.Integer,
        db.ForeignKey('service.id', ondelete='CASCADE'),
        nullable=False
    )
    status = db.Column(db.String(20))
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)

class Downtime(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service_id = db.Column(
        db.Integer,
        db.ForeignKey('service.id', ondelete='CASCADE'),
        nullable=False
    )
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime)
    reason = db.Column(db.String(255))

class Integration(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service_id = db.Column(
        db.Integer,
        db.ForeignKey('service.id', ondelete='CASCADE'),
        nullable=False
    )
    type = db.Column(db.String(50))
    config = db.Column(db.JSON)
    created_by = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Risk(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service_id = db.Column(
        db.Integer,
        db.ForeignKey('service.id', ondelete='CASCADE'),
        nullable=False
    )
    risk_score = db.Column(db.Integer, nullable=False)
    risk_level = db.Column(db.String(20), nullable=False)
    reason = db.Column(db.Text)
    is_critical = db.Column(db.Boolean, default=False)
    source = db.Column(db.String(20), default='automated')
    created_by = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service_id = db.Column(
        db.Integer,
        db.ForeignKey('service.id', ondelete='CASCADE'),
        nullable=False
    )
    type = db.Column(db.String(50), nullable=False)
    message = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    acknowledged = db.Column(db.Boolean, default=False)

class SLABreach(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service_id = db.Column(
        db.Integer,
        db.ForeignKey('service.id', ondelete='CASCADE'),
        nullable=False
    )
    type = db.Column(db.String(20), nullable=False)
    downtime_minutes = db.Column(db.Integer, nullable=False)
    threshold_minutes = db.Column(db.Integer, nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime)
    reason = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# --- Utility ---
def log_audit(action, entity, entity_id, user_id):
    audit_log = AuditLog(action=action, entity=entity, entity_id=entity_id, user_id=user_id or 0)
    db.session.add(audit_log)
    db.session.commit()

def role_required(*roles):
    def wrapper(fn):
        @wraps(fn)
        @jwt_required()
        def decorated(*args, **kwargs):
            claims = get_jwt()
            if claims.get("role") not in roles:
                return {'error': 'Forbidden'}, 403
            return fn(*args, **kwargs)
        return decorated
    return wrapper

def calculate_risk_score(service, bia, status, all_services):
    score = 0
    reasons = []
    is_critical = False

    if status and status.status == 'Down':
        score += 40
        reasons.append("Service is currently down")

    recent_downtimes = [
        d for d in service.downtimes
        if d.start_time >= datetime.utcnow() - timedelta(days=7)
    ]
    total_downtime_minutes = sum(
        ((d.end_time or datetime.utcnow()) - d.start_time).total_seconds() / 60
        for d in recent_downtimes
    )

    if total_downtime_minutes > 120:
        score += 20
        reasons.append("Frequent or prolonged downtimes in the last 7 days")

    if bia:
        if bia.criticality and bia.criticality.lower() == 'high':
            score += 15
            reasons.append("High criticality in BIA")
        elif bia.criticality and bia.criticality.lower() == 'medium':
            score += 10
            reasons.append("Medium criticality in BIA")

        if bia.impact and bia.impact.lower() in ['high', 'severe']:
            score += 10
            reasons.append(f"High impact in BIA: {bia.impact}")

        if bia.rto and bia.rto < 60:
            score += 10
            reasons.append("RTO < 1 hour")
        if bia.rpo and bia.rpo < 60:
            score += 5
            reasons.append("RPO < 1 hour")

        down_dependencies = []
        if bia.dependencies:
            down_dependencies = [
                dep.name for dep in bia.dependencies
                if dep.status and dep.status.status == 'Down'
            ]
            if down_dependencies:
                score += 20
                reasons.append(f"Dependencies down: {', '.join(down_dependencies)}")

    integration_count = len(service.integrations)
    if integration_count > 3:
        score += 10
        reasons.append("High number of integrations")
    if integration_count > 5:
        score += 5
        reasons.append("Very high integration complexity")

    level = 'Low'
    if score >= 80:
        level = 'High'
    elif score >= 50:
        level = 'Medium'

    if (
        (bia and bia.criticality and bia.criticality.lower() == 'high') or
        (bia and bia.impact and bia.impact.lower() in ['high', 'severe']) or
        (bia and bia.rto and bia.rto < 30) or
        (score >= 80) or
        (status and status.status == 'Down' and total_downtime_minutes > 120) or
        down_dependencies or
        integration_count > 5
    ):
        is_critical = True
        reasons.append("Service marked as CRITICAL based on business rules")

    return {
        'risk_score': min(score, 100),
        'risk_level': level,
        'is_critical': is_critical,
        'reason': ', '.join(reasons)
    }

# --- Schemas ---
signup_model = auth_ns.model('Signup', {
    'username': fields.String(required=True),
    'password': fields.String(required=True),
    'role': fields.String(default='user')
})

login_model = auth_ns.model('Login', {
    'username': fields.String(required=True),
    'password': fields.String(required=True)
})

service_model = service_ns.model('Service', {
    'name': fields.String(required=True),
    'description': fields.String,
    'criticality': fields.String,
    'impact': fields.String,
    'rto': fields.Integer,
    'rpo': fields.Integer,
    'dependencies': fields.List(fields.Integer),
    'signed_off': fields.Boolean
})

status_model = service_ns.model('StatusUpdate', {
    'status': fields.String(required=True)
})

audit_model = auth_ns.model('AuditLog', {
    'id': fields.Integer,
    'action': fields.String,
    'entity': fields.String,
    'entity_id': fields.Integer,
    'timestamp': fields.DateTime,
    'user_id': fields.Integer
})

integration_model = service_ns.model('Integration', {
    'service_id': fields.Integer(required=True),
    'type': fields.String(required=True, example='Slack'),
    'config': fields.Raw(required=True, description="Integration configuration as JSON"),
})

alert_model = alert_ns.model('Alert', {
    'id': fields.Integer,
    'service_id': fields.Integer,
    'type': fields.String,
    'message': fields.String,
    'severity': fields.String,
    'created_at': fields.DateTime,
    'acknowledged': fields.Boolean
})

sla_breach_model = alert_ns.model('SLABreach', {
    'id': fields.Integer,
    'service_id': fields.Integer,
    'type': fields.String,
    'downtime_minutes': fields.Integer,
    'threshold_minutes': fields.Integer,
    'start_time': fields.DateTime,
    'end_time': fields.DateTime,
    'reason': fields.String,
    'created_at': fields.DateTime
})

# --- Auth Routes ---
@auth_ns.route('/signup')
class Signup(Resource):
    @auth_ns.expect(signup_model)
    def post(self):
        data = auth_ns.payload
        if not data['username']:
            return {'error': 'Username is required'}, 400
        if not data['password']:
            return {'error': 'Password is required'}, 400
        if len(data['password']) < 6:
            return {'error': 'Password must be at least 6 characters long'}, 400
        if User.query.filter_by(username=data['username']).first():
            return {'error': 'User already exists'}, 400
        user = User(
            username=data['username'],
            password=generate_password_hash(data['password']),
            role=data.get('role', 'user')
        )
        db.session.add(user)
        db.session.commit()
        log_audit("User Signup", "User", user.id, None)
        return {'message': 'User registered successfully'}, 201

@auth_ns.route('/login')
class Login(Resource):
    @auth_ns.expect(login_model)
    def post(self):
        data = auth_ns.payload
        user = User.query.filter_by(username=data['username']).first()
        if not user or not check_password_hash(user.password, data['password']):
            return {'error': 'Invalid username or password'}, 401
        token = create_access_token(identity=str(user.id),
                                    additional_claims={"username": user.username, "role": user.role})
        return {'access_token': token}, 200

# --- Service Routes ---
@service_ns.route('')
class ServiceList(Resource):
    @jwt_required()
    @role_required('Business Owner')
    @api.doc(security='Bearer')
    @service_ns.expect(service_model)
    def post(self):
        data = service_ns.payload
        user = User.query.get(get_jwt_identity())
        service = Service(
            name=data['name'],
            description=data.get('description'),
            created_by=user.username
        )
        db.session.add(service)
        db.session.commit()
        bia = BIA(
            service_id=service.id,
            criticality=data.get('criticality'),
            impact=data.get('impact'),
            rto=data.get('rto'),
            rpo=data.get('rpo'),
            signed_off=data.get('signed_off', False)
        )
        db.session.add(bia)
        db.session.commit()
        dependencies = data.get('dependencies', [])
        for dep_id in dependencies:
            dependent_service = Service.query.get(dep_id)
            if dependent_service:
                bia.dependencies.append(dependent_service)
        db.session.commit()
        log_audit("Service Created", "Service", service.id, user.id)
        return {'message': 'Service created', 'service_id': service.id}, 201

    @jwt_required()
    def get(self):
        services = Service.query.all()
        results = []
        for s in services:
            results.append({
                'id': s.id,
                'name': s.name,
                'description': s.description,
                'created_by': s.created_by,
                'bia': {
                    'criticality': s.bia.criticality if s.bia else None,
                    'impact': s.bia.impact if s.bia else None,
                    'rto': s.bia.rto if s.bia else None,
                    'rpo': s.bia.rpo if s.bia else None,
                    'signed_off': s.bia.signed_off if s.bia else False,
                    'dependencies': [dep.id for dep in s.bia.dependencies] if s.bia else []
                },
                'status': s.status.status if s.status else "Unknown",
                'last_updated': s.status.last_updated.isoformat() if s.status and s.status.last_updated else None
            })
        return results

    @jwt_required()
    @role_required('Business Owner')
    @service_ns.expect(service_model)
    def put(self):
        data = service_ns.payload
        service = Service.query.get_or_404(data['id'])
        service.name = data.get('name', service.name)
        service.description = data.get('description', service.description)
        if service.bia:
            service.bia.criticality = data.get('criticality', service.bia.criticality)
            service.bia.impact = data.get('impact', service.bia.impact)
            service.bia.rto = data.get('rto', service.bia.rto)
            service.bia.rpo = data.get('rpo', service.bia.rpo)
            service.bia.signed_off = data.get('signed_off', service.bia.signed_off)
            dependency_ids = data.get('dependencies')
            if dependency_ids is not None:
                service.bia.dependencies = [
                    Service.query.get(dep_id) for dep_id in dependency_ids if Service.query.get(dep_id)
                ]
        db.session.commit()
        log_audit("Service Updated", "Service", service.id, get_jwt_identity())
        return {'message': 'Service updated successfully'}, 200

# --- Service Status Route ---
@service_ns.route('/<int:service_id>/status')
class ServiceStatus(Resource):
    @jwt_required()
    @role_required('Business Owner')
    @service_ns.expect(status_model)
    def post(self, service_id):
        data = service_ns.payload
        status = Status.query.filter_by(service_id=service_id).first()
        if not status:
            status = Status(service_id=service_id, status=data['status'])
        else:
            status.status = data['status']
            status.last_updated = datetime.utcnow()
        db.session.add(status)
        db.session.commit()
        log_audit("Status Updated", "Status", service_id, get_jwt_identity())
        return {'message': 'Status updated'}, 200

    @jwt_required()
    @role_required('Business Owner')
    @service_ns.expect(status_model)
    def put(self, service_id):
        data = service_ns.payload
        status = Status.query.filter_by(service_id=service_id).first()
        if not status:
            status = Status(service_id=service_id, status=data['status'])
        else:
            status.status = data['status']
            status.last_updated = datetime.utcnow()
        db.session.add(status)
        db.session.commit()
        log_audit("Status Updated", "Status", service_id, get_jwt_identity())
        return {'message': 'Status updated successfully'}, 200

# --- BIA Route ---
@service_ns.route('/<int:service_id>/bia')
class BIAResource(Resource):
    @jwt_required()
    @role_required('Business Owner')
    @service_ns.expect(service_model)
    def put(self, service_id):
        data = service_ns.payload
        service = Service.query.get_or_404(service_id)
        dependency_ids = data.get('dependencies')
        resolved_dependencies = [
            Service.query.get(dep_id) for dep_id in dependency_ids if Service.query.get(dep_id)
        ] if dependency_ids else []
        if not service.bia:
            bia = BIA(
                service_id=service.id,
                criticality=data.get('criticality'),
                impact=data.get('impact'),
                rto=data.get('rto'),
                rpo=data.get('rpo'),
                signed_off=data.get('signed_off', False),
                dependencies=resolved_dependencies
            )
            db.session.add(bia)
        else:
            service.bia.criticality = data.get('criticality', service.bia.criticality)
            service.bia.impact = data.get('impact', service.bia.impact)
            service.bia.rto = data.get('rto', service.bia.rto)
            service.bia.rpo = data.get('rpo', service.bia.rpo)
            service.bia.signed_off = data.get('signed_off', service.bia.signed_off)
            service.bia.dependencies = resolved_dependencies
        db.session.commit()
        log_audit("BIA Updated", "BIA", service_id, get_jwt_identity())
        return {'message': 'BIA updated successfully'}, 200

    @jwt_required()
    @role_required('Business Owner')
    def delete(self, service_id):
        service = Service.query.get_or_404(service_id)
        if service.bia:
            db.session.delete(service.bia)
            db.session.commit()
            log_audit("BIA Deleted", "BIA", service_id, get_jwt_identity())
            return {'message': 'BIA deleted successfully'}, 200
        else:
            return {'error': 'No BIA found for this service'}, 404

# --- Risk Route ---
@risk_ns.route('/<int:service_id>')
class GetRisk(Resource):
    @jwt_required()
    def get(self, service_id):
        service = Service.query.get_or_404(service_id)
        latest_risk = Risk.query.filter_by(service_id=service.id).order_by(Risk.created_at.desc()).first()
        if not latest_risk:
            return {'message': 'No risk score available for this service'}, 404
        return {
            'service_id': latest_risk.service_id,
            'risk_score': latest_risk.risk_score,
            'risk_level': latest_risk.risk_level,
            'is_critical': latest_risk.is_critical,
            'reason': latest_risk.reason,
            'source': latest_risk.source,
            'created_by': latest_risk.created_by,
            'created_at': latest_risk.created_at.isoformat()
        }, 200

@risk_ns.route('/<int:service_id>/save')
class SaveRisk(Resource):
    @jwt_required()
    @role_required('Ops Analyst')
    def post(self, service_id):
        service = Service.query.get_or_404(service_id)
        bia = BIA.query.filter_by(service_id=service.id).first()
        status = Status.query.filter_by(service_id=service.id).first()
        all_services = Service.query.all()
        result = calculate_risk_score(service, bia, status, all_services)
        risk = Risk(
            service_id=service.id,
            risk_score=result['risk_score'],
            risk_level=result['risk_level'],
            is_critical=result['is_critical'],
            reason=result['reason'],
            source='automated',
            created_by=get_jwt_identity()
        )
        db.session.add(risk)
        db.session.commit()
        log_audit("Automated Risk Score Saved", "Risk", service_id, get_jwt_identity())
        return {
            'message': 'Risk score saved',
            'service_id': service.id,
            'risk_score': result['risk_score'],
            'risk_level': result['risk_level'],
            'is_critical': result['is_critical'],
            'reason': result['reason']
        }, 200

@risk_ns.route('/<int:service_id>/manual')
class ManualRisk(Resource):
    @jwt_required()
    @role_required('Ops Analyst')
    def post(self, service_id):
        data = risk_ns.payload
        risk = Risk(
            service_id=service_id,
            risk_score=data['risk_score'],
            risk_level=data['risk_level'],
            reason=data.get('reason', ''),
            is_critical=data.get('is_critical', False),
            source='manual',
            created_by=get_jwt_identity()
        )
        db.session.add(risk)
        db.session.commit()
        log_audit("Manual Risk Score Added", "Risk", service_id, get_jwt_identity())
        return {'message': 'Manual risk score added'}, 200

    @jwt_required()
    @role_required('Ops Analyst')
    def put(self, service_id):
        data = risk_ns.payload
        risk = Risk.query.filter_by(service_id=service_id).order_by(Risk.created_at.desc()).first()
        if not risk:
            return {'message': 'No manual risk record found to update.'}, 404
        risk.risk_score = data['risk_score']
        risk.risk_level = data['risk_level']
        risk.reason = data.get('reason', risk.reason)
        risk.is_critical = data.get('is_critical', risk.is_critical)
        risk.created_at = datetime.utcnow()
        risk.created_by = get_jwt_identity()
        db.session.commit()
        log_audit("Manual Risk Score Updated", "Risk", service_id, get_jwt_identity())
        return {'message': 'Manual risk score updated'}, 200

# --- Audit Route ---
@audit_ns.route('')
class AuditLogList(Resource):
    @jwt_required()
    def get(self):
        logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
        return [{
            'id': log.id,
            'action': log.action,
            'entity': log.entity,
            'entity_id': log.entity_id,
            'timestamp': log.timestamp.isoformat(),
            'user_id': log.user_id
        } for log in logs]

# --- Integration Route ---
@service_ns.route('/integrations')
class IntegrationAPI(Resource):
    @jwt_required()
    @role_required('Engineer')
    @service_ns.expect(integration_model)
    def post(self):
        data = request.get_json()
        service = Service.query.get(data['service_id'])
        if not service:
            return {"error": "Service not found"}, 404
        integration = Integration(
            service_id=data['service_id'],
            type=data['type'],
            config=data['config'],
            created_by=get_jwt_identity()
        )
        db.session.add(integration)
        db.session.commit()
        if data['type'].lower() == 'slack':
            webhook_url = data['config'].get('webhook_url')
            channel = data['config'].get('channel', 'unknown')
            if webhook_url:
                slack_message = {
                    "text": f"🔧 *New Slack integration added!*\nService: *{service.name}*\nChannel: `#{channel}`"
                }
                try:
                    response = requests.post(webhook_url, json=slack_message, verify=False)
                    if response.status_code != 200:
                        logger.error(f"Slack message failed: {response.status_code} - {response.text}")
                except requests.exceptions.RequestException as e:
                    logger.error(f"Slack webhook error: {e}")
        return {"message": "Integration added successfully"}, 201

    @jwt_required()
    @role_required('Engineer')
    def get(self):
        integrations = Integration.query.all()
        return [{
            'id': i.id,
            'service_id': i.service_id,
            'type': i.type,
            'config': i.config,
            'created_by': i.created_by,
            'created_at': i.created_at.isoformat()
        } for i in integrations], 200

# --- Dependencies Route ---
@service_ns.route('/dependencies')
class ServiceDependencies(Resource):
    @jwt_required()
    @role_required('Engineer')
    def get(self):
        services = Service.query.all()
        result = []
        for service in services:
            if service.bia and service.bia.dependencies:
                dependencies_info = []
                for dep in service.bia.dependencies:
                    dep_bia = dep.bia
                    dep_status = dep.status
                    dependencies_info.append({
                        "service_id": dep.id,
                        "service_name": dep.name,
                        "criticality": dep_bia.criticality if dep_bia else None,
                        "impact": dep_bia.impact if dep_bia else None,
                        "rto": dep_bia.rto if dep_bia else None,
                        "rpo": dep_bia.rpo if dep_bia else None,
                        "status": dep_status.status if dep_status else None
                    })
                result.append({
                    "service_id": service.id,
                    "service_name": service.name,
                    "dependencies": dependencies_info
                })
        return {"dependencies": result}, 200

# --- Downtime Route ---
@service_ns.route('/<int:service_id>/downtime')
class ServiceDowntime(Resource):
    @jwt_required()
    def post(self, service_id):
        data = request.get_json()
        service = Service.query.get_or_404(service_id)
        try:
            start_time = datetime.fromisoformat(data['start_time'])
            end_time = datetime.fromisoformat(data['end_time']) if data.get('end_time') else None
        except ValueError:
            return {'message': 'Invalid date format. Use ISO 8601 (YYYY-MM-DDTHH:MM:SS).'}, 400
        reason = data.get('reason', 'Not specified')
        downtime = Downtime(
            service_id=service.id,
            start_time=start_time,
            end_time=end_time,
            reason=reason
        )
        db.session.add(downtime)
        db.session.commit()
        log_audit("Downtime Logged", "Downtime", service_id, get_jwt_identity())
        return {
            'message': 'Downtime logged',
            'downtime': {
                'service_id': service.id,
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat() if end_time else None,
                'reason': reason
            }
        }, 200

    @jwt_required()
    def get(self, service_id):
        service = Service.query.get_or_404(service_id)
        downtimes = Downtime.query.filter_by(service_id=service.id).order_by(Downtime.start_time.desc()).all()
        downtime_list = []
        for dt in downtimes:
            start = dt.start_time
            end = dt.end_time or datetime.utcnow()
            duration = end - start
            total_minutes = int(duration.total_seconds() / 60)
            downtime_list.append({
                'start_time': start.isoformat(),
                'end_time': dt.end_time.isoformat() if dt.end_time else None,
                'reason': dt.reason,
                'duration': str(duration),
                'total_minutes': total_minutes
            })
        return {
            'service_id': service.id,
            'service_name': service.name,
            'downtime_count': len(downtime_list),
            'downtimes': downtime_list
        }

# --- Health Check ---
def run_health_checks():
    with app.app_context():
        services = Service.query.all()
        status_changes = False
        
        for service in services:
            status = service.status
            bia = service.bia
            now = datetime.now()  # naive datetime
            
            if not status:
                status = Status(service_id=service.id, status="Unknown", last_updated=now)
                db.session.add(status)
                status_changes = True
                create_alert(service, "StatusChange", f"Service {service.name} status is Unknown", "Warning")
            else:
                delta = now - status.last_updated if status.last_updated else None
                
                if delta is None or delta > timedelta(minutes=10):
                    if status.status != "Down":
                        status.status = "Down"
                        status_changes = True
                        create_alert(service, "StatusChange", f"Service {service.name} is Down", "Critical")
                        send_alert(service)
                elif delta > timedelta(minutes=5):
                    if status.status != "Degraded":
                        status.status = "Degraded"
                        status_changes = True
                        create_alert(service, "StatusChange", f"Service {service.name} is Degraded", "Warning")
                else:
                    if status.status != "Up":
                        status.status = "Up"
                        status_changes = True
                        create_alert(service, "StatusChange", f"Service {service.name} is Up", "Info")
            
            if status.last_updated is None or status_changes:
                status.last_updated = now
            
            all_services = Service.query.all()
            risk_result = calculate_risk_score(service, bia, status, all_services)
            
            if risk_result.get('risk_level') == 'High':
                create_alert(service, "HighRisk", f"High risk score: {risk_result['risk_score']}. Reason: {risk_result['reason']}", "Critical")
            
            if risk_result.get('is_critical'):
                create_alert(service, "Critical", f"Service {service.name} is critical: {risk_result['reason']}", "Critical")
            
            if bia and (bia.rto or bia.rpo):
                downtimes = Downtime.query.filter_by(service_id=service.id).filter(
                    or_(
                        Downtime.end_time.is_(None),
                        Downtime.end_time > now - timedelta(hours=24)
                    )
                ).all()
                
                for downtime in downtimes:
                    downtime_duration = ((downtime.end_time or now) - downtime.start_time).total_seconds() / 60
                    if bia.rto and downtime_duration > bia.rto:
                        create_sla_breach(
                            service,
                            "RTO",
                            downtime_duration,
                            bia.rto,
                            downtime.start_time,
                            downtime.end_time,
                            f"Downtime exceeded RTO of {bia.rto} minutes"
                        )
                    if bia.rpo and downtime_duration > bia.rpo:
                        create_sla_breach(
                            service,
                            "RPO",
                            downtime_duration,
                            bia.rpo,
                            downtime.start_time,
                            downtime.end_time,
                            f"Downtime exceeded RPO of {bia.rpo} minutes"
                        )
        
        db.session.commit()


def create_alert(service, alert_type, message, severity):
    alert = Alert(
        service_id=service.id,
        type=alert_type,
        message=message,
        severity=severity
    )
    db.session.add(alert)
    db.session.commit()
    log_audit(f"Alert Created ({alert_type})", "Alert", service.id, 0)

def create_sla_breach(service, breach_type, downtime_minutes, threshold_minutes, start_time, end_time, reason):
    existing_breach = SLABreach.query.filter_by(
        service_id=service.id,
        type=breach_type,
        start_time=start_time
    ).first()
    if not existing_breach:
        breach = SLABreach(
            service_id=service.id,
            type=breach_type,
            downtime_minutes=int(downtime_minutes),
            threshold_minutes=threshold_minutes,
            start_time=start_time,
            end_time=end_time,
            reason=reason
        )
        db.session.add(breach)
        db.session.commit()
        log_audit(f"SLA Breach ({breach_type})", "SLABreach", service.id, 0)
        create_alert(
            service,
            f"SLA_{breach_type}",
            f"SLA Breach: {breach_type} exceeded {threshold_minutes} minutes (Actual: {int(downtime_minutes)} minutes)",
            "Critical"
        )

def send_alert(service):
    integration = Integration.query.filter_by(service_id=service.id, type='Slack').first()
    if integration and integration.config.get('webhook_url'):
        webhook_url = integration.config['webhook_url']
        channel = integration.config.get('channel', 'general')
        slack_message = {
            "text": f"🚨 *ALERT: Service Down!*\nService: *{service.name}*\nChannel: `#{channel}`"
        }
        try:
            response = requests.post(webhook_url, json=slack_message, verify=False)
            if response.status_code != 200:
                logger.error(f"Slack alert failed: {response.status_code} - {response.text}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Slack webhook error: {e}")
    else:
        logger.info(f"ALERT: {service.name} is down! (No Slack integration)")

@service_ns.route('/<int:service_id>/health')
class ServiceHealth(Resource):
    @jwt_required()
    def get(self, service_id):
        # Just call run_health_checks() directly; it has its own app_context
        run_health_checks()
        
        service = db.session.get(Service, service_id)
        if not service:
            return {'error': 'Service not found'}, 404
        
        bia = service.bia
        status = service.status
        latest_downtime = Downtime.query.filter_by(service_id=service_id).order_by(Downtime.start_time.desc()).first()
        all_services = Service.query.all()
        
        current_status = status.status if status else "Unknown"
        risk_result = calculate_risk_score(service, bia, status, all_services)
        overall_health, reason = determine_overall_health(current_status, risk_result)
        
        health_info = {
            "service_id": service.id,
            "name": service.name,
            "status": current_status,
            "last_updated": status.last_updated.isoformat() if status and status.last_updated else None,
            "bia": {
                "criticality": bia.criticality if bia else None,
                "rto": bia.rto if bia else None,
                "rpo": bia.rpo if bia else None
            },
            "downtime": {
                "start_time": latest_downtime.start_time.isoformat() if latest_downtime else None,
                "reason": latest_downtime.reason if latest_downtime else None
            },
            "overall_health": overall_health,
            "risk_score": risk_result.get('risk_score'),
            "is_critical": risk_result.get('is_critical'),
            "reason": reason,
            "uptime_percentage": calculate_uptime_percentage(service)
        }
        return health_info, 200

def determine_overall_health(current_status, risk_result):
    risk_level = risk_result['risk_level']
    reasons = risk_result['reason'].split(', ') if risk_result['reason'] else []
    if current_status == "Up" and risk_level == "Low":
        health_status = "Healthy"
        if not reasons:
            reasons.append("Service is operational with low risk")
    elif current_status == "Down" or risk_level == "High":
        health_status = "Unhealthy"
        if current_status == "Down" and "Service is currently down" not in reasons:
            reasons.append("Service is currently down")
    else:
        health_status = "Degraded"
        if current_status == "Degraded" and "Service is degraded" not in reasons:
            reasons.append("Service is degraded")
    return health_status, ', '.join(reasons) if reasons else "No issues detected"

def calculate_uptime_percentage(service):
    if not service.status or not service.status.last_updated:
        return 100.0  # No status or uptime data, assume fully up
    now = datetime.utcnow()  # Returns naive UTC datetime
    total_time = now - service.status.last_updated
    if total_time.total_seconds() <= 0:
        return 100.0  # Avoid negative or zero total_time
    downtime = Downtime.query.filter_by(service_id=service.id).all()
    downtime_duration = sum(
        [(d.end_time or now) - d.start_time for d in downtime],
        timedelta()
    )
    uptime_duration = total_time - downtime_duration
    if uptime_duration.total_seconds() < 0:
        uptime_duration = timedelta(seconds=0)  # Prevent negative uptime
    uptime_percentage = (uptime_duration.total_seconds() / total_time.total_seconds()) * 100
    return max(0.0, min(100.0, round(uptime_percentage, 2)))

# --- Alert Routes ---
@alert_ns.route('')
class AlertList(Resource):
    @jwt_required()
    def get(self):
        alerts = Alert.query.order_by(Alert.created_at.desc()).all()
        return [{
            'id': alert.id,
            'service_id': alert.service_id,
            'type': alert.type,
            'message': alert.message,
            'severity': alert.severity,
            'created_at': alert.created_at.isoformat(),
            'acknowledged': alert.acknowledged
        } for alert in alerts], 200

    @jwt_required()
    @role_required('Ops Analyst')
    @alert_ns.expect(alert_model)
    def put(self):
        data = alert_ns.payload
        alert = Alert.query.get_or_404(data['id'])
        alert.acknowledged = data.get('acknowledged', alert.acknowledged)
        db.session.commit()
        log_audit("Alert Acknowledged", "Alert", alert.service_id, get_jwt_identity())
        return {'message': 'Alert updated'}, 200

@alert_ns.route('/sla_breaches')
class SLABreachList(Resource):
    @jwt_required()
    def get(self):
        breaches = SLABreach.query.order_by(SLABreach.created_at.desc()).all()
        return [{
            'id': breach.id,
            'service_id': breach.service_id,
            'type': breach.type,
            'downtime_minutes': breach.downtime_minutes,
            'threshold_minutes': breach.threshold_minutes,
            'start_time': breach.start_time.isoformat(),
            'end_time': breach.end_time.isoformat() if breach.end_time else None,
            'reason': breach.reason,
            'created_at': breach.created_at.isoformat()
        } for breach in breaches], 200

# --- Scheduler ---
scheduler = BackgroundScheduler()
scheduler.add_job(run_health_checks, 'interval', minutes=5)
scheduler.start()

# --- Init & Run ---
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True, port=5001, ssl_context='adhoc')