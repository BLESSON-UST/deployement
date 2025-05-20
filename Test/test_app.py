
import pytest
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import create_access_token
from datetime import datetime, timedelta
import json
from freezegun import freeze_time
import requests_mock
from werkzeug.security import generate_password_hash
from app import app as flask_app, db as app_db, User, Service, BIA, Status, Downtime, Risk, AuditLog, Alert, SLABreach, Integration, calculate_risk_score, determine_overall_health, calculate_uptime_percentage, log_audit, create_alert, create_sla_breach, run_health_checks
import datetime as dt  # For dt.UTC
from datetime import datetime, timezone

# --- Test Fixtures ---
@pytest.fixture
def app():
    """Create a test Flask app with in-memory SQLite database."""
    flask_app.config['TESTING'] = True
    flask_app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    flask_app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    flask_app.config['JWT_SECRET_KEY'] = 'test-secret-key'
    flask_app.config['SKIP_MYSQL_INIT'] = True  # Skip MySQL initialization
    with flask_app.app_context():
        app_db.create_all()
        yield flask_app
        app_db.drop_all()

@pytest.fixture
def client(app):
    """Create a test client for the Flask app."""
    return app.test_client()

@pytest.fixture
def db(app):
    """Provide the database instance."""
    with app.app_context():
        yield app_db  # Yield the SQLAlchemy instance

@pytest.fixture
def user(db):
    """Create a test user."""
    user = User(
        username='testuser',
        password=generate_password_hash('password123'),
        role='Business Owner'
    )
    db.session.add(user)
    db.session.commit()
    return user

@pytest.fixture
def ops_analyst(db):
    """Create a test Ops Analyst user."""
    user = User(
        username='opsanalyst',
        password=generate_password_hash('password123'),
        role='Ops Analyst'
    )
    db.session.add(user)
    db.session.commit()
    return user

@pytest.fixture
def engineer(db):
    """Create a test Engineer user."""
    user = User(
        username='engineer',
        password=generate_password_hash('password123'),
        role='Engineer'
    )
    db.session.add(user)
    db.session.commit()
    return user

@pytest.fixture
def service(db, user):
    """Create a test service with BIA and Status."""
    service = Service(
        name='Test Service',
        description='Test Description',
        created_by=user.username
    )
    db.session.add(service)
    db.session.commit()
    bia = BIA(
        service_id=service.id,
        criticality='High',
        impact='Severe',
        rto=30,
        rpo=60,
        signed_off=True
    )
    status = Status(
        service_id=service.id,
        status='Up',
        last_updated=datetime.utcnow()  
    )
    db.session.add_all([bia, status])
    db.session.commit()
    return service

@pytest.fixture
def downtime(db, service):
    """Create a test downtime record."""
    downtime = Downtime(
        service_id=service.id,
        start_time=datetime.utcnow()   - timedelta(hours=1),
        end_time=datetime.utcnow()  ,
        reason='Test downtime'
    )
    db.session.add(downtime)
    db.session.commit()
    return downtime

@pytest.fixture
def integration(db, service, engineer):
    """Create a test integration."""
    integration = Integration(
        service_id=service.id,
        type='Slack',
        config={'webhook_url': 'https://slack.com/webhook', 'channel': 'general'},
        created_by=engineer.username
    )
    db.session.add(integration)
    db.session.commit()
    return integration

# --- Unit Tests ---
def test_calculate_risk_score_service_down(db, service):
    """Test risk score calculation for a service that is down."""
    status = Status.query.filter_by(service_id=service.id).first()
    status.status = 'Down'
    db.session.commit()
    result = calculate_risk_score(service, service.bia, status, [])
    assert result['risk_score'] >= 40
    assert result['risk_level'] == 'Medium'
    assert result['is_critical']
    assert 'Service is currently down' in result['reason']

def test_calculate_risk_score_high_criticality(db, service):
    """Test risk score calculation for high criticality."""
    result = calculate_risk_score(service, service.bia, service.status, [])
    assert result['risk_score'] >= 15
    assert result['is_critical']
    assert 'High criticality in BIA' in result['reason']

def test_calculate_risk_score_dependencies_down(db, service):
    """Test risk score calculation with down dependencies."""
    dep_service = Service(name='Dep Service', created_by='testuser')
    dep_status = Status(service=dep_service, status='Down')
    db.session.add_all([dep_service, dep_status])
    db.session.commit()
    service.bia.dependencies.append(dep_service)
    db.session.commit()
    result = calculate_risk_score(service, service.bia, service.status, [dep_service])
    assert result['risk_score'] >= 20
    assert result['is_critical']
    assert 'Dependencies down: Dep Service' in result['reason']

def test_determine_overall_health_healthy():
    """Test overall health determination for healthy service."""
    status = 'Up'
    risk_result = {'risk_level': 'Low', 'risk_score': 20, 'reason': ''}
    health, reason = determine_overall_health(status, risk_result)
    assert health == 'Healthy'
    assert 'Service is operational with low risk' in reason

def test_determine_overall_health_unhealthy():
    """Test overall health determination for unhealthy service."""
    status = 'Down'
    risk_result = {'risk_level': 'High', 'risk_score': 80, 'reason': 'Service is down'}
    health, reason = determine_overall_health(status, risk_result)
    assert health == 'Unhealthy'
    assert 'Service is currently down' in reason

def test_calculate_uptime_percentage(db, service, downtime):
    """Test uptime percentage calculation."""
    with freeze_time(datetime.utcnow()  ):
        percentage = calculate_uptime_percentage(service)
        assert 0 <= percentage <= 100
        assert isinstance(percentage, float)

def test_log_audit(db):
    """Test audit log creation."""
    log_audit('Test Action', 'Test Entity', 1, 1)
    log = AuditLog.query.first()
    assert log.action == 'Test Action'
    assert log.entity == 'Test Entity'
    assert log.entity_id == 1
    assert log.user_id == 1

def test_create_alert(db, service):
    """Test alert creation."""
    create_alert(service, 'TestAlert', 'Test Message', 'Critical')
    alert = Alert.query.first()
    assert alert.type == 'TestAlert'
    assert alert.message == 'Test Message'
    assert alert.severity == 'Critical'
    assert alert.service_id == service.id

def test_create_sla_breach(db, service):
    """Test SLA breach creation."""
    start_time = datetime.utcnow()   - timedelta(hours=1)
    create_sla_breach(service, 'RTO', 90, 30, start_time, None, 'Test breach')
    breach = SLABreach.query.first()
    assert breach.type == 'RTO'
    assert breach.downtime_minutes == 90
    assert breach.threshold_minutes == 30
    assert breach.reason == 'Test breach'

# --- Integration Tests ---
def test_signup_success(client, db):
    """Test successful user signup."""
    data = {'username': 'newuser', 'password': 'password123', 'role': 'user'}
    response = client.post('/api/auth/signup', json=data)
    assert response.status_code == 201
    assert response.json['message'] == 'User registered successfully'
    user = User.query.filter_by(username='newuser').first()
    assert user is not None
    assert user.role == 'user'

def test_signup_existing_user(client, db, user):
    """Test signup with existing username."""
    data = {'username': 'testuser', 'password': 'password123'}
    response = client.post('/api/auth/signup', json=data)
    assert response.status_code == 400
    assert response.json['error'] == 'User already exists'

def test_signup_short_password(client):
    """Test signup with short password."""
    data = {'username': 'newuser', 'password': 'short'}
    response = client.post('/api/auth/signup', json=data)
    assert response.status_code == 400
    assert response.json['error'] == 'Password must be at least 6 characters long'

def test_login_success(client, user):
    """Test successful login."""
    data = {'username': 'testuser', 'password': 'password123'}
    response = client.post('/api/auth/login', json=data)
    assert response.status_code == 200
    assert 'access_token' in response.json

def test_login_invalid_credentials(client, user):
    """Test login with invalid credentials."""
    data = {'username': 'testuser', 'password': 'wrongpassword'}
    response = client.post('/api/auth/login', json=data)
    assert response.status_code == 401
    assert response.json['error'] == 'Invalid username or password'

def test_create_service_authorized(client, user):
    """Test creating a service as Business Owner."""
    token = create_access_token(identity=str(user.id), additional_claims={'role': 'Business Owner'})
    headers = {'Authorization': f'Bearer {token}'}
    data = {
        'name': 'New Service',
        'description': 'Test service',
        'criticality': 'Medium',
        'impact': 'Moderate',
        'rto': 60,
        'rpo': 120,
        'signed_off': True,
        'dependencies': []
    }
    response = client.post('/api/services', json=data, headers=headers)
    assert response.status_code == 201
    assert response.json['message'] == 'Service created'
    service = Service.query.filter_by(name='New Service').first()
    assert service is not None
    assert service.bia.criticality == 'Medium'

def test_create_service_unauthorized(client, user):
    """Test creating a service without Business Owner role."""
    token = create_access_token(identity=str(user.id), additional_claims={'role': 'user'})
    headers = {'Authorization': f'Bearer {token}'}
    data = {'name': 'New Service'}
    response = client.post('/api/services', json=data, headers=headers)
    assert response.status_code == 403
    assert response.json['error'] == 'Forbidden'

def test_get_services(client, user, service):
    """Test retrieving all services."""
    token = create_access_token(identity=str(user.id), additional_claims={'role': 'Business Owner'})
    headers = {'Authorization': f'Bearer {token}'}
    response = client.get('/api/services', headers=headers)
    assert response.status_code == 200
    assert len(response.json) == 1
    assert response.json[0]['name'] == 'Test Service'

def test_update_service(client, user, service, db):
    """Test updating a service."""
    token = create_access_token(identity=str(user.id), additional_claims={'role': 'Business Owner'})
    headers = {'Authorization': f'Bearer {token}'}
    data = {
        'id': service.id,
        'name': 'Updated Service',
        'criticality': 'Low',
        'dependencies': []
    }
    response = client.put('/api/services', json=data, headers=headers)
    assert response.status_code == 200
    assert response.json['message'] == 'Service updated successfully'
    updated_service = db.session.get(Service, service.id)
    assert updated_service.name == 'Updated Service'
    assert updated_service.bia.criticality == 'Low'

def test_update_status(client, user, service):
    """Test updating service status."""
    token = create_access_token(identity=str(user.id), additional_claims={'role': 'Business Owner'})
    headers = {'Authorization': f'Bearer {token}'}
    data = {'status': 'Down'}
    response = client.post(f'/api/services/{service.id}/status', json=data, headers=headers)
    assert response.status_code == 200
    assert response.json['message'] == 'Status updated'
    status = Status.query.filter_by(service_id=service.id).first()
    assert status.status == 'Down'

def test_update_bia(client, user, service):
    """Test updating BIA."""
    token = create_access_token(identity=str(user.id), additional_claims={'role': 'Business Owner'})
    headers = {'Authorization': f'Bearer {token}'}
    data = {'criticality': 'Low', 'impact': 'Minor', 'rto': 120}
    response = client.put(f'/api/services/{service.id}/bia', json=data, headers=headers)
    assert response.status_code == 200
    assert response.json['message'] == 'BIA updated successfully'
    bia = BIA.query.filter_by(service_id=service.id).first()
    assert bia.criticality == 'Low'
    assert bia.impact == 'Minor'

def test_get_risk(client, db, user, service, ops_analyst):
    """Test retrieving risk score."""
    token = create_access_token(identity=str(ops_analyst.id), additional_claims={'role': 'Ops Analyst'})
    headers = {'Authorization': f'Bearer {token}'}
    risk = Risk(
        service_id=service.id,
        risk_score=50,
        risk_level='Medium',
        reason='Test risk',
        source='manual',
        created_by=ops_analyst.username
    )
    db.session.add(risk)
    db.session.commit()
    response = client.get(f'/api/risk/{service.id}', headers=headers)
    assert response.status_code == 200
    assert response.json['risk_score'] == 50
    assert response.json['risk_level'] == 'Medium'

def test_save_risk(client, ops_analyst, service):
    """Test saving automated risk score."""
    token = create_access_token(identity=str(ops_analyst.id), additional_claims={'role': 'Ops Analyst'})
    headers = {'Authorization': f'Bearer {token}'}
    response = client.post(f'/api/risk/{service.id}/save', headers=headers)
    assert response.status_code == 200
    assert response.json['message'] == 'Risk score saved'
    risk = Risk.query.filter_by(service_id=service.id).first()
    assert risk is not None
    assert risk.source == 'automated'

def test_manual_risk(client, ops_analyst, service):
    """Test adding manual risk score."""
    token = create_access_token(identity=str(ops_analyst.id), additional_claims={'role': 'Ops Analyst'})
    headers = {'Authorization': f'Bearer {token}'}
    data = {'risk_score': 75, 'risk_level': 'High', 'reason': 'Manual test', 'is_critical': True}
    response = client.post(f'/api/risk/{service.id}/manual', json=data, headers=headers)
    assert response.status_code == 200
    assert response.json['message'] == 'Manual risk score added'
    risk = Risk.query.filter_by(service_id=service.id).first()
    assert risk.risk_score == 75
    assert risk.source == 'manual'

def test_get_audit_logs(client, user):
    """Test retrieving audit logs."""
    token = create_access_token(identity=str(user.id), additional_claims={'role': 'Business Owner'})
    headers = {'Authorization': f'Bearer {token}'}
    log_audit('Test Action', 'Test Entity', 1, user.id)
    response = client.get('/api/audit', headers=headers)
    assert response.status_code == 200
    assert len(response.json) == 1
    assert response.json[0]['action'] == 'Test Action'

def test_create_integration(client, engineer, service, mocker):
    """Test creating a Slack integration."""
    token = create_access_token(identity=str(engineer.id), additional_claims={'role': 'Engineer'})
    headers = {'Authorization': f'Bearer {token}'}
    data = {
        'service_id': service.id,
        'type': 'Slack',
        'config': {'webhook_url': 'https://slack.com/webhook', 'channel': 'general'}
    }
    with requests_mock.Mocker() as m:
        m.post('https://slack.com/webhook', status_code=200)
        response = client.post('/api/services/integrations', json=data, headers=headers)
        assert response.status_code == 201
        assert response.json['message'] == 'Integration added successfully'
        integration = Integration.query.filter_by(service_id=service.id).first()
        assert integration.type == 'Slack'

def test_get_dependencies(client, db, engineer, service):
    """Test retrieving service dependencies."""
    token = create_access_token(identity=str(engineer.id), additional_claims={'role': 'Engineer'})
    headers = {'Authorization': f'Bearer {token}'}
    dep_service = Service(name='Dep Service', created_by='testuser')
    db.session.add(dep_service)
    db.session.commit()
    service.bia.dependencies.append(dep_service)
    db.session.commit()
    response = client.get('/api/services/dependencies', headers=headers)
    assert response.status_code == 200
    assert len(response.json['dependencies']) == 1
    assert response.json['dependencies'][0]['service_name'] == 'Test Service'

def test_log_downtime(client, user, service):
    """Test logging downtime."""
    token = create_access_token(identity=str(user.id), additional_claims={'role': 'Business Owner'})
    headers = {'Authorization': f'Bearer {token}'}
    start_time = datetime.utcnow()  .isoformat()
    data = {'start_time': start_time, 'reason': 'Test downtime'}
    response = client.post(f'/api/services/{service.id}/downtime', json=data, headers=headers)
    assert response.status_code == 200
    assert response.json['message'] == 'Downtime logged'
    downtime = Downtime.query.filter_by(service_id=service.id).first()
    assert downtime.reason == 'Test downtime'

def test_health_check(client, user, service, mocker):
    token = create_access_token(identity=str(user.id), additional_claims={'role': 'Business Owner'})
    headers = {'Authorization': f'Bearer {token}'}
    aware_now = datetime.now(timezone.utc)
    with freeze_time(aware_now):
        response = client.get(f'/api/services/{service.id}/health', headers=headers)
        assert response.status_code == 200
        assert response.json['service_id'] == service.id
        assert response.json['status'] == 'Up'
        assert response.json['overall_health'] in ['Healthy', 'Degraded', 'Unhealthy']


def test_get_alerts(client, user, service):
    """Test retrieving alerts."""
    token = create_access_token(identity=str(user.id), additional_claims={'role': 'Business Owner'})
    headers = {'Authorization': f'Bearer {token}'}
    create_alert(service, 'TestAlert', 'Test Message', 'Critical')
    response = client.get('/api/alerts', headers=headers)
    assert response.status_code == 200
    assert len(response.json) == 1
    assert response.json[0]['type'] == 'TestAlert'

def test_acknowledge_alert(client, db, ops_analyst, service):
    """Test acknowledging an alert."""
    token = create_access_token(identity=str(ops_analyst.id), additional_claims={'role': 'Ops Analyst'})
    headers = {'Authorization': f'Bearer {token}'}
    alert = Alert(service_id=service.id, type='TestAlert', message='Test', severity='Critical')
    db.session.add(alert)
    db.session.commit()
    data = {'id': alert.id, 'acknowledged': True}
    response = client.put('/api/alerts', json=data, headers=headers)
    assert response.status_code == 200
    assert response.json['message'] == 'Alert updated'
    updated_alert = db.session.get(Alert, alert.id)
    assert updated_alert.acknowledged

def test_get_sla_breaches(client, user, service):
    """Test retrieving SLA breaches."""
    token = create_access_token(identity=str(user.id), additional_claims={'role': 'Business Owner'})
    headers = {'Authorization': f'Bearer {token}'}
    start_time = datetime.utcnow()  
    create_sla_breach(service, 'RTO', 90, 30, start_time, None, 'Test breach')
    response = client.get('/api/alerts/sla_breaches', headers=headers)
    assert response.status_code == 200
    assert len(response.json) == 1
    assert response.json[0]['type'] == 'RTO'

def test_run_health_checks(mocker, db, service):
    mocker.patch('app.send_alert')  # Mock send_alert to avoid Slack calls
    naive_now = datetime.now()
    with freeze_time(naive_now):
        status = Status.query.filter_by(service_id=service.id).first()
        status.last_updated = naive_now - timedelta(minutes=15)
        status.status = 'Up'
        db.session.commit()
        run_health_checks()
        updated_status = Status.query.filter_by(service_id=service.id).first()
        assert updated_status.status == 'Down'
        alert = Alert.query.filter_by(service_id=service.id, type='StatusChange').first()
        assert alert is not None
        assert alert.severity == 'Critical'