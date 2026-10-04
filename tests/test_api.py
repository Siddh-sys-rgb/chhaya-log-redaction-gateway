import io
from pathlib import Path
import pytest
from app import create_app

SECRET='LEAK_SENTINEL_8842'

def test_health_and_template(client):
    assert client.get('/api/health').json['offline'] is True
    assert client.get('/').status_code==200
    assert b'CHHAYA' in client.get('/').data

def test_distinct_cookie_and_headers(client):
    response=client.get('/api/bootstrap')
    assert 'chhaya_session=' in response.headers['Set-Cookie']
    assert 'HttpOnly' in response.headers['Set-Cookie']
    assert 'SameSite=Strict' in response.headers['Set-Cookie']
    assert response.headers['Cache-Control']=='no-store'
    assert "default-src 'self'" in response.headers['Content-Security-Policy']

@pytest.mark.parametrize('headers', [{},{'X-CSRF-Token':'wrong'}])
def test_csrf_required(client,headers):
    client.get('/api/bootstrap')
    assert client.post('/api/runs',json={'text':'hi'},headers=headers).status_code==403

def test_origin_and_host_guards(client,csrf):
    assert client.post('/api/runs',json={'text':'hi'},headers={**csrf,'Origin':'https://evil.test'}).status_code==403
    assert client.get('/api/health',headers={'Host':'evil.test'}).status_code==400
    assert client.post('/api/runs',json={'text':'hi'},headers={**csrf,'Origin':'http://localhost'}).status_code==201

def test_raw_never_saved_or_returned(client,csrf,application):
    response=client.post('/api/runs',json={'text':f'password="{SECRET}" email=riya@example.test'},headers=csrf)
    assert response.status_code==201
    item=response.json
    for path in ['/api/runs','/api/runs/'+item['id'],'/api/runs/'+item['id']+'/export']:
        assert SECRET.encode() not in client.get(path).data
        assert b'riya@example.test' not in client.get(path).data
    for path in Path(application.config['DB']).parent.glob('*.sqlite3*'):
        assert SECRET.encode() not in path.read_bytes()
    assert 'output' not in client.get('/api/runs').json['runs'][0]
    assert len(item['output_sha256'])==64

def test_artifacts_are_immutable(client,csrf):
    a=client.post('/api/runs',json={'text':'password=one'},headers=csrf).json
    b=client.post('/api/runs',json={'text':'password=two'},headers=csrf).json
    assert a['id']!=b['id']
    assert client.put('/api/runs/'+a['id'],json={'text':'new'},headers=csrf).status_code==405
    assert client.get('/api/runs/'+a['id']).json==a

@pytest.mark.parametrize('payload', [{'text':None},[],{'text':'x','mode':'xml'},{'text':f'{{"password":"{SECRET}"','mode':'jsonl'}])
def test_input_errors_are_safe(client,csrf,payload):
    response=client.post('/api/runs',json=payload,headers=csrf)
    assert response.status_code==400
    assert SECRET.encode() not in response.data

def test_utf8_upload_and_unsafe_filename(client,csrf):
    response=client.post('/api/runs',data={'file':(io.BytesIO(f'password={SECRET}'.encode()),f'{SECRET}.log'),'mode':'text'},headers=csrf)
    assert response.status_code==201
    exported=client.get('/api/runs/'+response.json['id']+'/export')
    assert SECRET not in str(exported.headers)
    assert SECRET.encode() not in exported.data

def test_bad_utf8_and_request_size(client,csrf):
    response=client.post('/api/runs',data={'file':(io.BytesIO(b'\xff'),'bad.log')},headers=csrf)
    assert response.status_code==400
    assert client.post('/api/runs',data='x'*400000,headers=csrf,content_type='application/json').status_code==413

def test_failures_hide_exception_and_input(client,csrf,monkeypatch,caplog):
    import app
    def fail(*args): raise RuntimeError(SECRET)
    monkeypatch.setattr(app.storage,'save',fail)
    response=client.post('/api/runs',json={'text':f'password={SECRET}'},headers=csrf)
    assert response.status_code==500
    assert SECRET.encode() not in response.data
    assert SECRET not in caplog.text

def test_no_demo_and_missing_routes(tmp_path):
    client=create_app(tmp_path,no_demo=True).test_client()
    assert client.get('/api/demo').status_code==404
    assert client.get('/api/runs/missing').status_code==404
    assert client.get('/api/runs/missing/export').status_code==404
    assert client.get('/missing').is_json

def test_original_demo(client,csrf):
    demo=client.get('/api/demo').json
    result=client.post('/api/runs',json=demo,headers=csrf).json
    assert result['matches']==6
    assert len(client.get('/api/runs').json['runs'])==1
