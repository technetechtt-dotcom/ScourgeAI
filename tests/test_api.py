import os, json, time, hmac, hashlib
from fastapi.testclient import TestClient
os.environ['DATABASE_URL']='sqlite:///./test_techne.db'
os.environ['TIC_DATA_KEY']='test-data-key-not-for-production'
os.environ['TIC_CLIENT_SECRETS']=json.dumps({'tenant-a:guardian':'secret-guardian','tenant-a:arxvigil':'secret-arx','tenant-b:guardian':'other-guardian'})
from app import main
from app.models import Base
Base.metadata.drop_all(main.engine)
Base.metadata.create_all(main.engine)
client=TestClient(main.app)

def send(event_id,product,event_type,subject='person-1',tenant='tenant-a',secret=None):
    data={'schema_version':'1.0','event_id':event_id,'event_type':event_type,'source_product':product,'tenant_id':tenant,'subject_type':'person' if product=='guardian' else 'vehicle','subject_id':subject,'occurred_at':'2026-10-22T12:00:00Z','source':{},'observation':{},'integrity':{}}
    body=json.dumps(data,separators=(',',':')).encode()
    ts=str(int(time.time()))
    secret=secret if secret is not None else ('secret-guardian' if product=='guardian' else 'secret-arx')
    sig=hmac.new(secret.encode(),ts.encode()+b'.'+body,hashlib.sha256).hexdigest()
    return client.post('/v1/events',content=body,headers={'X-Event-Timestamp':ts,'X-Event-Signature':sig,'X-Event-Nonce':event_id,'Content-Type':'application/json'})

def test_health():
    assert client.get('/health').json()['live_dispatch'] is False

def test_explicit_sos_immediate_incident():
    r=send('sos-001','guardian','sos.manual')
    assert r.status_code==201
    assert r.json()['risk_level']=='EMERGENCY'
    assert send('sos-001','guardian','sos.manual').json()['duplicate'] is True
    detail=client.get('/v1/incidents/'+r.json()['incident_id'],params={'tenant_id':'tenant-a','product':'guardian'},headers={'X-Client-Secret':'secret-guardian'})
    assert detail.status_code==200
    assert detail.json()['assessment']['confidence']=='CONFIRMED_TRIGGER'
    assert detail.json()['recommendations'][0]['status']=='PENDING'

def test_two_distinct_signals_escalate_but_not_confirm_theft():
    a=send('arx-001','arxvigil','device.primary_signal_lost','vehicle-1')
    b=send('arx-002','arxvigil','device.power_cut','vehicle-1')
    assert a.json()['incident_id']==b.json()['incident_id']
    assert b.json()['risk_level']=='HIGH_RISK'
    detail=client.get('/v1/incidents/'+b.json()['incident_id'],params={'tenant_id':'tenant-a','product':'arxvigil'},headers={'X-Client-Secret':'secret-arx'}).json()
    assert 'theft is not confirmed' in detail['assessment']['inferred'][0]

def test_untrusted_and_cross_product_rejected():
    assert send('bad-auth','guardian','sos.manual',secret='wrong').status_code==401
    i=send('isolated-01','arxvigil','device.tamper','vehicle-7').json()['incident_id']
    assert client.get('/v1/incidents/'+i,params={'tenant_id':'tenant-a','product':'guardian'},headers={'X-Client-Secret':'secret-guardian'}).status_code==404
    assert client.get('/v1/incidents',params={'tenant_id':'tenant-b','product':'guardian'},headers={'X-Client-Secret':'secret-guardian'}).status_code==401

def test_operator_review_never_executes_action():
    r=send('sos-002','guardian','sos.volume','person-2')
    detail=client.get('/v1/incidents/'+r.json()['incident_id'],params={'tenant_id':'tenant-a','product':'guardian'},headers={'X-Client-Secret':'secret-guardian'}).json()
    rec=detail['recommendations'][0]['id']
    result=client.post('/v1/recommendations/'+rec+'/review',params={'tenant_id':'tenant-a','product':'guardian'},headers={'X-Client-Secret':'secret-guardian'},json={'status':'ACCEPTED','reviewer':'test-operator'})
    assert result.json()['action_executed'] is False
    assert result.json()['status']=='ACCEPTED'
    assert client.post('/v1/recommendations/'+rec+'/review',params={'tenant_id':'tenant-a','product':'guardian'},headers={'X-Client-Secret':'secret-guardian'},json={'status':'REJECTED','reviewer':'test-operator'}).status_code==409
