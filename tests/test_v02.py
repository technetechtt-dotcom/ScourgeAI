from tests.test_api import client, send

def credentials(product='guardian', tenant='tenant-a'):
    return {'params':{'tenant_id':tenant,'product':product}, 'headers':{'X-Client-Secret':'secret-guardian' if product=='guardian' else 'secret-arx'}}

def test_copilot_evidence_and_timeline():
    r=send('v02-sos-001','guardian','sos.safeword',subject='v02-person')
    assert r.status_code==201
    incident_id=r.json()['incident_id']
    briefing=client.get(f'/v1/incidents/{incident_id}/brief',**credentials()).json()
    assert briefing['ai_generated'] is False
    assert briefing['human_review_required'] is True
    assert 'v02-sos-001' in briefing['source_event_ids']
    assert briefing['risk_level']=='EMERGENCY'
    timeline=client.get(f'/v1/incidents/{incident_id}/timeline',**credentials()).json()
    assert timeline['events'][0]['payload_sha256']

def test_tenant_product_isolation_on_brief():
    r=send('v02-arx-001','arxvigil','device.tamper',subject='v02-vehicle')
    ident=r.json()['incident_id']
    assert client.get(f'/v1/incidents/{ident}/brief',**credentials()).status_code==404
    assert client.get(f'/v1/incidents/{ident}/timeline',**credentials()).status_code==404
    assert client.get(f'/v1/incidents/{ident}/brief',**credentials('arxvigil')).status_code==200

def test_recommendations_not_duplicated_for_same_action():
    a=send('v02-arx-002','arxvigil','device.tamper',subject='v02-car-2')
    b=send('v02-arx-003','arxvigil','device.primary_signal_lost',subject='v02-car-2')
    assert a.status_code==201 and b.status_code==201
    detail=client.get(f"/v1/incidents/{b.json()['incident_id']}",**credentials('arxvigil')).json()
    assert len([r for r in detail['recommendations'] if r['action']=='Inspect device health and seek corroborating evidence.'])==1

def test_reject_out_of_domain_event_and_dashboard_served():
    r=send('v02-bad-001','guardian','device.power_cut',subject='v02-bad')
    assert r.status_code==422
    page=client.get('/dashboard')
    assert page.status_code==200 and 'ScourgeAI' in page.text
