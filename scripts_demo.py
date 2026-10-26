"""With API running and demo credentials set, send a SIMULATED SOS; no real dispatch."""
import json, time, hashlib, hmac, urllib.request
secret='development-change-me'
event_id=f'demo-{int(time.time())}'
body=json.dumps({'schema_version':'1.0','event_id':event_id,'event_type':'sos.manual','source_product':'guardian','tenant_id':'demo','subject_type':'person','subject_id':'demo-user','occurred_at':'2026-10-22T12:00:00Z','source':{},'observation':{},'integrity':{}},separators=(',',':')).encode()
ts=str(int(time.time()))
sig=hmac.new(secret.encode(),ts.encode()+b'.'+body,hashlib.sha256).hexdigest()
request=urllib.request.Request('http://127.0.0.1:8000/v1/events',data=body,headers={'Content-Type':'application/json','X-Event-Timestamp':ts,'X-Event-Signature':sig,'X-Event-Nonce':event_id})
with urllib.request.urlopen(request) as res: print(res.read().decode())
