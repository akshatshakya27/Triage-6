import json
import httpx
from backend.services import narrative
from backend.config import settings

def test_mistral_request_and_redaction(monkeypatch):
    monkeypatch.setattr(settings,'NARRATIVE_PROVIDER','mistral')
    monkeypatch.setattr(settings,'MISTRAL_API_KEY','test-key-not-real')
    def handle(req):
        body=json.loads(req.content)
        assert req.url.host=='api.mistral.ai'
        assert req.headers['Authorization']=='Bearer test-key-not-real'
        assert '192.0.2.99' not in req.content.decode()
        assert 'payload-secret' not in req.content.decode()
        assert body['messages'][0]['role']=='system'
        return httpx.Response(200,json={'choices':[{'message':{'content':'Review the supplied attribution; classification remains uncertain.'}}]})
    client=httpx.Client(transport=httpx.MockTransport(handle))
    monkeypatch.setattr(narrative.httpx,'Client',lambda **kwargs:client)
    text,note,provider=narrative.explain({'prediction':'DoS','model_probability':.92,'shap':[],'raw':{'src_ip':'192.0.2.99','payload':'payload-secret'}})
    assert provider=='mistral' and text and 'verification' in note

def test_mistral_missing_key_is_local(monkeypatch):
    monkeypatch.setattr(settings,'NARRATIVE_PROVIDER','mistral')
    monkeypatch.setattr(settings,'MISTRAL_API_KEY','')
    text,note,provider=narrative.explain({})
    assert text is None and provider=='template' and 'incomplete' in note

def test_mistral_failure_falls_back(monkeypatch):
    monkeypatch.setattr(settings,'NARRATIVE_PROVIDER','mistral')
    monkeypatch.setattr(settings,'MISTRAL_API_KEY','test-key-not-real')
    client=httpx.Client(transport=httpx.MockTransport(lambda req:httpx.Response(429,json={'error':'rate limited'})))
    monkeypatch.setattr(narrative.httpx,'Client',lambda **kwargs:client)
    text,note,provider=narrative.explain({})
    assert text is None and provider=='template' and 'unavailable' in note

def test_auto_preserves_ibm_setting(monkeypatch):
    monkeypatch.setattr(settings,'NARRATIVE_PROVIDER','auto')
    monkeypatch.setattr(settings,'WATSONX_ENABLED',False)
    monkeypatch.setattr(settings,'MISTRAL_API_KEY','test-key-not-real')
    assert narrative.provider_status()['provider']=='template'
