"""Adapter contract test using a temporary synthetic model, never a detection benchmark."""
import json
import pytest

def test_real_lightgbm_shap_adapter(tmp_path,monkeypatch):
 np=pytest.importorskip('numpy')
 lgb=pytest.importorskip('lightgbm')
 pytest.importorskip('shap')
 from backend.services import inference
 from backend.config import settings
 rng=np.random.default_rng(42)
 labels=np.repeat([0,1,2],80)
 x=np.array([[5,0,float(5+label*100+rng.integers(0,5)),5,1000,300] for label in labels])
 m=lgb.LGBMClassifier(objective='multiclass',num_class=3,n_estimators=30,learning_rate=.2,num_leaves=7,verbosity=-1,n_jobs=1)
 m.fit(x,labels);path=tmp_path/'model.txt';m.booster_.save_model(str(path))
 manifest=tmp_path/'manifest.json';manifest.write_text(json.dumps({'schema':'eve-flow-v1','features':inference.FEATURES,'protocol_map':{'tcp':0},'classes':['Normal','Generic','Reconnaissance'],'eve_compatible':True,'validation':'SYNTHETIC ADAPTER TEST ONLY'}))
 monkeypatch.setattr(settings,'MODEL_PATH',str(path));monkeypatch.setattr(settings,'MODEL_MANIFEST',str(manifest))
 monkeypatch.setattr(inference,'_model',None);monkeypatch.setattr(inference,'_manifest',None)
 e={'proto':'TCP','event_type':'flow','flow':{'start':'2026-09-12T10:00:00Z','end':'2026-09-12T10:00:05Z','pkts_toserver':207,'pkts_toclient':5,'bytes_toserver':1000,'bytes_toclient':300}}
 r=inference.infer(e)
 assert r['engine']=='lightgbm' and r['prediction']=='Reconnaissance'
 assert r['model_probability']>.85 and len(r['shap'])==6,r
 assert 'raw model-output' in r['shap_status']
 del e['flow']['pkts_toclient']
 missing=inference.infer(e)
 assert missing['model_probability'] is None and 'dpkts' in missing['model_note']
 assert missing['priority'] is None
