"""Isolate every test module from real keys, models, and databases."""
import os,json,tempfile
from pathlib import Path
_tmp=tempfile.TemporaryDirectory()
os.environ['SECRET_KEY']='test-key-only'
os.environ['DATABASE_URL']='sqlite:///'+str(Path(_tmp.name)/'test.db')
os.environ['MODEL_PATH']=str(Path(_tmp.name)/'absent.txt')
os.environ['ADMIN_API_KEY']='test-admin'
os.environ['ANALYST_API_KEY']='test-analyst'
os.environ['VIEWER_API_KEY']='test-viewer'
os.environ['WATSONX_ENABLED']='false'
os.environ['NARRATIVE_PROVIDER']='template'
os.environ['MISTRAL_API_KEY']=''
