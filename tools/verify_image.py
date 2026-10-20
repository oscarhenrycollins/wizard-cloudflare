"""Verify the exact packaged GHCR index and both runnable manifests without registry credentials."""
import hashlib,json,urllib.request
from pathlib import Path
import yaml
image=yaml.safe_load((Path(__file__).resolve().parents[1]/'runtipi/docker-compose.yml').read_text())['services']['wizard-cloudflare']['image']
repo,ref=image.removeprefix('ghcr.io/').split('@'); repo=repo.rsplit(':',1)[0]
token=json.load(urllib.request.urlopen('https://ghcr.io/token?service=ghcr.io&scope=repository:'+repo+':pull'))['token']
headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json','User-Agent':'wizard-cloudflare-release/1'}
def get(kind,digest):
 with urllib.request.urlopen(urllib.request.Request('https://ghcr.io/v2/'+repo+'/'+kind+'/'+digest,headers=headers),timeout=30) as r:raw=r.read()
 assert 'sha256:'+hashlib.sha256(raw).hexdigest()==digest,'digest mismatch'
 return json.loads(raw)
index=get('manifests',ref); found={}
for item in index['manifests']:
 arch=item.get('platform',{}).get('architecture')
 if arch not in ('amd64','arm64'):continue
 manifest=get('manifests',item['digest']);config=get('blobs',manifest['config']['digest']);assert config['architecture']==arch;labels=config['config']['Labels'];assert labels['org.opencontainers.image.source']=='https://github.com/'+repo
 found[arch]={'digest':item['digest'],'source_commit':labels['org.opencontainers.image.revision']}
assert set(found)=={'amd64','arm64'}
assert len({x['source_commit'] for x in found.values()})==1
print(json.dumps({'anonymous_pull':True,'image':image,'platforms':found},indent=2))
