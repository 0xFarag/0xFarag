#!/usr/bin/env python3
"""Packaging-only correction: preserve all previously accepted proof bytes."""
from pathlib import Path
import hashlib,io,json,os,shutil,subprocess,sys,tarfile,time,zipfile

BASE=Path(__file__).resolve().parent
OUT=BASE/'correction'
REPO=Path('/workspace/scratch/7b68a7003223/authzledger')
PRIOR=Path('/workspace/scratch/5ee9d8409b8d/phase2-final/run-canonical')
CACHE=PRIOR.parent/'dependency-wheels'
COMMIT='43c5a5b036790310f8dad0991cd18aef7c8a467b'
EXPECTED='f01fbe3340bc5c1a29334a923c147206f3b48bf4d77a4244fea38978dc00c67f'
OUT.mkdir();(OUT/'logs').mkdir()
env={k:v for k,v in os.environ.items() if k not in ('PYTHONPATH','PYTHONHOME','VIRTUAL_ENV','SOURCE_DATE_EPOCH')}
env.update(PIP_NO_INDEX='1',PIP_FIND_LINKS=str(CACHE),PIP_DISABLE_PIP_VERSION_CHECK='1',PYTHONDONTWRITEBYTECODE='1',PYTHONHASHSEED='0',TZ='UTC',LC_ALL='C.UTF-8')
commands=[]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def dump(p,value):p.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
def require(value,message):
    if not value:raise RuntimeError(message)
def call(name,args,*,extra_env=None,cwd=OUT):
    child=env.copy();child.update(extra_env or {});start=time.time();print('START '+name,flush=True)
    with (OUT/'logs'/f'{name}.log').open('w') as log:
        p=subprocess.run([str(a) for a in args],env=child,cwd=cwd,stdout=log,stderr=subprocess.STDOUT)
    commands.append({'name':name,'argv':[str(a) for a in args],'cwd':str(cwd),'exit_code':p.returncode,'seconds':round(time.time()-start,3),'source_date_epoch':child.get('SOURCE_DATE_EPOCH')})
    dump(OUT/'commands.json',commands);require(p.returncode==0,name+' failed');print('PASS '+name,flush=True)
def inventory(p):return {x.relative_to(p).as_posix():sha(x) for x in sorted(p.rglob('*')) if x.is_file()}
def zinventory(p):
    with zipfile.ZipFile(p) as z:return {i.filename:hashlib.sha256(z.read(i.filename)).hexdigest() for i in z.infolist()}

proofs=[('assessment-demos',PRIOR/'assessment-demos/proof',PRIOR/'trust-anchors/assessment-demos-public.pem'),
        ('selective100',PRIOR/'selective100/proof',PRIOR/'trust-anchors/selective100-public.pem'),
        ('report-50',PRIOR/'report-qa/proof-a',PRIOR/'trust-anchors/report-50-public.pem'),
        ('workflow-safe',PRIOR/'report-qa/workflow-assurance-safe/proof',PRIOR/'trust-anchors/workflow-safe-public.pem'),
        ('workflow-violation',PRIOR/'report-qa/workflow-assurance-violation/proof',PRIOR/'trust-anchors/workflow-violation-public.pem')]
for name in ('assessment-demos','selective100'):
    root=REPO/'evidence/1.1.0-release-review'/name
    proofs.append(('historical-'+name,root/'proof',root/'trusted-public.pem'))
before={name:{'proof':inventory(bundle),'key_sha256':sha(key)} for name,bundle,key in proofs}
dump(OUT/'retained-proofs-before.json',before)
archive=subprocess.run(['git','archive',COMMIT],cwd=REPO,check=True,stdout=subprocess.PIPE).stdout
dump(OUT/'source.json',{'commit':COMMIT,'git_archive_sha256':hashlib.sha256(archive).hexdigest(),'build_env':{'SOURCE_DATE_EPOCH':'1767225600','setuptools':'84.0.0','wheel':'0.48.0'},'driver_sha256':sha(Path(__file__))})
buildpython=PRIOR/'build-venv/bin/python'
call('00-backend-versions',[buildpython,'-c','import importlib.metadata as m,json; print(json.dumps({x:m.version(x) for x in ("setuptools","wheel")})); assert m.version("setuptools")=="84.0.0"; assert m.version("wheel")=="0.48.0"'])
wheels=[]
for n in (1,2):
    source=OUT/f'git-source-{n}';source.mkdir()
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:tar.extractall(source,filter='data')
    require(sha(source/'NOTICE.txt')==sha(REPO/'NOTICE.txt'),'NOTICE source mismatch')
    call(f'01-build-{n}',[buildpython,'-m','pip','wheel','--no-deps','--no-build-isolation','--wheel-dir',OUT/f'wheel-{n}',source],extra_env={'SOURCE_DATE_EPOCH':'1767225600'})
    wheel=OUT/f'wheel-{n}/authzledger-1.1.0-py3-none-any.whl'
    require(sha(wheel)==EXPECTED,'clean Git wheel differs from CI result');wheels.append(wheel)
old=PRIOR/'wheel-1/authzledger-1.1.0-py3-none-any.whl';a,b=zinventory(old),zinventory(wheels[0])
added=set(b)-set(a);removed=set(a)-set(b);changed={n for n in set(a)&set(b) if a[n]!=b[n]}
require(added=={'authzledger-1.1.0.dist-info/licenses/NOTICE.txt'} and not removed,'unexpected added/removed wheel payload')
require(changed=={'authzledger-1.1.0.dist-info/METADATA','authzledger-1.1.0.dist-info/RECORD'},'unexpected changed wheel payload')
with zipfile.ZipFile(wheels[0]) as z:
    require(z.read('authzledger-1.1.0.dist-info/licenses/NOTICE.txt')==(REPO/'NOTICE.txt').read_bytes(),'wheel NOTICE bytes mismatch')
    metadata=z.read('authzledger-1.1.0.dist-info/METADATA').decode()
    require('License-File: NOTICE.txt' in metadata,'NOTICE declaration absent')
    dump(OUT/'wheel-inventory.json',[{'path':i.filename,'size':i.file_size,'timestamp':i.date_time,'mode':i.external_attr,'sha256':b[i.filename]} for i in z.infolist()])
dump(OUT/'wheel-difference.json',{'superseded_wheel_sha256':sha(old),'correct_wheel_sha256':EXPECTED,'added':sorted(added),'removed':sorted(removed),'changed':sorted(changed),'all_authzledger_payloads_byte_identical':True,'cause':'External acceptance source copy listed NOTICE rather than existing NOTICE.txt; clean Git CI correctly includes license notice.'})
dump(OUT/'deterministic-wheel.json',{'passed':True,'sha256':EXPECTED,'bytes':wheels[0].stat().st_size,'source_commit':COMMIT,'source_date_epoch':1767225600,'wheels':[str(x) for x in wheels],'build_backend':{'setuptools':'84.0.0','wheel':'0.48.0'},'notice_included':True})
venv=OUT/'installed-venv';call('02-clean-venv',[sys.executable,'-m','venv',venv]);python=venv/'bin/python'
call('03-install-reports',[python,'-m','pip','install',str(wheels[0])+'[reports]','pypdf==6.10.0','pillow==12.3.0'])
call('04-pip-check',[python,'-m','pip','check']);call('05-pip-freeze',[python,'-m','pip','freeze','--all'])
provenance_code='''import authzledger,importlib.metadata as m,hashlib,json,sys
from pathlib import Path
p=Path(authzledger.__file__).resolve().parent
fonts={n:hashlib.sha256((p/'fonts'/n).read_bytes()).hexdigest() for n in ('DejaVuSans.ttf','DejaVuSans-Bold.ttf')}
if 'site-packages' not in p.parts or authzledger.__version__!='1.1.0' or m.version('reportlab')!='4.4.9':raise RuntimeError('wrong installed runtime')
expected={'DejaVuSans.ttf':'ae7b7855e115a5966d8b1b3f80f254ccc117ec86f9965e202ee2940453837280','DejaVuSans-Bold.ttf':'5c1247acef7f2b8522a31742c76d6adcb5569bacc0be7ceaa4dc39dd252ce895'}
if fonts!=expected:raise RuntimeError('font mismatch')
value={'passed':True,'module_path':str(p),'python':sys.version,'prefix':sys.prefix,'versions':{n:m.version(n) for n in ('authzledger','reportlab','pillow','pypdf')},'font_sha256':fonts,'wheel_sha256':sys.argv[2]}
Path(sys.argv[1]).write_text(json.dumps(value,indent=2)+'\\n')
print(json.dumps(value))
'''
call('06-installed-provenance',[python,'-I','-c',provenance_code,OUT/'installed-provenance.json',EXPECTED])
harness=OUT/'harness';shutil.copytree(PRIOR/'harness',harness)
verify=harness/'tools/verify_bundle.py';qa=harness/'proof_qa.py'
for name,bundle,key in proofs:
    call('07-verify-'+name,[python,'-I',qa,'verify','--bundle',bundle,'--public-key',key,'--standalone',verify,'--out',OUT/(name+'-verification.json')])
call('08-fresh-demos',[python,'-I',harness/'tools/check_assessment.py','--out',OUT/'fresh-demos'])
call('09-fresh-workflows',[python,'-I',harness/'tools/check_workflows110.py','--out',OUT/'fresh-workflows'])
renders={}
for label,epoch in (('unset',None),('release','1767225600'),('zero','0'),('invalid','invalid')):
    options={} if epoch is None else {'SOURCE_DATE_EPOCH':epoch}
    destination=OUT/('render-'+label)
    call('10-render-'+label,[python,'-I',qa,'render','--snapshot',PRIOR/'report-qa/snapshot-50.json','--out',destination],extra_env=options)
    renders[label]=inventory(destination)
    require(renders[label]==inventory(PRIOR/'report-qa/render-a'),'50-finding reports changed with corrected wheel')
    call('11-verify-report-'+label,[python,'-I',qa,'verify','--bundle',PRIOR/'report-qa/proof-a','--public-key',PRIOR/'trust-anchors/report-50-public.pem','--standalone',verify,'--out',OUT/('report-'+label+'-verification.json')],extra_env=options)
after={name:{'proof':inventory(bundle),'key_sha256':sha(key)} for name,bundle,key in proofs}
require(before==after,'previously accepted proof/key bytes changed')
dump(OUT/'retained-proofs-unchanged.json',{'passed':True,'proofs':after})
dump(OUT/'report-byte-equality.json',{'passed':True,'snapshot':str(PRIOR/'report-qa/snapshot-50.json'),'snapshot_sha256':sha(PRIOR/'report-qa/snapshot-50.json'),'findings':50,'all_three_formats_match_original_canonical_run':True,'epoch_environments':renders,'visual_review_reused_reason':'Every PDF byte equals previously visually reviewed canonical PDF.'})
dump(OUT/'acceptance.json',{'passed':True,'scope':'Packaging NOTICE.txt inclusion correction only','source_commit':COMMIT,'wheel_sha256':EXPECTED,'wheel_bytes':wheels[0].stat().st_size,'two_clean_git_builds_identical':True,'all_product_payload_bytes_unchanged':True,'clean_install_reports_and_fonts_verified':True,'retained_proof_bundles_both_verifiers':len(proofs),'all_retained_proof_and_key_bytes_unchanged':True,'new_demos_and_workflows_passed':True,'original_50finding_json_html_pdf_byte_equal_in_four_epoch_environments':True,'canonical_visual_review_still_applicable':True,'supersedes_only_original_wheel_build_and_install_receipts':True,'commands_exit_zero':len(commands),'notice_missing_in_superseded_harness_fixed':True})
print('CORRECTED WHEEL ACCEPTANCE PASSED',flush=True)
