"""One verification entrypoint; stops on failure and records command outcomes."""
import argparse
import json
import subprocess
import sys
from pathlib import Path
from datetime import datetime, timezone

parser=argparse.ArgumentParser()
parser.add_argument('--skip-install',action='store_true')
args=parser.parse_args()
root=Path(__file__).resolve().parents[1]
artifact=root/'artifacts'/'verification'
artifact.mkdir(parents=True,exist_ok=True)
commands=[]
if not args.skip_install:
    commands += [(root,[sys.executable,'-m','pip','install','-r','backend/requirements-dev.lock']),
        (root/'web',['npm','ci']),(root/'extension',['npm','ci'])]
commands += [(root,[sys.executable,'-m','ruff','check','backend/app','backend/tests']),
    (root,[sys.executable,'-m','ruff','format','--check','backend/app','backend/tests']),
    (root,[sys.executable,'-m','pytest','backend/tests','-q','--junitxml='+str(artifact/'backend.xml')]),
    (root/'web',['npm','test']),(root/'web',['npm','run','typecheck']),(root/'web',['npm','run','build']),
    (root/'extension',['npm','run','package'])]
results=[]
for cwd,cmd in commands:
    if sys.platform=='win32' and cmd[0]=='npm':
        cmd[0]='npm.cmd'
    result=subprocess.run(cmd,cwd=cwd,text=True,capture_output=True)
    name=str(len(results)+1).zfill(2)
    (artifact/(name+'.log')).write_text(result.stdout+'\n'+result.stderr,encoding='utf-8')
    results.append({'command':cmd,'cwd':str(cwd.relative_to(root)), 'exit_code':result.returncode})
    (artifact/'results.json').write_text(json.dumps({'recorded_at':datetime.now(timezone.utc).isoformat(),'results':results},indent=2))
    print('PASS' if result.returncode==0 else 'FAIL',' '.join(cmd))
    if result.returncode:
        print(result.stdout[-3000:]+result.stderr[-3000:])
        raise SystemExit(result.returncode)
