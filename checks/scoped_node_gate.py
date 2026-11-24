"""Generic scoped private Node gate. No application code is committed here."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from oidc_preflight import NoRedirect, request_assertion

BASE = "https://kronos-ci-broker.evinsta9.workers.dev"
HTTP = urllib.request.build_opener(NoRedirect)
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
SAFE_PATH = re.compile(r"(?:src/[A-Za-z0-9_.-]+\.js|tests/api/[A-Za-z0-9_.-]+\.test\.mjs)")
IMAGE = "node:22-bookworm-slim"

def digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def call(path, expected, auth=None, data=None, method="POST"):
    headers = {"Accept":"application/json","User-Agent":"Kronos-project-CI/1.0"}
    if auth:
        headers["Authorization"] = "Bearer " + auth
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(BASE+"/v1/scoped/"+path, headers=headers,
                                 data=data, method=method)
    try:
        with HTTP.open(req, timeout=25) as res:
            status, raw, marker = res.status, res.read(96001), res.headers.get("X-Kronos-CI-Contract")
    except urllib.error.HTTPError as res:
        status, raw, marker = res.code, res.read(96001), res.headers.get("X-Kronos-CI-Contract")
    print("Scoped gate "+path+": HTTP "+str(status)+" expected "+str(expected), flush=True)
    if status != expected or marker != "preflight-v1" or len(raw)>96000:
        raise RuntimeError("unexpected broker response")
    return json.loads(raw)

def materialize(bundle, job, workspace):
    if digest(bundle) != job["bundle_sha256"]:
        raise RuntimeError("bundle integrity")
    obj = json.loads(bundle)
    if set(obj) != {"scope","revision","source_tree","files"} or any(obj[k]!=job[k] for k in ("scope","revision","source_tree")):
        raise RuntimeError("bundle identity")
    files = obj["files"]
    if not isinstance(files,list) or not 2<=len(files)<=20:
        raise RuntimeError("file bounds")
    seen, tests = set(), []
    for f in files:
        if set(f)!={"path","sha","text"} or not isinstance(f["path"],str) or not SAFE_PATH.fullmatch(f["path"]) or f["path"] in seen or not HEX40.fullmatch(f["sha"]):
            raise RuntimeError("invalid file")
        raw=f["text"].encode("utf-8")
        if len(raw)>48000 or hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()!=f["sha"]:
            raise RuntimeError("blob integrity")
        seen.add(f["path"])
        target=workspace/f["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        target.chmod(0o444)
        if f["path"].startswith("tests/"):
            tests.append(f["path"])
    if not tests:
        raise RuntimeError("no tests")
    return sorted(tests)

def main():
    # Pull and resolve a public runtime before receiving any private bytes.
    subprocess.run(["docker","pull",IMAGE],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=120,check=True)
    image=subprocess.check_output(["docker","image","inspect","--format","{{.Id}}",IMAGE],text=True,timeout=15).strip()
    if not re.fullmatch(r"sha256:[a-f0-9]{64}",image):
        raise RuntimeError("invalid image")
    auth=request_assertion(os.environ)
    call("claim",401)
    call("payload",409,auth,method="GET")
    job=call("claim",200,auth)
    if job["scope"]!="node-test-v1" or not HEX40.fullmatch(job["revision"]) or not HEX40.fullmatch(job["source_tree"]) or not HEX64.fullmatch(job["bundle_sha256"]):
        raise RuntimeError("invalid approved job")
    call("claim",409,auth)
    obj=call("payload",200,auth,method="GET")
    if obj["bundle_sha256"]!=job["bundle_sha256"]:
        raise RuntimeError("invalid bundle digest")
    with tempfile.TemporaryDirectory(prefix="private-ci-",dir=os.environ["RUNNER_TEMP"]) as root:
        root=Path(root)
        workspace=root/"work"
        workspace.mkdir(mode=0o755)
        tests=materialize(obj["payload"],job,workspace)
        # No network, credentials, writable source, host mounts except the
        # scoped read-only workspace, artifact/cache service or Docker socket.
        command=["docker","run","--rm","--pull","never","--network","none","--read-only",
                 "--cap-drop","ALL","--security-opt","no-new-privileges","--user","65534:65534",
                 "--pids-limit","128","--memory","768m","--cpus","2",
                 "--tmpfs","/tmp:rw,noexec,nosuid,size=64m","--env","HOME=/tmp","--env","CI=true",
                 "--workdir","/work","--mount","type=bind,source="+str(workspace)+",target=/work,readonly",
                 image,"node","--experimental-default-type=module","--test","--test-reporter=tap",*tests]
        log=root/"private.log"
        with log.open("wb") as out:
            result=subprocess.run(command,stdout=out,stderr=subprocess.STDOUT,timeout=90,check=False)
        if log.stat().st_size>20000:
            raise RuntimeError("private log exceeds receipt limit")
        receipt={k:job[k] for k in ("revision","source_tree","bundle_sha256")}
        receipt.update(exit_code=result.returncode,image_id=image,log=log.read_text(errors="replace"))
        bad=dict(receipt,revision="0"*40)
        call("result",422,request_assertion(os.environ),json.dumps(bad,separators=(",",":")).encode())
        verdict=call("result",200,request_assertion(os.environ),json.dumps(receipt,separators=(",",":")).encode())
        call("payload",409,request_assertion(os.environ),method="GET")
        if verdict!={"accepted":True,"state":"passed"} or result.returncode!=0:
            raise RuntimeError("private gate failed")
    print("Scoped private Node gate passed; private receipt stored, source purged. No public application logs or artifacts.",flush=True)

if __name__=="__main__":
    try:
        main()
    except Exception:
        print("Scoped private gate failed; no source, test output or credentials emitted.",file=sys.stderr)
        raise SystemExit(1)
