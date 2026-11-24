"""Generic project-specific public dependency preparation, no application source."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
from oidc_preflight import NoRedirect, request_assertion

BASE="https://kronos-ci-broker.evinsta9.workers.dev"
HTTP=urllib.request.build_opener(NoRedirect)
IMAGE="node:22-bookworm-slim"
GIT=re.compile(r"[a-f0-9]{40}")
HASH=re.compile(r"[a-f0-9]{64}")
NAME=re.compile(r"(?:@[a-z0-9][a-z0-9_.-]*/)?[a-z0-9][a-z0-9_.-]*")
VERSION=re.compile(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?")
def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def call(path,status,auth=None,data=None,method="POST"):
    headers={"Accept":"application/json","User-Agent":"Kronos-project-CI/1.0"}
    if auth:
        headers["Authorization"]="Bearer "+auth
    if data is not None:
        headers["Content-Type"]="application/json"
    request=urllib.request.Request(BASE+"/v1/dependency/"+path,data=data,headers=headers,method=method)
    try:
        with HTTP.open(request,timeout=60) as response:
            code,raw,marker=response.status,response.read(24001),response.headers.get("X-Kronos-CI-Contract")
    except urllib.error.HTTPError as response:
        code,raw,marker=response.code,response.read(24001),response.headers.get("X-Kronos-CI-Contract")
    print("Dependency "+path+": HTTP "+str(code)+" expected "+str(status),flush=True)
    if code!=status or len(raw)>24000 or marker!="preflight-v1":
        raise RuntimeError("Unexpected broker response")
    return json.loads(raw)

def validate(payload,job):
    if digest(payload.encode())!=job["bundle_sha256"]:
        raise ValueError("Input digest")
    x=json.loads(payload)
    if set(x)!={"scope","revision","source_tree","package","wasm"} or any(x[k]!=job[k] for k in ("scope","revision","source_tree")) or x["scope"]!="dependency-prep-v1":
        raise ValueError("Input identity")
    p=x["package"]
    if set(p)!={"name","version","private","type","dependencies","devDependencies"} or not NAME.fullmatch(p["name"]) or not VERSION.fullmatch(p["version"]) or p["private"] is not True or p["type"]!="module":
        raise ValueError("Package metadata")
    for key in ("dependencies","devDependencies"):
        if not isinstance(p[key],dict) or len(p[key])>80 or any(not NAME.fullmatch(n) or not VERSION.fullmatch(v) for n,v in p[key].items()):
            raise ValueError("Dependency must be exact public registry version")
    w=x["wasm"]
    if set(w)!={"name","version","path","bytes","sha256"} or w["name"]!="onnxruntime-web" or not VERSION.fullmatch(w["version"]) or w["path"]!="package/dist/ort-wasm-simd-threaded.wasm" or type(w["bytes"]) is not int or not 1<=w["bytes"]<=30000000 or not HASH.fullmatch(w["sha256"]):
        raise ValueError("WASM provenance")
    return x

def run(command,log,timeout):
    try:
        with log.open("ab") as out:
            return subprocess.run(command,stdout=out,stderr=subprocess.STDOUT,timeout=timeout,check=False).returncode
    except subprocess.TimeoutExpired:
        return 124

def measure_wasm(path,w):
    if not path.is_file() or path.stat().st_size>250000000:
        return {"bytes":0,"sha256":"0"*64}
    try:
        with tarfile.open(path,"r:gz") as archive:
            members=[m for m in archive.getmembers() if m.name==w["path"]]
            if len(members)!=1 or not members[0].isfile() or members[0].size>30000000:
                return {"bytes":0,"sha256":"0"*64}
            with archive.extractfile(members[0]) as f:
                raw=f.read(30000001)
            return {"bytes":len(raw),"sha256":digest(raw)}
    except (OSError,tarfile.TarError):
        return {"bytes":0,"sha256":"0"*64}

def main():
    subprocess.run(["docker","pull",IMAGE],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=120,check=True)
    image=subprocess.check_output(["docker","image","inspect","--format","{{.Id}}",IMAGE],text=True,timeout=15).strip()
    if not re.fullmatch(r"sha256:[a-f0-9]{64}",image):
        raise ValueError("Runtime identity")
    auth=request_assertion(os.environ)
    call("claim",401)
    call("input",409,auth,method="GET")
    job=call("claim",200,auth)
    if job["scope"]!="dependency-prep-v1" or not GIT.fullmatch(job["revision"]) or not GIT.fullmatch(job["source_tree"]) or not HASH.fullmatch(job["bundle_sha256"]):
        raise ValueError("Job identity")
    call("claim",409,auth)
    x=validate(call("input",200,auth,method="GET")["payload"],job)
    with tempfile.TemporaryDirectory(prefix="private-deps-",dir=os.environ["RUNNER_TEMP"]) as directory:
        root=Path(directory)
        work=root/"work"
        work.mkdir(mode=0o777)
        work.chmod(0o777)
        (work/"package.json").write_text(json.dumps(x["package"],separators=(",",":")),encoding="utf-8")
        (work/"package.json").chmod(0o444)
        log=root/"private.log"
        # No application code, production secrets, Docker socket or Git checkout.
        # Only public registry dependency resolution; scripts are disabled.
        docker=["docker","run","--rm","--pull","never","--read-only",
                "--cap-drop","ALL","--security-opt","no-new-privileges",
                "--user","65534:65534","--pids-limit","256","--memory","3g","--cpus","2",
                "--tmpfs","/tmp:rw,nosuid,size=1g","--env","HOME=/tmp",
                "--env","NPM_CONFIG_CACHE=/tmp/npm-cache","--env","NPM_CONFIG_REGISTRY=https://registry.npmjs.org/",
                "--env","NPM_CONFIG_IGNORE_SCRIPTS=true","--env","NPM_CONFIG_UPDATE_NOTIFIER=false",
                "--workdir","/work","--mount","type=bind,source="+str(work)+",target=/work",
                image,"npm"]
        common=["--ignore-scripts","--no-audit","--no-fund","--registry=https://registry.npmjs.org/"]
        rc=run(docker+["install","--package-lock-only",*common],log,180)
        lock=work/"package-lock.json"
        locktext=lock.read_text(encoding="utf-8") if lock.is_file() and lock.stat().st_size<=460000 else ""
        if rc==0 and locktext:
            rc=run(docker+["ci",*common],log,240)
            if lock.read_text(encoding="utf-8")!=locktext:
                rc=125
        w=x["wasm"]
        pack=run(docker+["pack",w["name"]+"@"+w["version"],"--pack-destination=/work",*common],log,240)
        measured=measure_wasm(work/(w["name"]+"-"+w["version"]+".tgz"),w) if pack==0 else {"bytes":0,"sha256":"0"*64}
        tail=""
        if log.exists():
            with log.open("rb") as f:
                f.seek(max(0,log.stat().st_size-12000))
                tail=f.read().decode("utf-8",errors="replace")
        receipt={k:job[k] for k in ("revision","source_tree","bundle_sha256")}
        receipt.update(image_id=image,install_exit=rc if 0<=rc<=255 else 125,pack_exit=pack if 0<=pack<=255 else 125,lockfile=locktext,wasm=measured,log=tail)
        payload=json.dumps(receipt,separators=(",",":"),ensure_ascii=False).encode()
        if len(payload)>524288:
            raise ValueError("Receipt bounds")
        verdict=call("result",200,request_assertion(os.environ),payload)
        call("input",409,request_assertion(os.environ),method="GET")
        call("result",409,request_assertion(os.environ),payload)
        print("Private dependency receipt: lock="+str(verdict["installVerified"])+" wasm="+str(verdict["wasmVerified"]),flush=True)
        if verdict.get("state")!="passed":
            raise RuntimeError("Dependency or WASM verification failed")
    print("Dependency preparation passed; private receipt stored.",flush=True)

if __name__=="__main__":
    try:
        main()
    except Exception:
        print("Dependency preparation failed; no private package details or logs emitted.",file=sys.stderr)
        raise SystemExit(1)
