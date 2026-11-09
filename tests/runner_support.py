"""Authored Docker responses; the fake executable never contacts a daemon."""

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import pytest
from tests.static_pipeline import prepare

from vulnproof.correlation import correlate
from vulnproof.planning import create_plans
from vulnproof.runner.models import PreparationRecord, PreparedImage
from vulnproof.runner.profile import approval_bytes, recipe_hash, runner_approval
from vulnproof.static.analysis import fixture_manifest

IMAGE = "sha256:" + "a" * 64


def runner_inputs(root: Path, *, raw: bytes | None = None) -> dict[str, Any]:
    capture, analysis = prepare(root, raw=raw)
    correlation = root / "correlation.json"
    correlation.write_text(correlate(capture, analysis).model_dump_json())
    plan = root / "plan.json"
    document = create_plans(capture, analysis, correlation)
    plan.write_text(document.model_dump_json())
    fixture = fixture_manifest().fixtures[0]
    recipe = runner_approval().recipes[0]
    receipt = PreparationRecord(
        schema_version="1.0",
        profile="fixture-diagnostics-v1",
        approval_sha256=hashlib.sha256(approval_bytes()).hexdigest(),
        images=(
            PreparedImage(
                fixture_id=fixture.id,
                source_fingerprint=fixture.fingerprint,
                recipe_sha256=recipe_hash(recipe),
                image_id=IMAGE,
            ),
        ),
    )
    preparation = root / "prepared.json"
    preparation.write_text(receipt.model_dump_json())
    return dict(
        capture=capture,
        analysis=analysis,
        correlation=correlation,
        plan=plan,
        preparation=preparation,
        finding_id=document.findings[0].finding_id,
        socket=root / "fake.sock",
        output=root / "attempt",
        authorize_execution=True,
    )


def fake_docker(root: Path, monkeypatch: pytest.MonkeyPatch, **control: object) -> Path:
    directory = root / "fake-docker"
    directory.mkdir()
    (directory / "control.json").write_text(json.dumps(control))
    executable = directory / "docker"
    executable.write_text("#!" + sys.executable + "\n" + FAKE_DOCKER)
    executable.chmod(0o755)
    import shutil

    original = shutil.which
    monkeypatch.setattr(
        shutil, "which", lambda name: str(executable) if name == "docker" else original(name)
    )
    return directory


FAKE_DOCKER = """
import json, os, pathlib, sys, time
root = pathlib.Path(__file__).parent
control = json.loads((root / "control.json").read_text())
args = sys.argv[5:]
with (root / "calls.jsonl").open("a") as stream:
    stream.write(json.dumps({"prefix":sys.argv[1:5],"args":args,"env":dict(os.environ)})+"\\n")
state_path = root / "state.json"
state = json.loads(state_path.read_text()) if state_path.exists() else {"exists":False,"started":False}
def save(): state_path.write_text(json.dumps(state))
stage = args[0]
if stage == "image": stage = "image-inspect"
if stage == "inspect":
    stage = "owner" if "--format={{json .Config.Labels}}" in args else ("state" if state["started"] else "container-inspect")
if control.get("fail") == stage:
    print("Synthetic failure",file=sys.stderr); sys.exit(1)
if control.get("malformed") == stage:
    print("not json"); sys.exit(0)
if control.get("sleep") == stage: time.sleep(10)
if stage == "info":
    info={"os":control.get("os","linux"),"memory":True,"swap":True,"pids":True,"cpu":True,"security":[]}
    info.update(control.get("daemon_changes",{}))
    print(json.dumps(info))
elif stage == "image-inspect":
    config={"User":"10001:10001","WorkingDir":"/fixture","Cmd":["python","/fixture/runner_driver.py"],"Entrypoint":None,"Volumes":None,"OnBuild":None,"Healthcheck":None}
    if control.get("image_bad"): config["Entrypoint"]=["unapproved"]
    print(json.dumps([{"Id":args[-1],"Os":"linux","Config":config}]))
elif stage == "build":
    image="sha256:"+("a" if "vulnerable" in args[-1] else "b")*64
    pathlib.Path(args[args.index("--iidfile")+1]).write_text(image+"\\n")
    print("Synthetic build; no source executed")
elif stage == "create":
    state.update(exists=True,name=args[args.index("--name")+1],image=args[-2]); save()
    if control.get("partial_create_sleep"): time.sleep(10)
    if control.get("partial_create"): sys.exit(1)
    print("a"*64)
elif stage == "container-inspect":
    name=state["name"]
    config={"User":"10001:10001","WorkingDir":"/fixture","Cmd":["/fixture/runner_driver.py"],"Entrypoint":["python"],"Volumes":None,"Healthcheck":{"Test":["NONE"]},"Labels":{"vulnproof.attempt":name}}
    host={"ReadonlyRootfs":True,"NetworkMode":"none","PortBindings":{},"PublishAllPorts":False,"Privileged":False,"CapDrop":["ALL"],"CapAdd":None,"SecurityOpt":["no-new-privileges"],"NanoCpus":1000000000,"Memory":268435456,"MemorySwap":268435456,"PidsLimit":64,"Tmpfs":{"/tmp":"rw,noexec,nosuid,nodev,size=16777216,mode=1777"},"LogConfig":{"Type":"none"},"RestartPolicy":{"Name":"no"},"Binds":None,"Mounts":None,"PidMode":"","IpcMode":"private","UTSMode":"","CgroupnsMode":"private","UsernsMode":""}
    host.update(control.get("host_changes",{}))
    if control.get("foreign_owner"): config["Labels"]["vulnproof.attempt"]="unrelated"
    print(json.dumps([{"Image":state["image"],"Config":config,"HostConfig":host,"Mounts":[],"State":{"Running":False,"Status":"created"}}]))
elif stage == "start":
    state["started"]=True; save()
    if control.get("stderr_warning"): print("Synthetic warning",file=sys.stderr)
    if control.get("driver_sleep"): time.sleep(10)
    if control.get("flood"): print("x"*(2*1024*1024)); sys.exit(0)
    checks={key:True for key in ("non_root","no_new_privileges","zero_capabilities","read_only_root","root_write_denied","temporary_write","only_loopback","debug_disabled","legitimate_download")}
    if control.get("driver_bad"): checks["legitimate_download"]=False
    print(json.dumps({"schema_version":"1.0","profile":"fixture-diagnostics-v1","checks":checks}))
elif stage == "state":
    print(json.dumps([{"State":{"Running":False,"ExitCode":control.get("exit",0),"OOMKilled":control.get("oom",False)}}]))
elif stage == "owner":
    if control.get("cleanup_unavailable"): sys.exit(1)
    print(json.dumps({"vulnproof.attempt":"unrelated" if control.get("foreign_owner") else state.get("name")}))
elif stage == "rm":
    if control.get("cleanup_failed"): sys.exit(1)
    state["exists"]=False; save()
elif stage == "ps":
    if control.get("cleanup_unavailable"): sys.exit(1)
    print("a"*64 if state["exists"] else "")
else:
    print("Unexpected fake Docker operation",file=sys.stderr); sys.exit(2)
"""
