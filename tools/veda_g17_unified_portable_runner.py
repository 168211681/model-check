#!/usr/bin/env python3
"""VEDA G1.7 disposable GGUF/Supervisor/Seccomp/kernel integration QA.

Run only on a disposable GitHub-hosted Standard Linux runner with no secret
mounts. A pinned, read-only, nonroot, networkless OCI container is created for
each negative control and bounded native inference. This is not a rootless
cgroup delegation or Bubblewrap proof. Never approve Trust G0 based on this QA.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

IMAGE = ("ghcr.io/ggml-org/llama.cpp:light@sha256:"
         "d1dac5128905d21f2ef7306a3bcbd509ef50dbe5b5b91c5f2812dd0d6f859b2c")
EXPECTED_BIN = "9e679c20d0eb664323549e915a1d05a33e63ef9c48fd226093b8bc21a1677de2"
EXPECTED_MODEL = "e3131339bf4e8065265593d4fd8f7bb7ff2d3abff1edb5618aa1197b89cad9f5"
EXPECTED_STDOUT = "d7a3611195b24f1246701c68beaa1a3a641b4b759607a45bb837b36294461c53"
EXPECTED_SUPERVISOR = "b48f1fe8c5567bb4b4e23feb618c54f5aa5a3d0d85211d0324c2b5fbe9fac65e"
EXPECTED_SECCOMP = "efaa1283764902999ce91d694466548011260bbebcfc040af324226811fb0c0a"

PROMPT = "Capital city quiz:\nGermany: Berlin\nItaly: Rome\nSpain: Madrid\nFrance:"

PREFLIGHT = """
import hashlib, os
from pathlib import Path
cg = Path("/sys/fs/cgroup")
assert os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 65534
assert cg.joinpath("memory.max").read_text().strip() == str(768*1024*1024)
assert cg.joinpath("pids.max").read_text().strip() == "48"
st = dict((a,b.strip()) for a,b in
          (line.split(":",1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line))
assert st.get("CapEff") == "0000000000000000"
assert st.get("NoNewPrivs") == "1"
assert not os.access("/var/run/docker.sock",os.R_OK) and not os.access("/var/run/docker.sock",os.W_OK)
mounts = {}
for line in Path("/proc/self/mountinfo").read_text().splitlines():
    row=line.split(" - ",1)[0].split()
    if len(row)>5:
        mounts[row[4]]=set(row[5].split(","))
assert "ro" in mounts.get("/",set()), "root must be readonly"
assert {"rw","noexec","nosuid","nodev"}.issubset(mounts.get("/tmp",set())), "scratch mount options wrong"
assert hashlib.sha256(Path("/app/llama-completion").read_bytes()).hexdigest() == "9e679c20d0eb664323549e915a1d05a33e63ef9c48fd226093b8bc21a1677de2"
assert hashlib.sha256(Path("/model/model.gguf").read_bytes()).hexdigest() == "e3131339bf4e8065265593d4fd8f7bb7ff2d3abff1edb5618aa1197b89cad9f5"
print("G1.7 INTEGRATED_CONTAINER_HARDENING=PASS",flush=True)
"""


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            h.update(block)
    return h.hexdigest()


def require_hash(path: Path, expected: str) -> None:
    if digest(path) != expected:
        raise AssertionError(f"BLOCKED: hash mismatch for {path.name}")


def read_decision(out: str) -> dict:
    prefix = "VEDA_SUPERVISOR_RESULT="
    matches = [json.loads(line[len(prefix):])
               for line in out.splitlines() if line.startswith(prefix)]
    if len(matches) != 1:
        raise AssertionError("BLOCKED: unique Supervisor result missing")
    row = matches[0]
    if row.get("decision") != "exit_0" or row.get("child_exit") != 0 or row.get("alive_group_after") != 0:
        raise AssertionError("BLOCKED: Supervisor failed: "+json.dumps(row,sort_keys=True))
    return row


def run(argv: list[str], label: str) -> str:
    proc = subprocess.run(argv, capture_output=True, text=True,
                          timeout=95, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"BLOCKED: {label}: exit={proc.returncode}: "
                           f"stdout={proc.stdout[-1250:]!r}, stderr={proc.stderr[-900:]!r}")
    return proc.stdout


def cpu_info() -> tuple[str, str]:
    meta = {}
    for line in Path("/proc/cpuinfo").read_text().splitlines():
        if ":" in line:
            k,v = line.split(":",1)
            if k in ("vendor_id","model name") and k not in meta:
                meta[k] = v.strip()
    return meta.get("vendor_id","UNKNOWN"),meta.get("model name","UNKNOWN")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--portable", type=Path, required=True)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--job", required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()

    assert os.environ.get("GITHUB_REPOSITORY") == "168211681/model-check", "wrong repository"
    assert os.environ.get("GITHUB_REF") == "refs/heads/main", "wrong branch"
    assert os.environ.get("RUNNER_OS") == "Linux", "not a Linux runner"
    portable,model=args.portable.resolve(strict=True),args.model.resolve(strict=True)
    assert portable.is_dir() and model.is_file()
    for filename, expected in (
        ("llama-completion", EXPECTED_BIN),
        ("veda_g15_process_supervisor.py", EXPECTED_SUPERVISOR),
        ("veda_g16_seccomp_exec.py", EXPECTED_SECCOMP),
    ):
        require_hash(portable / filename,expected)
    require_hash(model,EXPECTED_MODEL)

    root=Path("/sys/fs/cgroup")
    # The host runner is not the container and must never write into cgroups.
    assert root.is_dir()
    options=[
        "docker", "run", "--rm", "--network", "none",
        "--memory", "768m", "--memory-swap", "768m", "--pids-limit", "48",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--user", "65534:65534", "--read-only",
        "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=256m,mode=1777",
        "--mount", f"type=bind,source={portable},target=/portable,readonly",
        "--mount", f"type=bind,source={portable / 'llama-completion'},target=/app/llama-completion,readonly",
        "--mount", f"type=bind,source={model.parent},target=/model,readonly",
        "--env", "LD_LIBRARY_PATH=/portable:/app",
        "--entrypoint", "/usr/bin/python3", IMAGE,
    ]
    preflight=run(options+["-S","-c",PREFLIGHT],"kernel/readonly/hash preflight")
    if "G1.7 INTEGRATED_CONTAINER_HARDENING=PASS" not in preflight:
        raise AssertionError("BLOCKED: container preflight positive evidence missing")
    print(preflight.strip(),flush=True)

    base=[
        "-S", "/portable/veda_g15_process_supervisor.py",
        "--max-rss-mb", "200", "--max-as-mb", "3072",
        "--max-processes", "4", "--timeout-s", "12", "--",
        "/usr/bin/python3", "-S", "/portable/veda_g16_seccomp_exec.py",
        "--post-exec-selftest",
    ]
    negative=read_decision(run(options+base,"negative control"))
    if ("G1.6 SECCOMP_PERSISTED_ACROSS_EXEC=PASS" not in negative.get("stdout_excerpt","")
        or "G1.6 SECCOMP_POLICY_LOADED=27_DENIED_SYSCALLS" not in negative.get("stderr_excerpt","")):
        raise AssertionError("BLOCKED: seccomp filter/exec negative control missing")
    print("G1.7 INTEGRATED_SECCOMP_NEGATIVE_CONTROL=PASS",flush=True)

    values={}
    observations={}
    for threads in (1,2):
        values[threads]=[]
        observations[threads]=[]
        for attempt in (1,2):
            cmd=[
                "-S", "/portable/veda_g15_process_supervisor.py",
                "--max-rss-mb","600","--max-as-mb","3072",
                "--max-processes","8","--timeout-s","55","--",
                "/usr/bin/python3","-S","/portable/veda_g16_seccomp_exec.py",
                "--","/app/llama-completion",
                "--model","/model/"+model.name,"--prompt",PROMPT,
                "--n-predict","24","--ctx-size","256",
                "--threads",str(threads),"--threads-batch",str(threads),
                "--temp","0","--seed","42","--no-display-prompt","--no-conversation",
            ]
            row=read_decision(run(options+cmd,f"model {threads=} {attempt=}"))
            if ("Paris" not in row.get("stdout_excerpt","") or
                "G1.6 SECCOMP_POLICY_LOADED=27_DENIED_SYSCALLS" not in row.get("stderr_excerpt","")):
                raise AssertionError("BLOCKED: model semantic or Seccomp evidence absent")
            if (row.get("max_observed_processes",999)>8 or
                row.get("max_observed_rss_bytes",999999999)>=600*1024*1024):
                raise AssertionError("BLOCKED: application resource observation failed")
            if row["stdout_sha256"] != EXPECTED_STDOUT:
                raise AssertionError(f"BLOCKED: portable GGUF output drift: {row['stdout_sha256']}")
            values[threads].append(row["stdout_sha256"])
            observations[threads].append(row["max_observed_rss_bytes"])
            print(f"G1.7 INTEGRATED_THREADS_{threads}_ATTEMPT_{attempt}_SHA256={row['stdout_sha256']}",flush=True)
        if len(set(values[threads])) != 1:
            raise AssertionError("BLOCKED: within-run nondeterminism")
        print(f"G1.7 INTEGRATED_THREADS_{threads}=PASS_2_OF_2",flush=True)

    vendor,cpu=cpu_info()
    result={
        "job":args.job,
        "cpu_vendor":vendor,
        "cpu_model":cpu,
        "binary_sha256":EXPECTED_BIN,
        "model_sha256":EXPECTED_MODEL,
        "source_supervisor_sha256":EXPECTED_SUPERVISOR,
        "source_seccomp_sha256":EXPECTED_SECCOMP,
        "stdout_sha256":EXPECTED_STDOUT,
        "inferences":4,
        "max_sampled_rss_bytes":max(sum(observations.values(),[])),
        "security":"nonroot,networkless,readonly,noexec,capdrop,seccomp27,G1.5supervisor,memory768MiB,pids48",
        "rootless_delegation":"NOT_TESTED",
        "trust_g0":"HOLD",
    }
    args.manifest.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print("G1.7 INTEGRATED_CPU_VENDOR="+vendor,flush=True)
    print("G1.7 INTEGRATED_CPU_MODEL="+cpu,flush=True)
    print("G1.7 INTEGRATED_PORTABLE_FULL_SECURITY=PASS",flush=True)
    print("G1.7 ROOTLESS_DELEGATION=NOT_TESTED",flush=True)
    print("G1.7 TRUST_G0=HOLD",flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
