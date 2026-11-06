#!/usr/bin/env python3
"""Load every Foreman pipeline file in this repo against the schema Foreman validates it with.

Usage:  python3 scripts/deploy/check-pipelines.py        (needs python3 and PyYAML, exit 0 = pass)

Mirrors, by hand, the keys and limits of `pipelineFile` and `pipelineStep` in the Foreman repo
(packages/contracts/src/deployments.ts) and the placeholder rules of `interpolate` and
`sharedRecordBranchLeaks` (apps/api/src/services/deployments/pipeline.ts). It is a copy, so a
change to the Foreman schema needs the same change here; the check that matters is Foreman's own
loader, and this script exists to catch a typo before a release is triggered.

Then it holds each file to the rules this repo wants of it (see EXPECT below). The two release
pipelines run on a github_release target. They inject no credential (gh uses the host keyring),
they advertise nothing, and they end with a read-only Collect evidence step.
"""
import re
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
PIPELINE_DIR = REPO_ROOT / ".foreman" / "pipelines"
SCRIPT_DIR = REPO_ROOT / "scripts" / "deploy"

# pipelineFile keys, strict: an unknown key is a failure.
FILE_KEYS = {"name", "description", "kind", "operation", "install", "requires_files", "advertises", "steps"}
# pipelineStep keys, strict.
STEP_KEYS = {"name", "description", "run", "needs", "timeout", "workdir", "slow", "expect", "observe", "always", "required"}
# A fact key named in `expect`: lowercase start, then letters, digits, dot, dash, underscore, 40 characters at most.
FACT_KEY = re.compile(r"^[a-z][A-Za-z0-9_.-]{0,39}$")
# The last step of every pipeline: it prints evidence and no verdict (docs/pipeline-observability.md in foreman).
EVIDENCE_STEP = "Collect evidence"
KINDS = {"runos_cluster", "github_release"}
OPERATIONS = {"deploy", "cohort", "rollback"}
SLUG = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
PLACEHOLDER = re.compile(r"\$\{\{\s*([a-zA-Z0-9_.]+)\s*\}\}")
BARE = {"version", "repo", "ref", "branch", "fast", "rollback_to", "run_dir"}
# The target config keys these pipelines are allowed to read. The target row must define each.
TARGET_KEYS = {"env", "branch", "deployed_branch"}
# The shared record branches. A command that names one literally defeats the objective-scoped
# rewrite of ${{ target.deployed_branch }}, which Foreman refuses.
RECORD_BRANCHES = ("deployed/dev", "deployed/prod")
# Words that change the repo, the registry or the cluster. The evidence step uses none of them.
MUTATING = ("git push", "git tag", "git branch", "git merge", "gh release create", "gh release edit", "kubectl", "docker push")

CANDIDATE_STEPS = [
    "Hidden release candidate only",
    "Gate chain",
    "Tag and push",
    "Wait for the release workflow",
    "Verify the published release",
    "Advance the deployed branch",
    EVIDENCE_STEP,
]
FINAL_STEPS = [
    "Version and target agree",
    "Final comes from the validated candidate",
    "Gate chain",
    "Tag and push",
    "Wait for the release workflow",
    "Verify the published release",
    "Advance the deployed branch",
    EVIDENCE_STEP,
]
TIMEOUTS = {"Gate chain": 1800, "Wait for the release workflow": 1800, "Verify the published release": 300, EVIDENCE_STEP: 120}
# The script each step must run, by step name.
SCRIPTS = {
    "Gate chain": "scripts/release.sh",
    "Wait for the release workflow": "scripts/deploy/watch-release.sh",
    "Verify the published release": "scripts/deploy/verify-release.sh",
    EVIDENCE_STEP: "scripts/deploy/release-evidence.sh",
}

# Per file: the exact step names in order. A file not listed here fails, so a new pipeline must be
# added to this table on purpose.
EXPECT = {
    "release-rc.yml": {"steps": CANDIDATE_STEPS},
    "release.yml": {"steps": FINAL_STEPS},
}


def check_step(where: str, step: object, errors: list[str]) -> None:
    if not isinstance(step, dict):
        errors.append(f"{where}: a step must be a mapping")
        return
    for key in step:
        if key not in STEP_KEYS:
            errors.append(f"{where}: unknown step key '{key}'")
    name = step.get("name")
    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 120:
        errors.append(f"{where}: name must be a string of 1 to 120 characters")
    desc = step.get("description", "")
    if not isinstance(desc, str) or len(desc.strip()) > 500:
        errors.append(f"{where}: description must be a string of at most 500 characters")
    run = step.get("run")
    if not isinstance(run, str) or not 1 <= len(run.strip()) <= 4000:
        errors.append(f"{where}: run must be a string of 1 to 4000 characters")
    needs = step.get("needs", [])
    if not isinstance(needs, list) or len(needs) > 10:
        errors.append(f"{where}: needs must be a list of at most 10 slugs")
    else:
        for slug in needs:
            if not isinstance(slug, str) or not SLUG.match(slug):
                errors.append(f"{where}: credential slug {slug!r} must be kebab-case")
        if needs:
            errors.append(f"{where}: a release step injects no credential (gh uses the host keyring), found {needs!r}")
    timeout = step.get("timeout")
    if timeout is not None and (
        isinstance(timeout, bool) or not isinstance(timeout, int) or not 0 < timeout <= 21600
    ):
        errors.append(f"{where}: timeout must be a positive integer of at most 21600")
    workdir = step.get("workdir")
    if workdir is not None and (not isinstance(workdir, str) or len(workdir.strip()) > 200):
        errors.append(f"{where}: workdir must be a string of at most 200 characters")
    if "slow" in step and not isinstance(step["slow"], bool):
        errors.append(f"{where}: slow must be a boolean")
    expect = step.get("expect", [])
    if not isinstance(expect, list) or len(expect) > 40:
        errors.append(f"{where}: expect must be a list of at most 40 fact keys")
    else:
        for key in expect:
            if not isinstance(key, str) or not FACT_KEY.match(key):
                errors.append(f"{where}: expect key {key!r} must start with a lowercase letter and use letters, digits, dot, dash, underscore (40 at most)")
    observe = step.get("observe", "")
    if not isinstance(observe, str) or len(observe.strip()) > 500:
        errors.append(f"{where}: observe must be a string of at most 500 characters")
    for flag in ("always", "required"):
        if flag in step and not isinstance(step[flag], bool):
            errors.append(f"{where}: {flag} must be a boolean")
    if step.get("required") is True and step.get("always") is not True:
        errors.append(f"{where}: required only applies to a step with always: true")
    if isinstance(run, str):
        for expr in PLACEHOLDER.findall(run):
            if "." in expr:
                if not expr.startswith("target.") or expr[len("target."):] not in TARGET_KEYS:
                    errors.append(f"{where}: placeholder ${{{{ {expr} }}}} is not a target key this repo expects")
            elif expr not in BARE:
                errors.append(f"{where}: placeholder ${{{{ {expr} }}}} is not one foreman resolves")
        for line in run.split("\n"):
            if line.lstrip().startswith("#"):
                continue
            for branch in RECORD_BRANCHES:
                if re.search(rf"(^|[^\w-]){re.escape(branch)}([^\w/-]|$)", line):
                    errors.append(f"{where}: the command names the shared record branch {branch} literally; use ${{{{ target.deployed_branch }}}}")
        if "git add -A" in run or "git add ." in run:
            errors.append(f"{where}: a blanket git add can sweep unreviewed work into a release; stage named files")


def script_facts() -> set[str]:
    """Every fact key that a script in scripts/deploy prints through fm_fact."""
    keys: set[str] = set()
    for path in SCRIPT_DIR.glob("*.sh"):
        keys.update(re.findall(r"\bfm_fact\s+([a-z][A-Za-z0-9_.-]*)\b", path.read_text()))
    return keys


def check_evidence_step(label: str, steps: list, errors: list[str]) -> None:
    """The last step is `Collect evidence`: always, 120 s, no credential, a read-only script call."""
    last = steps[-1] if steps and isinstance(steps[-1], dict) else {}
    if last.get("name") != EVIDENCE_STEP:
        errors.append(f"{label}: the last step must be named {EVIDENCE_STEP!r}")
        return
    if last.get("always") is not True or last.get("required") is True:
        errors.append(f"{label}: {EVIDENCE_STEP!r} must set always: true and must not set required")
    if last.get("timeout") != 120:
        errors.append(f"{label}: {EVIDENCE_STEP!r} timeout must be 120")
    run = last.get("run", "")
    if "release-evidence.sh" not in run or "${{ run_dir }}" not in run:
        errors.append(f"{label}: {EVIDENCE_STEP!r} must call release-evidence.sh with a file in ${{{{ run_dir }}}}")
    for word in MUTATING:
        if word in run:
            errors.append(f"{label}: {EVIDENCE_STEP!r} is read-only and must not run {word!r}")
    text = (SCRIPT_DIR / "release-evidence.sh").read_text() if (SCRIPT_DIR / "release-evidence.sh").is_file() else ""
    for word in MUTATING:
        if word in text:
            errors.append(f"{label}: scripts/deploy/release-evidence.sh is read-only and must not run {word!r}")


def check_file(path: Path, facts: set[str]) -> list[str]:
    errors: list[str] = []
    label = path.name
    try:
        doc = yaml.safe_load(path.read_text())
    except yaml.YAMLError as err:
        return [f"{label}: not valid YAML: {err}"]
    if not isinstance(doc, dict):
        return [f"{label}: the file must be a mapping"]
    for key in doc:
        if key not in FILE_KEYS:
            errors.append(f"{label}: unknown key '{key}'")
    name = doc.get("name")
    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 120:
        errors.append(f"{label}: name must be a string of 1 to 120 characters")
    description = doc.get("description", "")
    if not isinstance(description, str) or len(description.strip()) > 1000:
        errors.append(f"{label}: description must be a string of at most 1000 characters")
    if doc.get("kind") not in KINDS:
        errors.append(f"{label}: kind must be one of {sorted(KINDS)}")
    if doc.get("kind") != "github_release":
        errors.append(f"{label}: a public repo release is a github_release pipeline; GitHub Actions builds, foreman does not")
    if doc.get("operation", "deploy") != "deploy":
        errors.append(f"{label}: operation must be deploy")
    if "advertises" in doc:
        errors.append(f"{label}: this repo advertises no version; remove advertises")
    if doc.get("install") is not None:
        errors.append(f"{label}: no install step: foreman builds nothing here")
    steps = doc.get("steps")
    if not isinstance(steps, list) or not 1 <= len(steps) <= 100:
        errors.append(f"{label}: steps must be a list of 1 to 100 steps")
        steps = []
    for index, step in enumerate(steps):
        check_step(f"{label} step {index + 1}", step, errors)

    expect = EXPECT.get(path.name)
    if expect is None:
        errors.append(f"{label}: no expectations in EXPECT; add this file to the table on purpose")
        return errors
    names = [s.get("name") for s in steps if isinstance(s, dict)]
    if names != expect["steps"]:
        errors.append(f"{label}: steps are {names}, expected {expect['steps']}")
    for step in steps:
        if not isinstance(step, dict):
            continue
        step_name = step.get("name")
        want = TIMEOUTS.get(step_name)
        if want is not None and step.get("timeout") != want:
            errors.append(f"{label}: step {step_name!r} timeout must be {want}")
        script = SCRIPTS.get(step_name)
        if script:
            if not (REPO_ROOT / script).is_file():
                errors.append(f"{label}: the script {script} does not exist")
            if script not in step.get("run", ""):
                errors.append(f"{label}: step {step_name!r} must run {script}")
        for key in step.get("expect", []) or []:
            if key not in facts:
                errors.append(f"{label}: step {step_name!r} expects fact {key!r}, which no script in scripts/deploy prints")
    gate = next((s for s in steps if isinstance(s, dict) and s.get("name") == "Gate chain"), {})
    if "--check" not in gate.get("run", ""):
        errors.append(f"{label}: the Gate chain step must run scripts/release.sh in --check mode")
    check_evidence_step(label, steps, errors)
    return errors


def main() -> int:
    files = sorted(PIPELINE_DIR.glob("*.y*ml"))
    if not files:
        print(f"no pipeline files in {PIPELINE_DIR}")
        return 1
    facts = script_facts()
    failures = 0
    for path in files:
        errors = check_file(path, facts)
        if errors:
            failures += len(errors)
            for message in errors:
                print(f"FAIL {message}")
        else:
            print(f"ok   {path.name}")
    missing = set(EXPECT) - {p.name for p in files}
    for name in sorted(missing):
        failures += 1
        print(f"FAIL {name}: expected pipeline file is missing")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
