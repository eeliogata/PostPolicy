#!/usr/bin/env python3
import argparse
import base64
import hashlib
import http.client
import json
import os
import re
import ssl
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from urllib.parse import urlsplit


SECRET_FIELDS = {"x-amz-signature", "x-amz-security-token", "x-amz-credential", "awsaccesskeyid", "signature"}
LOCKED_FIELDS = SECRET_FIELDS | {"policy", "x-amz-algorithm", "x-amz-date", "file"}
ERROR = re.compile(r"An error occurred \(([^)]+)\)")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def form(path):
    data = json.loads(path.read_text())
    if not isinstance(data, dict) or not isinstance(data.get("url"), str) or not isinstance(data.get("fields"), dict):
        raise ValueError("expected url and fields in the form file")
    fields = data["fields"]
    if "key" not in fields or "policy" not in fields or "file" in fields:
        raise ValueError("form needs key and policy fields, but no file field")
    for name, value in fields.items():
        if (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9-]+", name)
                or not isinstance(value, str) or "\r" in value or "\n" in value):
            raise ValueError("invalid form field")
    url = urlsplit(data["url"])
    if url.scheme not in ("http", "https") or not url.hostname or url.username or url.password or url.fragment:
        raise ValueError("invalid form URL")
    policy = json.loads(base64.b64decode(fields["policy"], validate=True))
    if not isinstance(policy, dict) or not isinstance(policy.get("conditions"), list):
        raise ValueError("invalid POST policy")
    return url, fields, policy


def visible_policy(policy):
    conditions = []
    for condition in policy["conditions"]:
        if isinstance(condition, dict):
            conditions.append({name: "[redacted]" if name.lower() in SECRET_FIELDS else value
                               for name, value in condition.items()})
        elif isinstance(condition, list) and len(condition) == 3:
            operator, field, value = condition
            conditions.append([operator, field,
                               "[redacted]" if isinstance(field, str) and field.lstrip("$").lower() in SECRET_FIELDS else value])
        else:
            raise ValueError("invalid policy condition")
    return {"expiration": policy.get("expiration"), "conditions": conditions}


def encode(fields, filename, payload):
    boundary = "postpolicy-" + uuid.uuid4().hex
    parts = []
    for name, value in fields.items():
        parts.append((f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n").encode())
    parts.append((f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n"
                  "Content-Type: application/octet-stream\r\n\r\n").encode() + payload + b"\r\n")
    parts.append(f"--{boundary}--\r\n".encode())
    return boundary, b"".join(parts)


def upload(url, fields, filename, payload, timeout, insecure):
    boundary, body = encode(fields, filename, payload)
    if len(body) > 1024 * 1024:
        raise ValueError("multipart request exceeds 1 MiB")
    context = ssl.create_default_context()
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    port = url.port or (443 if url.scheme == "https" else 80)
    conn = (http.client.HTTPSConnection(url.hostname, port, timeout=timeout, context=context)
            if url.scheme == "https" else http.client.HTTPConnection(url.hostname, port, timeout=timeout))
    try:
        path = (url.path or "/") + ("?" + url.query if url.query else "")
        conn.request("POST", path, body=body,
                     headers={"Content-Type": "multipart/form-data; boundary=" + boundary})
        response = conn.getresponse()
        if len(response.read(8193)) > 8192:
            raise ValueError("upload response exceeds 8 KiB")
        return response.status
    finally:
        conn.close()


def aws(args, command):
    call = ["aws", "--no-cli-pager", "--no-cli-auto-prompt",
            "--cli-connect-timeout", "5", "--cli-read-timeout", "20"]
    if args.profile:
        call += ["--profile", args.profile]
    if args.region:
        call += ["--region", args.region]
    if args.endpoint_url:
        call += ["--endpoint-url", args.endpoint_url]
    call += ["s3api"] + command
    env = os.environ.copy()
    env.update(AWS_MAX_ATTEMPTS="1", AWS_RETRY_MODE="standard", AWS_PAGER="")
    return subprocess.run(call, capture_output=True, text=True, env=env, check=False)


def readback(args, key):
    with tempfile.TemporaryDirectory() as directory:
        target = str(Path(directory) / "object")
        result = aws(args, ["get-object", "--bucket", args.bucket, "--key", key, target])
        if result.returncode == 0:
            return {"status": "found", "sha256": sha256(Path(target).read_bytes())}
        match = ERROR.search(result.stderr)
        code = match.group(1) if match else "AwsCliError"
        if code in {"NoSuchKey", "404", "NotFound"}:
            return {"status": "absent"}
        raise ValueError("readback failed: " + code)


def delete(args, key):
    result = aws(args, ["delete-object", "--bucket", args.bucket, "--key", key])
    if result.returncode:
        match = ERROR.search(result.stderr)
        return {"key": key, "status": "error", "code": match.group(1) if match else "AwsCliError"}
    return {"key": key, "status": "deleted"}


def effective_key(fields, filename):
    return fields["key"].replace("${filename}", filename)


def probe(args, url, fields, policy):
    owned = {}
    report = {"endpoint_host": url.hostname, "bucket": args.bucket,
              "policy": visible_policy(policy), "trials": [], "cleanup": [], "unverified_uploads": []}
    mutations = [(None, None)] + [item.split("=", 1) for item in args.set]
    try:
        for index, (name, value) in enumerate(mutations):
            trial_fields = fields.copy()
            filename = args.filename
            if name == "filename":
                filename = value
            elif name:
                existing = next((key for key in trial_fields if key.lower() == name.lower()), name)
                trial_fields[existing] = value
            if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", filename):
                raise ValueError("invalid filename")
            key = effective_key(trial_fields, filename)
            item = {"mutation_field": name, "mutation_value_sha256": sha256(value.encode()) if name else None,
                    "effective_key": key}
            report["trials"].append(item)
            if not key.startswith(args.prefix):
                item["skipped"] = "outside selected prefix"
                continue
            if key not in owned:
                before = readback(args, key)
                if before["status"] != "absent":
                    item["skipped"] = "object already exists"
                    continue
            payload = ("postpolicy:" + args.marker + ":" + str(index)).encode()
            item["payload_sha256"] = sha256(payload)
            item["upload_status"] = upload(url, trial_fields, filename, payload, args.timeout, args.insecure)
            after = readback(args, key)
            item["readback"] = after
            item["stored_payload_match"] = after.get("sha256") == item["payload_sha256"]
            if item["stored_payload_match"]:
                owned[key] = item["payload_sha256"]
            elif 200 <= item["upload_status"] < 300:
                report["unverified_uploads"].append(key)
    except (OSError, ValueError, http.client.HTTPException) as error:
        report["error"] = {"type": type(error).__name__}
    finally:
        for key, expected in owned.items():
            try:
                current = readback(args, key)
                if current.get("sha256") == expected:
                    report["cleanup"].append(delete(args, key))
                else:
                    report["cleanup"].append({"key": key, "status": "left in place"})
            except (OSError, ValueError) as error:
                report["cleanup"].append({"key": key, "status": "error", "code": type(error).__name__})
    return report


def main():
    parser = argparse.ArgumentParser(description="Inspect and probe a presigned S3 POST policy")
    sub = parser.add_subparsers(dest="command", required=True)
    inspect = sub.add_parser("inspect")
    inspect.add_argument("form", type=Path)
    run = sub.add_parser("probe")
    run.add_argument("form", type=Path)
    run.add_argument("--bucket", required=True)
    run.add_argument("--prefix", required=True)
    run.add_argument("--profile")
    run.add_argument("--region")
    run.add_argument("--endpoint-url")
    run.add_argument("--filename", default="postpolicy-" + uuid.uuid4().hex + ".bin")
    run.add_argument("--marker", default=uuid.uuid4().hex)
    run.add_argument("--set", action="append", default=[], metavar="FIELD=VALUE")
    run.add_argument("--out", type=Path, required=True)
    run.add_argument("--timeout", type=float, default=10)
    run.add_argument("--insecure", action="store_true")
    args = parser.parse_args()
    try:
        url, fields, policy = form(args.form)
        if args.command == "inspect":
            print(json.dumps(visible_policy(policy), indent=2))
            return 0
        if args.timeout <= 0 or not args.prefix or not re.fullmatch(r"[A-Za-z0-9-]{1,64}", args.marker):
            raise ValueError("invalid timeout, prefix, or marker")
        for condition in policy["conditions"]:
            if isinstance(condition, dict) and "bucket" in condition and condition["bucket"] != args.bucket:
                raise ValueError("bucket does not match the POST policy")
            if (isinstance(condition, list) and len(condition) == 3
                    and condition[0] == "eq" and condition[1] == "$bucket"
                    and condition[2] != args.bucket):
                raise ValueError("bucket does not match the POST policy")
        for item in args.set:
            if "=" not in item:
                raise ValueError("--set needs FIELD=VALUE")
            name, value = item.split("=", 1)
            if (not re.fullmatch(r"[A-Za-z0-9-]+", name) or name.lower() in LOCKED_FIELDS
                    or "\r" in value or "\n" in value):
                raise ValueError("invalid mutation field")
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            report = probe(args, url, fields, policy)
            json.dump(report, output, indent=2)
            output.write("\n")
    except (OSError, ValueError, KeyError, http.client.HTTPException) as error:
        parser.exit(2, str(error) + "\n")
    print(args.out)
    incomplete = any(item["status"] != "deleted" for item in report["cleanup"])
    return 2 if "error" in report or incomplete or report["unverified_uploads"] else 0


if __name__ == "__main__":
    sys.exit(main())
