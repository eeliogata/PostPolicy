# PostPolicy

Inspect a presigned S3 POST policy and check what a supplied form can store. Input is a JSON file with `url` and `fields`, as returned by `generate_presigned_post`. The policy view redacts credential and token conditions.

```sh
python3 postpolicy.py inspect form.json
python3 postpolicy.py probe form.json --bucket test-bucket --prefix scratch/ --profile assessment --set Content-Type=text/plain --set key=scratch/alternate.bin --out result.json
```

`probe` sends the original form once, then one request per `--set FIELD=VALUE`, always starting from the original fields. `--set filename=NAME` changes the multipart file name for `${filename}` expansion. The payload is a small unique marker. Each requested key must be under `--prefix`; an authorized AWS CLI `GetObject` checks that the key was absent before the first write and that the stored bytes match after each write. Confirmed test objects are deleted only if their bytes still match. Use `--endpoint-url` for an S3-compatible readback endpoint.

The report omits signatures, session tokens, form contents, and object bodies. A successful POST without matching readback is listed under `unverified_uploads` and is left in place. The command returns 2 if probing or cleanup is incomplete. AWS CLI credentials used for readback need GetObject and DeleteObject on the selected prefix.
