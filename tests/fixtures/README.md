# CloudTrail fixtures

**These two fixtures are synthetic.** They were written by hand to the exact shape of a
`LookupEvents` response, not captured from a real AWS run. Nothing in this repository has
called AWS yet, and pretending otherwise would be the kind of claim `CLAUDE.md` forbids.

Replace them with real, scrubbed captures after the first demo run:

```bash
python scripts/capture_fixture.py <access key id> --region ap-south-1 \
  --out tests/fixtures/cloudtrail_ap_south_1.json
```

`capture_fixture.py` scrubs before writing, including inside the nested `CloudTrailEvent`
JSON string, which is where account ids and ARNs hide:

| Real value | Written to the fixture |
|---|---|
| Any 12-digit account id, including inside ARNs | `000000000000` |
| `sourceIPAddress` | `203.0.113.10` (RFC 5737 documentation range) |
| `userAgent` | `scrubbed` |
| Any AWS access key id | `AKIAIOSFODNN7EXAMPLE` |

The key id is rewritten to AWS's own documented example on purpose: a fixture holding a
real-looking key id would, correctly, fail `scripts/check_secrets.sh`.

## What each fixture holds

| File | Contents |
|---|---|
| `cloudtrail_ap_south_1.json` | One `RunInstances` and one `DescribeInstances`, so the creation filter is exercised |
| `cloudtrail_us_east_1.json` | One `RunInstances` in the second region, and a `NextToken` so pagination is exercised |
