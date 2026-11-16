"""Synthetic contract inputs for the pinned Rego engine tests; no TEE claims."""
import json
import sys
from test_trustee import TrusteeTest
from hal_fleet.trustee_policy import render

test = TrusteeTest()
test.setUp()
tee = sys.argv[1]
if tee == 'snp':
    test.snp()
claims = test.payload(tee)['submods']['cpu0']['ear.veraison.annotated-evidence']
print(json.dumps(dict(policy=render(test.policy), claims=claims)))
