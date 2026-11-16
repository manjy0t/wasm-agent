"""Create a dedicated Trustee policy from already-approved HAL requirements.

This command never learns/approves measurements from a target or registers policy
over the network. The administrator installs the generated CPU policy in Trustee.
"""
import argparse
import base64
import json
from pathlib import Path
import sys

from .attested_channel import validate_policy
from .common import Error, canonical, digest, parse, require
from .trustee import RELEASE, TDX_FIELDS, TCB_FIELDS, policy_binding


def render(policy):
    validate_policy(policy)
    conditions = []
    if policy['platform'] == 'intel-tdx':
        conditions += ['input.tdx', 'not input.snp',
                       'input.tdx.quote.header.tee_type == "81000000"',
                       'input.tdx.quote.header.vendor_id == "939a7233f79c4ca9940a0db3957f0607"',
                       'input.tdx.td_attributes.debug == false',
                       'input.tdx.tcb_status == "UpToDate"',
                       'input.tdx.collateral_expiration_status == "0"']
        conditions += ['input.tdx.quote.body.' + field + ' == ' + json.dumps(policy['measurements'][key])
                       for key, field in TDX_FIELDS.items()]
    else:
        # Trustee's SNP verifier enforces VMPL 0, vendor chain, signature and
        # endorsement TCB. Product selection is also checked by management's codec.
        conditions += ['input.snp', 'not input.tdx', 'input.snp.policy_debug_allowed == false',
                       'input.snp.policy_migrate_ma == false',
                       'input.snp.measurement == ' + json.dumps(policy['measurements']['measurement'])]
        conditions += ['input.snp.reported_tcb_' + key + ' >= ' + str(policy['snp_minimum_tcb'][key])
                       for key in TCB_FIELDS]
    conditions += ['is_string(input.report_data)', 'count(input.report_data) == 128']
    return ('# Generated for Trustee v0.22.0; approved values, never remote discovery.\n'
            'package policy\nimport rego.v1\n\n'
            'default hardware := 97\ndefault configuration := 36\ndefault executables := 33\n'
            'hardware := 2 if { approved }\nconfiguration := 2 if { approved }\n'
            'executables := 3 if { approved }\n\napproved if {\n    ' + '\n    '.join(conditions) + '\n}\n\n'
            'trust_claims := {"hardware": hardware, "configuration": configuration, "executables": executables,\n'
            '    "instance-identity": 0, "file-system": 0, "runtime-opaque": 0, "storage-opaque": 0, "sourced-data": 0}\n'
            'extensions := [{"name": "hal.policy-binding", "key": -70001, "value": '
            + json.dumps(policy_binding(policy)) + '}]\n')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy', required=True, type=Path, help='Already approved platform measurements and SNP TCB requirements')
    parser.add_argument('--url', default='http://127.0.0.1:8080')
    parser.add_argument('--issuer', default='hal-management-trustee')
    parser.add_argument('--signer-public-key', required=True, type=Path)
    parser.add_argument('--ca-file', type=Path, help='CA for a remote HTTPS AS; omitted for system trust or local loopback')
    parser.add_argument('--snp-codec', type=Path, help='Built codec on the management machine, required for AMD')
    parser.add_argument('--output', required=True, type=Path, help='New directory; existing files are never replaced')
    args = parser.parse_args(argv)
    try:
        policy = parse(args.policy.read_text())
        policy['verifier'] = 'trustee'
        for legacy in ('qvl_library', 'verifier_argv', 'verifier_files'):
            policy.pop(legacy, None)
        config = dict(release=RELEASE, url=args.url, issuer=args.issuer,
                      signer_public_key_pem=args.signer_public_key.read_text(),
                      policy_id='hal-' + ('tdx-' if policy['platform'] == 'intel-tdx' else 'snp-') + policy_binding(policy)[:16])
        if args.ca_file:
            config['ca_pem'] = args.ca_file.read_text()
        if args.snp_codec:
            config['snp_codec'] = dict(path=str(args.snp_codec.resolve()), sha256=digest(args.snp_codec.read_bytes()))
        policy['trustee'] = config
        source = render(policy)
        upload = dict(policy_id=config['policy_id'] + '_cpu', policy=base64.urlsafe_b64encode(source.encode()).decode().rstrip('='))
        require(not args.output.exists(), 'Output directory exists; choose a new directory to preserve policy')
        args.output.mkdir(parents=True, mode=0o700)
        for name, value in [('attestation-policy.json', json.dumps(policy, indent=2) + '\n'),
                            (upload['policy_id'] + '.rego', source), ('policy-upload.json', canonical(upload) + '\n')]:
            with (args.output / name).open('x') as stream:
                stream.write(value)
        print(json.dumps(dict(output=str(args.output), policy_id=config['policy_id'],
                              policy_binding=policy_binding(policy), registered=False), indent=2))
        return 0
    except (Error, OSError, KeyError, TypeError, ValueError) as exc:
        print('Error: ' + str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
