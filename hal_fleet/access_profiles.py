"""Optional refinements of the existing signed rule; no new authority/service.

Templates are explicit administrative choices. Imports alone cannot establish
least privilege, and this generator never guesses or grants new capabilities.
"""
import copy
from functools import lru_cache
from pathlib import Path
from .common import digest, parse, require, atomic_json, SHA
from .local_files import read_regular, write_private

ROOT = Path(__file__).resolve().parents[1]
FIELDS = {'version', 'artifact_sha256', 'operations', 'max_host_calls', 'max_buffer_bytes'}


@lru_cache(maxsize=1)
def definition():
    return parse((ROOT / 'vendor/hal-access-profile/profile-v1.json').read_text(encoding='utf-8'))


def validate(profile, artifact, permissions):
    require(isinstance(profile, dict) and set(profile) == FIELDS, 'Invalid workload access profile fields')
    require(isinstance(artifact, str) and SHA.fullmatch(artifact), 'Invalid profile artifact digest')
    require(type(profile['version']) is int and profile['version'] == 1
            and profile['artifact_sha256'] == artifact, 'Unsupported profile version or artifact binding')
    for field, maximum in (('max_host_calls', 100000), ('max_buffer_bytes', 1048576)):
        require(type(profile[field]) is int and 1 <= profile[field] <= maximum, 'Invalid profile limit: ' + field)
    operations = profile['operations']
    known = definition()['operations']
    require(isinstance(operations, list) and len(operations) <= len(known)
            and all(isinstance(op, str) and op in known for op in operations), 'Unknown profile operation')
    require(len(set(operations)) == len(operations), 'Duplicate profile operation')
    require(all(not known[op] or known[op] in permissions for op in operations),
            'Profile cannot grant permissions outside the management rule')
    return profile


def create(artifact, permissions, template, max_host_calls=10000, max_buffer_bytes=1048576):
    templates = definition()['templates']
    require(template in templates, 'Unknown access template: ' + template)
    return validate(dict(version=1, artifact_sha256=artifact, operations=list(templates[template]),
                         max_host_calls=max_host_calls, max_buffer_bytes=max_buffer_bytes), artifact, permissions)


def generate(manifest, output, template, assignments=None, name_suffix='', max_host_calls=10000, max_buffer_bytes=1048576):
    """Prepare a new manifest locally. Existing artifacts and policy stay intact."""
    from .policy import workload
    manifest, output = Path(manifest), Path(output)
    require(not output.exists(), 'Output already exists; keep the reviewed manifest', 409)
    require(bool(template) != bool(assignments), 'Choose one template or an assignments JSON file')
    value = copy.deepcopy(parse(read_regular(manifest).decode('utf-8-sig')))
    require(isinstance(value, dict) and isinstance(value.get('workloads'), list)
            and 1 <= len(value['workloads']) <= 128, 'Expected a workload manifest')
    rows = value['workloads']
    names = [workload(row)['name'] for row in rows]
    require(len(set(names)) == len(names), 'Duplicate workload name')
    mapping = parse(read_regular(assignments).decode('utf-8-sig')) if assignments else dict.fromkeys(names, template)
    require(isinstance(mapping, dict) and set(mapping) == set(names)
            and all(isinstance(t, str) for t in mapping.values()), 'Assign exactly one template to each manifest workload')
    artifacts = {}
    for row in rows:
        raw = read_regular(manifest.parent / row['component'], maximum=16777216)
        require(len(raw) == row['artifact_bytes'] and digest(raw) == row['sha256'], 'Artifact differs from manifest')
        require('access_profile' not in row['rule'], 'Manifest already has a profile; use the original manifest')
        row['rule']['access_profile'] = create(row['sha256'], row['rule']['hal_permissions'], mapping[row['name']],
                                              max_host_calls, max_buffer_bytes)
        row['name'] += name_suffix
        workload(row)
        artifacts[row['component']] = raw
    # Preflight every destination before writing anything. The manifest is the
    # final commit marker; an interrupted copy can be resumed with the same input.
    for name, raw in artifacts.items():
        destination = output.parent / name
        if destination.exists():
            require(read_regular(destination, maximum=16777216) == raw, 'Output artifact has different bytes: ' + name)
    output.parent.mkdir(parents=True, exist_ok=True)
    for name, raw in artifacts.items():
        destination = output.parent / name
        if not destination.exists():
            write_private(destination, raw, exclusive=True)
    atomic_json(output, value, exclusive=True)
    return dict(manifest=str(output), workloads=names, profiles=len(rows), published=False,
                note='Review before publishing. Catalog names are immutable; existing grants are unchanged.')
