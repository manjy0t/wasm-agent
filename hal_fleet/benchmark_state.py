"""Refuse cross-profile service state and overlapping managed VM services."""
import os
from pathlib import Path
import sys
from .common import Error, require, read_private, digest


def bind_state(config, database):
    architecture = config.get('execution_architecture', 'legacy')
    pin = dict(role=config['role'], architecture=architecture, mode=config.get('mode'))
    if architecture == 'hal-native-audited-v1':
        pin['certificate_sha256'] = digest(Path(config['native_certificate']).read_bytes())
    if architecture == 'hal-selectable-execution-v1':
        pin.update(profiles=config['profile_sha256'], mode_control_public_key=config['mode_control_public_key'])
    with database.lock:
        old = database.get('service-profile', 'pin')
        if old is None:
            if architecture == 'hal-native-audited-v1':
                require(database.connection.execute('SELECT count(*) FROM records').fetchone()[0] == 0,
                        'Audited native requires fresh state; do not reuse an agent or historical native database', 409)
            database.put('service-profile', 'pin', pin)
        else:
            require(old == pin, 'Service state belongs to another execution profile; choose a fresh state directory', 409)


def execution_slot(path=None):
    """OS lock shared by native and agent fleet services, outside their state dirs.

    It prevents accidental parallel managed deployments. An administrator can
    bypass it by running binaries directly; this is not a security boundary.
    """
    import fcntl
    if path is None:
        require(sys.platform == 'linux', 'Fleet execution services require a Linux VM')
        path = '/run/hal-fleet-execution-profile.lock'
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    stream = os.fdopen(fd, 'r+')
    try:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        stream.close()
        raise Error('Another native or agent fleet service owns this VM; stop and drain it before switching profiles', 409) from exc
    return stream
