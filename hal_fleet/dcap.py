"""Intel DCAP QVL adapter on the trusted management VM (Linux, 64-bit).

Uses the vendor's tdx_qv_verify_quote API, not a home-grown signature verifier.
QPL/PCCS configuration and current Intel collateral are deployment prerequisites.
Only DCAP v4 / TDX 1.0 quote bodies are decoded; unknown formats fail closed.
"""
import ctypes
import os
import struct
import time
from .common import Error, digest, require


def verify_quote(raw, library):
    require(os.name == 'posix' and ctypes.sizeof(ctypes.c_long) == 8, 'DCAP adapter requires 64-bit Linux', 503)
    require(len(raw) >= 636 and struct.unpack_from('<H', raw)[0] == 4
            and struct.unpack_from('<I', raw, 4)[0] == 0x81,
            'Only TDX v4 quotes are supported by this adapter', 403)
    require(636 + struct.unpack_from('<I', raw, 632)[0] == len(raw), 'Malformed TDX quote length', 403)
    try:
        qvl = ctypes.CDLL(library)
        verify = qvl.tdx_qv_verify_quote
        u32 = ctypes.c_uint32
        verify.argtypes = [ctypes.c_void_p, u32, ctypes.c_void_p, ctypes.c_long,
                           ctypes.POINTER(u32), ctypes.POINTER(u32), ctypes.c_void_p, u32, ctypes.c_void_p]
        verify.restype = u32
        quote = ctypes.create_string_buffer(raw)
        expired, result = u32(1), u32(0xFFFFFFFF)
        status = verify(quote, len(raw), None, int(time.time()), ctypes.byref(expired),
                        ctypes.byref(result), None, 0, None)
    except (OSError, AttributeError) as exc:
        raise Error('Intel DCAP QVL is unavailable on management', 503, 'attestation_failed') from exc
    require(status == 0 and expired.value == 0 and result.value == 0,
            'DCAP rejected quote, collateral expiry, or TCB status', 403, 'attestation_failed')
    offsets = {'mrtd': 184, 'rtmr0': 376, 'rtmr1': 424, 'rtmr2': 472, 'rtmr3': 520}
    return dict(verified=True, platform='intel-tdx', evidence_sha256=digest(raw),
                report_data=raw[568:632].hex(), debug=bool(struct.unpack_from('<Q', raw, 168)[0] & 1),
                tcb_status='UpToDate', measurements={name: raw[pos:pos+48].hex() for name, pos in offsets.items()})


if __name__ == '__main__':
    import sys
    from .common import canonical, parse
    try:
        require(len(sys.argv) == 2, 'Supply a QVL library path')
        message = sys.stdin.buffer.read(2 * 1024 * 1024 + 128)
        request = parse(message)
        raw = bytes.fromhex(request['report_hex'])
        require(len(raw) <= 1024 * 1024, 'Evidence too large')
        print(canonical(verify_quote(raw, sys.argv[1])))
    except Exception:
        sys.exit(1)
