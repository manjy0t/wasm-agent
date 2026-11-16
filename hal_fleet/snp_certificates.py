"""Bounded Linux SNP extended-report certificate-table decoding.

This only translates endorsements into Trustee's sev::CertTableEntry JSON.
Trustee, using its pinned AMD roots, must verify the chain and report signature.
The UUID byte order and serde names match the pinned sev crate used by Trustee.
"""
import struct
import uuid

MAX_CERTIFICATES = 64 * 1024
TYPES = {
    'c0b406a4-a803-4952-9743-3fb6014cd0ae': 'ARK',
    '4ab7b379-bbac-4fe4-a02f-05aef327c782': 'ASK',
    '63da758d-e664-4564-adc5-f4b93be8accd': 'VCEK',
    'a8074bc2-a25a-483e-aae6-39c045a0b8a1': 'VLEK',
}


def decode_table(raw):
    if not raw:
        return []
    if len(raw) > MAX_CERTIFICATES:
        raise ValueError('SNP certificate table exceeds 64 KiB')
    entries, seen, position = [], set(), 0
    while True:
        if position + 24 > len(raw) or len(entries) >= 64:
            raise ValueError('SNP certificate table is truncated or has no terminator')
        guid, offset, length = struct.unpack_from('<16sII', raw, position)
        position += 24
        if guid == bytes(16):
            if offset or length:
                raise ValueError('Invalid SNP certificate table terminator')
            break
        if guid in seen or length == 0 or offset + length > len(raw):
            raise ValueError('Duplicate or out-of-bounds SNP certificate entry')
        seen.add(guid)
        entries.append((guid, offset, length))
    end = position
    for _, offset, length in sorted(entries, key=lambda entry: entry[1]):
        if offset < end:
            raise ValueError('SNP certificate entries overlap the table or each other')
        end = offset + length
    return [{'cert_type': TYPES[str(uuid.UUID(bytes=guid))], 'data': list(raw[offset:offset + length])}
            for guid, offset, length in entries if str(uuid.UUID(bytes=guid)) in TYPES]


def chain_for_report(report, auxiliary):
    if len(report) != 1184:
        raise ValueError('Expected a complete 1184-byte SNP report')
    info = struct.unpack_from('<I', report, 0x48)[0]
    signer = (info >> 2) & 7
    if signer not in (0, 1) or info & 2:
        raise ValueError('SNP report is unsigned or uses an unsupported signing key')
    kind = 'VLEK' if signer == 1 else 'VCEK'
    entries = decode_table(auxiliary)
    # Supplying two different leaves lets a verifier select the wrong one.
    chain = [entry for entry in entries if entry['cert_type'] in ('ARK', 'ASK', kind)]
    if not any(entry['cert_type'] == kind for entry in chain):
        if kind == 'VLEK' or auxiliary:
            raise ValueError('SNP report needs a ' + kind + ' certificate from the guest extended report (TSM auxblob)')
        return None  # VCEK-only platforms may use Trustee's AMD KDS lookup.
    return chain
