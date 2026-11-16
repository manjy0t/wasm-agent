#!/usr/bin/env python3
"""Client/deployer checks on Windows, macOS and Linux; no Rust/Docker/VM needed.

Native Windows tests exercise real ACLs. Other platforms explicitly skip those
tests, and exercise the Windows ACL decision logic with synthetic descriptors.
"""
import io
import json
import os
from pathlib import Path, PureWindowsPath
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hal_fleet.common import Error, atomic_json, read_private
from hal_fleet.install import ROLES, add_archive_file, certificates, inventory, package, remote_command
from hal_fleet.local_files import _windows_check, _windows_open, read_regular, resolve_ca_file, write_private
from hal_fleet.client import Client


class PortableFilesTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='hal client Å ')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def test_private_json_roundtrip_replace_and_exclusive_creation(self):
        path = self.root / 'state' / 'alice.json'
        atomic_json(path, {'note': 'Ålice', 'revision': 1}, exclusive=True)
        self.assertEqual(read_private(path)['note'], 'Ålice')
        with self.assertRaises(FileExistsError):
            atomic_json(path, {'revision': 9}, exclusive=True)
        self.assertEqual(read_private(path)['revision'], 1)
        atomic_json(path, {'revision': 2})
        self.assertEqual(read_private(path), {'revision': 2})
        self.assertEqual(list(path.parent.glob('.write-*')), [])

    def test_failed_replace_preserves_previous_file_and_removes_temporary(self):
        path = self.root / 'alice.json'
        atomic_json(path, {'revision': 1})
        with patch('hal_fleet.local_files.os.replace', side_effect=OSError('fixture interruption')):
            with self.assertRaisesRegex(OSError, 'interruption'):
                atomic_json(path, {'revision': 2})
        self.assertEqual(read_private(path), {'revision': 1})
        self.assertEqual(list(self.root.glob('.write-*')), [])

    def test_private_reads_are_bounded_and_accept_utf8_bom(self):
        path = self.root / 'alice.json'
        write_private(path, b'\xef\xbb\xbf' + '{"note":"Å"}'.encode('utf-8'))
        self.assertEqual(read_private(path), {'note': 'Å'})
        with self.assertRaisesRegex(ValueError, 'size limit'):
            read_regular(path, private=True, maximum=4)

    @unittest.skipIf(os.name == 'nt', 'POSIX mode enforcement; Windows ACLs tested separately')
    def test_posix_permissions_and_symlink_checks_remain_enabled(self):
        path, link = self.root / 'alice.json', self.root / 'link.json'
        atomic_json(path, {'fixture': True})
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        link.symlink_to(path)
        with self.assertRaises(OSError):
            read_private(link)
        path.chmod(0o644)
        with self.assertRaisesRegex(Error, 'mode 600'):
            read_private(path)

    def test_relocated_deployment_ca_paths_keep_same_certificate(self):
        directory = self.root / 'state' / 'fleet-tls'
        directory.mkdir(parents=True)
        ca = directory / 'ca.pem'
        ca.write_bytes(b'public certificate fixture')
        config = directory / 'deployment.json'
        for old in ('ca.pem', '/missing/mac/path/ca.pem', r'C:\missing\old user\ca.pem'):
            with self.subTest(old=old):
                self.assertEqual(resolve_ca_file(config, old), str(ca.resolve()))
        self.assertEqual(resolve_ca_file(self.root/'state/alice.json', '/old/path/ca.pem'), str(ca.resolve()))
        with self.assertRaisesRegex(ValueError, 'CA certificate not found'):
            resolve_ca_file(config, '/missing/different.pem')

    def test_existing_explicit_ca_takes_precedence_over_fallback(self):
        expected = self.root / 'explicit.pem'
        expected.write_bytes(b'explicit')
        (self.root / 'ca.pem').write_bytes(b'fallback')
        self.assertEqual(resolve_ca_file(self.root/'deployment.json', str(expected)), str(expected.resolve()))

    def test_inventory_accepts_powershell_utf8_bom(self):
        value = dict(vms={role: dict(ip='192.0.2.' + str(i+1), ssh_user='tester') for i,role in enumerate(ROLES)})
        path = self.root / 'inventory.json'
        path.write_text(json.dumps(value), encoding='utf-8-sig')
        self.assertEqual(inventory(path), value)

    def test_source_archive_uses_linux_names_and_does_not_package_state(self):
        root = self.root / 'source'
        (root/'hal_fleet').mkdir(parents=True)
        file = root/'hal_fleet/client.py'
        file.write_bytes(b'# fixture\n')
        (root/'state').mkdir()
        (root/'state/alice.json').write_bytes(b'private fixture')
        output = self.root/'source.tar.gz'
        package(root, output)
        with tarfile.open(output) as archive:
            self.assertEqual(archive.getnames(), ['hal-on-demand/hal_fleet/client.py'])
            self.assertEqual(archive.getmembers()[0].mode, 0o644)
        # Exercise a Windows path object on POSIX as well as on Windows.
        with patch('hal_fleet.install.source_files', return_value=[(file, PureWindowsPath('hal_fleet/client.py'))]):
            package(root, self.root/'windows.tar.gz')
        with tarfile.open(self.root/'windows.tar.gz') as archive:
            self.assertEqual(archive.getnames(), ['hal-on-demand/hal_fleet/client.py'])

    def test_tls_archive_has_explicit_private_linux_modes(self):
        key = self.root/'execution.key'
        write_private(key, b'fixture key')
        memory = io.BytesIO()
        with tarfile.open(fileobj=memory, mode='w:gz') as archive:
            add_archive_file(archive, key, 'execution.key', private=True)
        memory.seek(0)
        with tarfile.open(fileobj=memory) as archive:
            self.assertEqual(archive.getmembers()[0].mode, 0o600)
            self.assertEqual(archive.extractfile('execution.key').read(), b'fixture key')

    def test_cli_creates_keys_and_certificates_without_a_local_host_binary(self):
        command = [sys.executable, '-B', str(ROOT/'fleet.py')]
        key = self.root/'operator.json'
        subprocess.run(command+['operator-key', '--output', str(key)], capture_output=True, text=True, check=True)
        self.assertEqual(len(read_private(key)['private_key']), 64)
        inv = self.root/'inventory.json'
        atomic_json(inv, dict(vms={role: dict(ip='192.0.2.'+str(i+1), ssh_user='tester') for i,role in enumerate(ROLES)}))
        subprocess.run(command+['certificates', '--inventory', str(inv), '--output', str(self.root/'tls')],
                       capture_output=True, text=True, check=True)
        self.assertIn(b'PRIVATE KEY', read_regular(self.root/'tls/ca-key.pem', private=True))
        for subcommand in ('onboard', 'run', 'bench', 'deploy', 'publish', 'result'):
            subprocess.run(command+[subcommand, '--help'], capture_output=True, text=True, check=True)

    def test_ssh_preserves_spaced_key_path_and_binary_stdin_without_local_shell(self):
        key = self.root/'a key'
        info = dict(vms={'identity': dict(ip='192.0.2.1', ssh_user='tester')})
        with patch('hal_fleet.install.subprocess.run', return_value=SimpleNamespace(stdout=b'ok\n')) as run:
            self.assertEqual(remote_command(info,key,'identity','cat',b'\x00\r\n\xff',True), 'ok\n')
        args, kwargs = run.call_args
        self.assertIn(str(key.resolve()), args[0])
        self.assertEqual(kwargs['input'], b'\x00\r\n\xff')
        self.assertFalse(kwargs.get('shell',False))


class WindowsAclDecisionTest(unittest.TestCase):
    """Decision tests run everywhere; these do not emulate the Windows kernel."""
    def check(self, entries, *, attributes=0, owner='user'):
        con = SimpleNamespace(FILE_ATTRIBUTE_DIRECTORY=16, FILE_ATTRIBUTE_REPARSE_POINT=1024, INHERIT_ONLY_ACE=8)
        files = SimpleNamespace(GetFileInformationByHandle=lambda _: (attributes,), GetFileType=lambda _: 1, FILE_TYPE_DISK=1)
        acl = None if entries is None else SimpleNamespace(GetAceCount=lambda:len(entries), GetAce=lambda i:entries[i])
        sd = SimpleNamespace(GetSecurityDescriptorOwner=lambda:owner, GetSecurityDescriptorDacl=lambda:acl)
        security = SimpleNamespace(SE_FILE_OBJECT=1, OWNER_SECURITY_INFORMATION=1, DACL_SECURITY_INFORMATION=4,
            ACCESS_ALLOWED_ACE_TYPE=0, ACCESS_DENIED_ACE_TYPE=1, ConvertSidToStringSid=lambda x:x, GetSecurityInfo=lambda *a:sd)
        api = (None,None,None,con,files,security)
        with patch('hal_fleet.local_files._windows_identity',return_value=('user',{'user','system','admin'})):
            _windows_check(42,'fixture.json',True,api)

    def test_accept_owner_and_os_accounts_and_reject_other_allow_entries(self):
        self.check([((0,0),1,'user'),((0,0),1,'system'),((0,0),1,'admin')])
        for other in ('everyone','users','another-user'):
            with self.subTest(other=other), self.assertRaisesRegex(ValueError,'grants access'):
                self.check([((0,0),1,'user'),((0,0),1,other)])

    def test_reject_null_acl_unexpected_owner_unknown_ace_and_reparse_points(self):
        for kwargs in ({'entries':None}, {'entries':[], 'owner':'another-user'},
                       {'entries':[((5,0),1,'user')]}, {'entries':[], 'attributes':1024},
                       {'entries':[], 'attributes':16}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.check(**kwargs)


class WindowsOpenContractTest(unittest.TestCase):
    """Exercise Windows-only call construction on every OS, with module-specific constants.

    Pywin32 b312 exposes FILE_FLAG_OPEN_REPARSE_POINT in win32file, not win32con.
    These small API substitutes intentionally do not invent missing attributes.
    Native ACL/filesystem tests below still require an actual Windows kernel.
    """
    def setUp(self):
        class Handle:
            def __init__(self):
                self.Close, self.Detach = Mock(), Mock()
            def __int__(self):
                return 123
        self.handle = Handle()
        self.crt = SimpleNamespace(open_osfhandle=Mock(return_value=71))
        self.con = SimpleNamespace(GENERIC_READ=0x80000000, GENERIC_WRITE=0x40000000,
            FILE_SHARE_READ=1, FILE_SHARE_DELETE=4, CREATE_NEW=1, OPEN_EXISTING=3,
            FILE_ATTRIBUTE_DIRECTORY=16, FILE_ATTRIBUTE_REPARSE_POINT=1024, INHERIT_ONLY_ACE=8)
        self.files = SimpleNamespace(CreateFile=Mock(return_value=self.handle),
            FILE_FLAG_OPEN_REPARSE_POINT=0x00200000, FILE_TYPE_DISK=1,
            GetFileType=Mock(return_value=1), GetFileInformationByHandle=Mock(return_value=(0,)))
        self.acl = SimpleNamespace(AddAccessAllowedAce=Mock(), GetAceCount=lambda:1,
                                  GetAce=lambda _:((0,0),0x1f01ff,'user'))
        self.descriptor = SimpleNamespace(SetSecurityDescriptorOwner=Mock(), SetSecurityDescriptorDacl=Mock(),
            SetSecurityDescriptorControl=Mock(), GetSecurityDescriptorOwner=lambda:'user',
            GetSecurityDescriptorDacl=lambda:self.acl)
        self.security = SimpleNamespace(ACL=lambda:self.acl, ACL_REVISION=2, SE_DACL_PROTECTED=4096,
            SECURITY_DESCRIPTOR=lambda:self.descriptor, SECURITY_ATTRIBUTES=SimpleNamespace,
            ConvertStringSidToSid=lambda value:value, ConvertSidToStringSid=lambda value:value,
            SE_FILE_OBJECT=1, OWNER_SECURITY_INFORMATION=1, DACL_SECURITY_INFORMATION=4,
            ACCESS_DENIED_ACE_TYPE=1, ACCESS_ALLOWED_ACE_TYPE=0,
            GetSecurityInfo=lambda *args:self.descriptor)
        api = (self.crt,SimpleNamespace(FILE_ALL_ACCESS=0x1f01ff),None,self.con,self.files,self.security)
        for patcher in (patch('hal_fleet.local_files._windows_api',return_value=api),
                        patch('hal_fleet.local_files._windows_identity',return_value=('user',{'user'})),
                        patch('hal_fleet.local_files.os.O_BINARY',0x8000,create=True)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_open_existing_uses_win32file_reparse_flag_and_transfers_handle(self):
        self.assertFalse(hasattr(self.con,'FILE_FLAG_OPEN_REPARSE_POINT'))
        self.assertEqual(_windows_open('alice.json'),71)
        self.files.CreateFile.assert_called_once_with('alice.json',0x80000000,5,None,3,0x00200000,None)
        self.handle.Detach.assert_called_once()
        self.handle.Close.assert_not_called()

    def test_create_sets_protected_dacl_before_open_with_reparse_flag(self):
        self.assertEqual(_windows_open('alice.json',create=True),71)
        args = self.files.CreateFile.call_args.args
        self.assertEqual((args[1],args[2],args[4],args[5]),(0xc0000000,5,1,0x00200000))
        self.assertIs(args[3].SECURITY_DESCRIPTOR,self.descriptor)
        self.assertFalse(args[3].bInheritHandle)
        self.descriptor.SetSecurityDescriptorControl.assert_called_once_with(4096,4096)

    def test_reparse_point_rejection_closes_handle_before_crt_transfer(self):
        self.files.GetFileInformationByHandle.return_value=(1024,)
        with self.assertRaisesRegex(ValueError,'reparse point'):
            _windows_open('link.json')
        self.handle.Close.assert_called_once()
        self.handle.Detach.assert_not_called()
        self.crt.open_osfhandle.assert_not_called()

    def test_win32_file_errors_are_translated_but_programming_errors_are_not(self):
        error=Exception('fixture access denied')
        error.winerror=5
        self.files.CreateFile.side_effect=error
        with self.assertRaisesRegex(PermissionError,'access denied'):
            _windows_open('alice.json')
        self.files.CreateFile.side_effect=AttributeError('fixture API bug')
        with self.assertRaisesRegex(AttributeError,'API bug'):
            _windows_open('alice.json')


class ClientWorkflowTest(unittest.TestCase):
    """Real CLI/signatures/authority/storage, in-memory transport and fake execution.

    This validates laptop paths and protocol compatibility, not Wasm execution.
    """
    setUp = PortableFilesTest.setUp

    def test_publish_onboard_renew_run_benchmark_result_and_relocation(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        import fleet
        from hal_fleet.authority import Authority
        from hal_fleet.common import Database, digest, parse, private_hex, public, verify_request
        from hal_fleet.policy import certificate, signed_job
        from hal_fleet.services import Files, Management

        issuer, operator = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        trust = dict(version=1,issuer='hal-identity',management_audience='hal-management',
            files_audience='hal-files',execution_audience='intel-worker-1',identity_public_key=public(issuer),
            operator_public_key=public(operator),endpoints={r:'https://'+r+'.invalid' for r in ROLES})
        apps = {}
        transport = Mock()
        transport.call.side_effect = lambda base,path,body=None,**kw: apps[base].handle('GET' if body is None else 'POST',path,body)
        configs, databases = {}, {}
        for role in ROLES:
            directory=self.root/role
            directory.mkdir()
            db=Database(directory/'db.sqlite3')
            self.addCleanup(db.close)
            databases[role]=db
            configs[role]=dict(role=role,trust=trust,state_dir=str(directory),
                identity_url=trust['endpoints']['identity'],execution_url=trust['endpoints']['execution'])
        identity_key=self.root/'identity/key.json'
        atomic_json(identity_key,{'private_key':private_hex(issuer)})
        configs['identity']['identity_key']=str(identity_key)
        apps[trust['endpoints']['identity']]=Authority(configs['identity'],databases['identity'])
        apps[trust['endpoints']['files']]=Files(configs['files'],databases['files'])
        apps[trust['endpoints']['management']]=Management(configs['management'],databases['management'],transport)

        class FakeExecution:
            mode='wasm'
            def handle(self, method, path, body):
                isolation='per-user-container' if self.mode=='wasm' else 'in-process'
                if path in ('/v1/enroll','/v1/session'):
                    req=verify_request(body,trust['execution_audience'],path.rsplit('/',1)[1],databases['execution'])
                    doc=certificate(req['body']['document'],configs['execution'])
                    assert req['public_key']==doc['public_key']
                    if path=='/v1/enroll':
                        return dict(enrolled=doc['subject'],revision=doc['revision'],workloads=len(doc['workloads']))
                    return dict(tenant=doc['subject'],audience=trust['execution_audience'],epoch='a'*64,
                                mode=self.mode,isolation=isolation)
                assert path=='/v1/run'
                doc=certificate(body['document'],configs['execution'])
                claims,row=signed_job(doc,body['job'],trust['execution_audience'],isolation,'a'*64)
                databases['execution'].consume('job',claims['job_id'])
                return dict(status='ok',tenant=doc['subject'],job_id=claims['job_id'],execution_mode=self.mode,
                    configuration=dict(workload_isolation=isolation,compile_opt_level='speed'),
                    workload_instance_reused=False,gateway_signature_checked=True,sha256=row['sha256'],
                    cache_policy=claims['cache'],cache_status='bypass' if claims['cache']=='bypass' else 'hit',
                    job_authorization=dict(verified=True),agent_result_validation='passed',
                    result=dict(hex=row['rule']['validation']['value']),timings_ms=dict(host_request=1))

        execution=FakeExecution()
        apps[trust['endpoints']['execution']]=execution
        operator_file=self.root/'operator.json'
        atomic_json(operator_file,{'private_key':private_hex(operator)})
        bootstrap=self.root/'state/fleet-tls/deployment.json'
        atomic_json(bootstrap,dict(endpoints=trust['endpoints'],issuer_sha256=digest(bytes.fromhex(public(issuer))),
                                   ca_file='/missing/mac/computer/ca.pem'))
        (bootstrap.parent/'ca.pem').write_bytes(b'public CA fixture; transport is mocked')
        client_file=self.root/'state/alice.json'

        def cli(*args):
            output=io.StringIO()
            with patch.object(sys,'argv',['fleet.py',*map(str,args)]), patch('sys.stdout',output), \
                    patch('hal_fleet.common.Transport',return_value=transport), \
                    patch('hal_fleet.client.Transport',return_value=transport):
                self.assertEqual(fleet.main(),0)
            return json.loads(output.getvalue())

        cli('publish','--operator',operator_file,'--deployment',bootstrap,'--manifest',ROOT/'benchmarks/artifacts/manifest.json')
        args=('onboard','--user','alice','--deployment',bootstrap,'--output',client_file,'--workloads','all')
        self.assertEqual(len(cli(*args)['approved']),15)
        before=read_private(client_file)['private_key']
        # Model an existing client config copied from a different OS/computer.
        moved=read_private(client_file)
        moved['ca_file']=r'C:\missing\old computer\ca.pem'
        atomic_json(client_file,moved)
        cli('renew','--client',client_file)
        cli(*args)
        self.assertEqual(read_private(client_file)['private_key'],before)
        self.assertEqual(len(cli('catalog','--client',client_file)['workloads']),15)
        job=cli('run','--client',client_file,'--workload','matrix-multiply','--cache','reuse')
        self.assertEqual(job['client_result_validation'],'passed')
        saved=cli('result','--client',client_file,'--job-id',job['job_id'])
        self.assertEqual(saved['status'],'completed')
        # Legacy service responses intentionally cannot enter the new audited
        # benchmark population; ordinary legacy run/result commands still work.
        from hal_fleet.common import Error
        with self.assertRaisesRegex(Error, 'Update management'):
            cli('bench','--client',client_file,'--workloads','matrix-multiply','--jobs','2',
                '--concurrency','1','--cache','bypass','--output',self.root/'results')
        execution.mode='native'
        job=cli('run','--client',client_file,'--workload','matrix-multiply','--cache','bypass',
                '--expect-mode','native','--expect-isolation','in-process')
        self.assertEqual(job['status'],'completed')


@unittest.skipUnless(os.name == 'nt', 'Requires a real Windows kernel and pywin32')
class NativeWindowsTest(unittest.TestCase):
    setUp = PortableFilesTest.setUp
    def test_windows_dacl_is_protected_on_create_and_atomic_replace(self):
        import win32security as security
        path=self.root/'alice.json'
        for revision in (1,2):
            atomic_json(path,{'revision':revision})
            self.assertEqual(read_private(path)['revision'],revision)
            sd=security.GetNamedSecurityInfo(str(path),security.SE_FILE_OBJECT,security.DACL_SECURITY_INFORMATION)
            self.assertTrue(sd.GetSecurityDescriptorControl()[0] & security.SE_DACL_PROTECTED)

    def test_windows_file_with_everyone_read_is_rejected(self):
        import ntsecuritycon
        import win32security as security
        path=self.root/'alice.json'
        atomic_json(path,{'fixture':True})
        sd=security.GetNamedSecurityInfo(str(path),security.SE_FILE_OBJECT,security.DACL_SECURITY_INFORMATION)
        acl=sd.GetSecurityDescriptorDacl()
        acl.AddAccessAllowedAce(security.ACL_REVISION,ntsecuritycon.FILE_GENERIC_READ,
                               security.ConvertStringSidToSid('S-1-1-0'))
        security.SetNamedSecurityInfo(str(path),security.SE_FILE_OBJECT,
                                     security.DACL_SECURITY_INFORMATION | security.PROTECTED_DACL_SECURITY_INFORMATION,
                                     None,None,acl,None)
        with self.assertRaisesRegex(Error,'grants access'):
            read_private(path)

    def test_windows_service_commands_fail_with_linux_guidance(self):
        result=subprocess.run([sys.executable,'-B',str(ROOT/'fleet.py'),'serve'],capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('Linux service VM',result.stderr)


if __name__=='__main__':
    unittest.main(verbosity=2)
