import bz2
import enum
import importlib
import io
import os
import plistlib
import struct
import sys
import tempfile
import types
import unittest
from types import SimpleNamespace
from unittest import mock


def _install_plugin_import_stubs():
    macinfo_stub = types.ModuleType('plugins.helpers.macinfo')

    class EntryType(enum.IntEnum):
        FILES = 1
        FOLDERS = 2
        FILES_AND_FOLDERS = 3

    macinfo_stub.EntryType = EntryType
    sys.modules['plugins.helpers.macinfo'] = macinfo_stub

    writer_stub = types.ModuleType('plugins.helpers.writer')

    class DataType(enum.IntEnum):
        INTEGER = 1
        REAL = 2
        TEXT = 3
        BLOB = 4
        DATE = 5

    writer_stub.DataType = DataType
    writer_stub.WriteList = lambda *args, **kwargs: None
    sys.modules['plugins.helpers.writer'] = writer_stub


_install_plugin_import_stubs()

codesign_offline = importlib.import_module('plugins.helpers.codesign_offline')
pystartup = importlib.import_module('plugins.pystartup')
macho_offline = importlib.import_module('plugins.helpers.macho_offline')
persistence_common = importlib.import_module('plugins.helpers.persistence_common')
app_bundle_discovery = importlib.import_module('plugins.helpers.app_bundle_discovery')
injection = importlib.import_module('plugins.injection')
helpertools = importlib.import_module('plugins.helpertools')
sshpersist = importlib.import_module('plugins.sshpersist')
pkgscripts = importlib.import_module('plugins.pkgscripts')
emondpersist = importlib.import_module('plugins.emondpersist')
extpersist = importlib.import_module('plugins.extpersist')
pluginpersist = importlib.import_module('plugins.pluginpersist')

MAIN_INDEX = {
    name: idx for idx, name in enumerate(persistence_common.MAIN_TABLE_COLUMNS)
}
DETAIL_INDEX = {
    name: idx for idx, name in enumerate(persistence_common.DETAIL_TABLE_COLUMNS)
}


class FakeMacInfo:
    def __init__(self, files=None, folders=None, listings=None, file_bytes=None,
                 sizes=None, plists=None):
        self.files = set(files or [])
        self.folders = set(folders or [])
        self.listings = listings or {}
        self.file_bytes = file_bytes or {}
        self.sizes = sizes or {}
        self.plists = plists or {}

    def IsValidFilePath(self, path):
        return path in self.files or path in self.file_bytes or path in self.plists or os.path.isfile(path)

    def IsValidFolderPath(self, path):
        return path in self.folders

    def ListItemsInFolder(self, path, entry_type, include_dates=False):
        return list(self.listings.get(path, []))

    def ExportFile(self, *args, **kwargs):
        return None

    def Open(self, path):
        if path in self.file_bytes:
            return io.BytesIO(self.file_bytes[path])
        if os.path.isfile(path):
            return open(path, 'rb')
        return None

    def ReadPlist(self, path):
        if path in self.plists:
            return True, self.plists[path], ''
        return False, None, 'missing'

    def GetFileMACTimes(self, path):
        return {}

    def GetFileSize(self, path):
        if path in self.sizes:
            return self.sizes[path]
        if path in self.file_bytes:
            return len(self.file_bytes[path])
        if os.path.isfile(path):
            return os.path.getsize(path)
        return 0


class PersistenceFindingTests(unittest.TestCase):
    @staticmethod
    def _build_macho64_slice(has_code_signature):
        magic = 0xFEEDFACF
        cputype = 0x01000007
        cpusubtype = 3
        filetype = 2
        ncmds = 1
        sizeofcmds = 16
        flags = 0
        reserved = 0
        header = struct.pack(
            '<8I', magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved)
        cmd = macho_offline.LC_CODE_SIGNATURE if has_code_signature else macho_offline.LC_LOAD_DYLIB
        load_cmd = struct.pack('<4I', cmd, 16, 24, 0)
        return header + load_cmd

    def test_codesign_status_classification(self):
        self.assertEqual(
            codesign_offline._classify_binary_codesign_status(None, '/bin/test', 'TEAMID1234'),
            'signed',
        )

        with mock.patch.object(
            codesign_offline,
            'parse_macho_from_mac_info',
            return_value=SimpleNamespace(parse_error='', arches=[object()], has_code_signature=True),
        ):
            self.assertEqual(
                codesign_offline._classify_binary_codesign_status(None, '/bin/test', ''),
                'signed',
            )

        with mock.patch.object(
            codesign_offline,
            'parse_macho_from_mac_info',
            return_value=SimpleNamespace(parse_error='', arches=[object()], has_code_signature=False),
        ):
            self.assertEqual(
                codesign_offline._classify_binary_codesign_status(None, '/bin/test', ''),
                'unsigned',
            )

    def test_scope_from_path_classifies_system_and_user_paths(self):
        self.assertEqual(
            persistence_common.get_scope_from_path('/Applications/Foo.app'),
            'system',
        )
        self.assertEqual(
            persistence_common.get_scope_from_path('/Users/alice/Applications/Foo.app'),
            'user',
        )

    def test_injection_scope_uses_owner_path(self):
        fake_mac = FakeMacInfo()
        main_rows = []
        detail_rows = []
        fake_macho = SimpleNamespace(
            parse_error='',
            arches=[object()],
            has_code_signature=False,
            dylibs=[SimpleNamespace(path='/tmp/inject.dylib', load_type='required')],
        )

        with mock.patch.object(injection, 'parse_macho_from_mac_info', return_value=fake_macho):
            injection.scan_binary_for_injection(
                fake_mac,
                '/Applications/Foo.app/Contents/MacOS/Foo',
                '/Applications/Foo.app',
                'com.example.foo',
                main_rows,
                detail_rows,
            )

        self.assertEqual(main_rows[0][MAIN_INDEX['Scope']], 'system')

    def test_injection_owner_context_sets_user_and_uid(self):
        fake_mac = FakeMacInfo()
        main_rows = []
        detail_rows = []
        fake_macho = SimpleNamespace(
            parse_error='',
            arches=[object()],
            has_code_signature=False,
            dylibs=[SimpleNamespace(path='/tmp/inject.dylib', load_type='required')],
        )

        with mock.patch.object(injection, 'parse_macho_from_mac_info', return_value=fake_macho):
            injection.scan_binary_for_injection(
                fake_mac,
                '/Users/alice/Applications/Foo.app/Contents/MacOS/Foo',
                '/Users/alice/Applications/Foo.app',
                'com.example.foo',
                main_rows,
                detail_rows,
                'user',
                'alice',
                '501',
            )

        self.assertEqual(main_rows[0][MAIN_INDEX['Scope']], 'user')
        self.assertEqual(main_rows[0][MAIN_INDEX['User']], 'alice')
        self.assertEqual(main_rows[0][MAIN_INDEX['UID']], '501')

    def test_lsenvironment_scope_uses_bundle_path(self):
        info_plist_path = '/Applications/Foo.app/Contents/Info.plist'
        fake_mac = FakeMacInfo(plists={
            info_plist_path: {'LSEnvironment': {'DYLD_INSERT_LIBRARIES': '/tmp/inject.dylib'}}
        })
        main_rows = []
        detail_rows = []

        injection.scan_app_for_lsenvironment(
            fake_mac,
            '/Applications/Foo.app',
            'com.example.foo',
            main_rows,
            detail_rows,
        )

        self.assertEqual(main_rows[0][MAIN_INDEX['Scope']], 'system')

    def test_curated_app_bundle_contexts_preserve_user_owner(self):
        fake_mac = FakeMacInfo(
            folders={
                '/Applications',
                '/Users/alice/Applications',
            },
            listings={
                '/Applications': [{'name': 'SystemApp.app'}],
                '/Users/alice/Applications': [{'name': 'UserApp.app'}],
            },
        )
        fake_mac.users = [
            SimpleNamespace(user_name='alice', home_dir='/Users/alice', UID='501')
        ]

        contexts = {
            entry['bundle_path']: entry
            for entry in app_bundle_discovery.list_curated_app_bundle_contexts(fake_mac)
        }

        self.assertEqual(contexts['/Applications/SystemApp.app']['scope'], 'system')
        self.assertEqual(contexts['/Applications/SystemApp.app']['user'], '')
        self.assertEqual(contexts['/Users/alice/Applications/UserApp.app']['scope'], 'user')
        self.assertEqual(contexts['/Users/alice/Applications/UserApp.app']['user'], 'alice')
        self.assertEqual(contexts['/Users/alice/Applications/UserApp.app']['uid'], '501')

    def test_helpertools_launchservices_scope_uses_owner_path(self):
        owner_app_path = '/Users/alice/Applications/Foo.app'
        ls_dir = owner_app_path + '/Contents/Library/LaunchServices'
        helper_path = ls_dir + '/FooHelper'
        fake_mac = FakeMacInfo(
            folders={ls_dir},
            listings={ls_dir: [{'name': 'FooHelper'}]},
        )
        main_rows = []
        detail_rows = []

        with mock.patch.object(
            helpertools,
            'get_binary_codesign_info',
            return_value=SimpleNamespace(team_id='', codesign_status='unknown', sha256=''),
        ):
            helpertools.process_launchservices_helpers(
                fake_mac,
                owner_app_path,
                'com.example.foo',
                main_rows,
                detail_rows,
            )

        self.assertEqual(main_rows[0][MAIN_INDEX['Scope']], 'user')
        self.assertEqual(main_rows[0][MAIN_INDEX['ArtifactPath']], helper_path)

    def test_sshpersist_keeps_sha256_empty_for_authorized_keys(self):
        authkeys_path = '/tmp/authorized_keys'
        fake_mac = FakeMacInfo(file_bytes={
            authkeys_path: (
                b'command="/bin/echo hi" ssh-ed25519 '
                b'AAAAC3NzaC1lZDI1NTE5AAAAIGh0estkeymaterial user@test\n'
            )
        })
        main_rows = []
        detail_rows = []
        sshpersist.process_authorized_keys(
            fake_mac, authkeys_path, 'alice', '501', main_rows, detail_rows
        )

        self.assertEqual(main_rows[0][MAIN_INDEX['SHA256']], '')
        fingerprints = [
            row[DETAIL_INDEX['Value']]
            for row in detail_rows
            if row[DETAIL_INDEX['EvidenceType']] == 'key_fingerprint'
        ]
        self.assertEqual(len(fingerprints), 1)
        self.assertTrue(fingerprints[0].startswith('SHA256:'))

    def test_pkgscripts_skips_oversized_package_rows(self):
        fake_mac = FakeMacInfo(
            files={'/tmp/large.pkg'},
            sizes={'/tmp/large.pkg': pkgscripts.MAX_PKG_PARSE_BYTES + 1},
        )
        main_rows = []
        detail_rows = []

        pkgscripts.process_pkg_file(fake_mac, '/tmp/large.pkg', 'alice', '501', main_rows, detail_rows)

        self.assertEqual(main_rows, [])
        self.assertEqual(detail_rows, [])

    def test_pkgscripts_uses_bzip2_decoder(self):
        payload = b'#!/bin/sh\necho hello\n'
        compressed = bz2.compress(payload)
        extracted = pkgscripts._extract_xar_file(
            compressed, 0, 0, len(compressed), 'application/x-bzip2'
        )
        self.assertEqual(extracted, payload)

    def test_emond_only_runcommand_emits_main_rows(self):
        plist_data = [{
            'name': 'rule-one',
            'conditions': [{'type': 'startup'}],
            'actions': [
                {'type': 'RunCommand', 'command': '/bin/echo', 'arguments': ['hi']},
                {'type': 'Log', 'message': 'ignored in main table'},
            ],
        }]

        with tempfile.TemporaryDirectory() as temp_dir:
            plist_path = os.path.join(temp_dir, 'rule.plist')
            with open(plist_path, 'wb') as handle:
                plistlib.dump(plist_data, handle)

            main_rows = []
            detail_rows = []
            emondpersist.process_emond_rule_file(None, plist_path, main_rows, detail_rows)

        self.assertEqual(len(main_rows), 1)
        self.assertEqual(main_rows[0][MAIN_INDEX['TargetPath']], '/bin/echo')
        self.assertGreaterEqual(len(detail_rows), 2)

    def test_extpersist_picks_latest_chromium_version_deterministically(self):
        ext_id_dir = '/Users/alice/Library/Application Support/Google/Chrome/Default/Extensions/extid'
        manifest_paths = {
            ext_id_dir + '/1.2/manifest.json': b'{"name": "Version 1.2"}',
            ext_id_dir + '/1.10/manifest.json': b'{"name": "Version 1.10"}',
            ext_id_dir + '/0.9/manifest.json': b'{"name": "Version 0.9"}',
        }
        fake_mac = FakeMacInfo(
            file_bytes=manifest_paths,
            listings={
                ext_id_dir: [
                    {'name': '1.2'},
                    {'name': '1.10'},
                    {'name': '0.9'},
                ]
            },
        )
        main_rows = []
        detail_rows = []

        extpersist._process_chromium_extension_id(
            fake_mac, ext_id_dir, 'extid', 'alice', '501', main_rows, detail_rows
        )

        self.assertEqual(len(main_rows), 1)
        self.assertEqual(main_rows[0][MAIN_INDEX['LabelOrName']], 'Version 1.10')
        self.assertTrue(main_rows[0][MAIN_INDEX['ArtifactPath']].endswith('/1.10'))

    def test_pluginpersist_dirs_exclude_editor_autoload(self):
        self.assertFalse(any('/autoload' in rel_path for rel_path, _, _ in pluginpersist.USER_PLUGIN_DIRS))

    def test_pluginpersist_standalone_skips_editor_autoload_paths(self):
        output_params = SimpleNamespace()

        with mock.patch.object(pluginpersist, 'write_output') as write_output:
            pluginpersist.Plugin_Start_Standalone(
                ['/Users/alice/.config/nvim/autoload/example.vim'],
                output_params,
            )

        write_output.assert_not_called()

    def test_pluginpersist_standalone_keeps_real_editor_plugin_paths(self):
        output_params = SimpleNamespace()

        with mock.patch.object(pluginpersist, 'write_output') as write_output:
            pluginpersist.Plugin_Start_Standalone(
                ['/Users/alice/.config/nvim/plugin/example.vim'],
                output_params,
            )

        write_output.assert_called_once()

    def test_find_main_binary_fallback_is_deterministic(self):
        bundle_path = '/Apps/Foo.app'
        macos_dir = bundle_path + '/Contents/MacOS'
        plist = {'CFBundleName': 'Main'}

        first = FakeMacInfo(
            folders={macos_dir},
            listings={macos_dir: [{'name': 'Helper'}, {'name': 'Main'}]},
        )
        second = FakeMacInfo(
            folders={macos_dir},
            listings={macos_dir: [{'name': 'Main'}, {'name': 'Helper'}]},
        )

        expected = bundle_path + '/Contents/MacOS/Main'
        self.assertEqual(codesign_offline._find_main_binary(first, bundle_path, plist), expected)
        self.assertEqual(codesign_offline._find_main_binary(second, bundle_path, plist), expected)

    def test_pystartup_finds_library_python_version_dir(self):
        base_dir = '/Users/alice/Library/Python'
        site_packages = base_dir + '/3.11/lib/python/site-packages'
        fake_mac = FakeMacInfo(
            folders={base_dir, site_packages},
            listings={base_dir: [{'name': '3.11'}]},
        )

        self.assertEqual(
            list(pystartup._find_site_packages_dirs(fake_mac, base_dir)),
            [site_packages],
        )

    def test_parse_macho_from_mac_info_reads_late_fat_slices(self):
        arch1 = self._build_macho64_slice(False)
        arch2 = self._build_macho64_slice(True)
        arch1_offset = 0x1000
        arch2_offset = macho_offline.MAX_LOAD_CMD_READ_BYTES + 0x10000

        fat_header = struct.pack('>II', macho_offline.FAT_MAGIC, 2)
        fat_arch1 = struct.pack('>IIIII', 0x01000007, 3, arch1_offset, len(arch1), 12)
        fat_arch2 = struct.pack('>IIIII', 0x0100000C, 0, arch2_offset, len(arch2), 12)

        data = bytearray(arch2_offset + len(arch2))
        data[:8] = fat_header
        data[8:28] = fat_arch1
        data[28:48] = fat_arch2
        data[arch1_offset:arch1_offset + len(arch1)] = arch1
        data[arch2_offset:arch2_offset + len(arch2)] = arch2

        fake_mac = FakeMacInfo(file_bytes={'/tmp/fatbin': bytes(data)})
        info = macho_offline.parse_macho_from_mac_info(fake_mac, '/tmp/fatbin')

        self.assertTrue(info.is_fat)
        self.assertEqual(len(info.arches), 2)
        self.assertTrue(info.has_code_signature)


if __name__ == '__main__':
    unittest.main()
