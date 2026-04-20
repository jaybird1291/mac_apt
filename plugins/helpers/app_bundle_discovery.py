'''
   Copyright (c) 2026 jaybird1291

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

   app_bundle_discovery.py
   -----------------------
   Shared shallow app bundle discovery for persistence-focused plugins.
'''

import logging
from collections import deque

from plugins.helpers.macinfo import EntryType
from plugins.helpers.persistence_common import safe_user_label

log = logging.getLogger('MAIN.HELPERS.APPBUNDLEDISCOVERY')

SYSTEM_APP_ROOTS = (
    '/Applications',
    '/Library/Applications',
    '/Applications/Setapp',
)


def _iter_curated_roots(mac_info):
    for root in SYSTEM_APP_ROOTS:
        yield {
            'root': root,
            'scope': 'system',
            'user': '',
            'uid': '',
        }

    processed_homes = set()
    for user in mac_info.users:
        user_name = safe_user_label(user.user_name, user.home_dir)
        if not user_name:
            continue
        if user.home_dir in processed_homes:
            continue
        processed_homes.add(user.home_dir)
        user_context = {
            'scope': 'user',
            'user': user_name,
            'uid': str(user.UID) if user.UID not in ('', None) else '',
        }
        yield {
            'root': user.home_dir + '/Applications',
            **user_context,
        }
        yield {
            'root': user.home_dir + '/Desktop',
            **user_context,
        }


def list_curated_app_bundle_contexts(mac_info, max_depth=2):
    '''Return shallow-discovered .app bundle paths with owner attribution context.'''
    bundle_contexts = []
    seen_bundles = set()
    seen_dirs = set()

    for root_info in _iter_curated_roots(mac_info):
        root = root_info['root']
        if root in seen_dirs or not mac_info.IsValidFolderPath(root):
            continue
        queue = deque([(root, 0)])
        seen_dirs.add(root)

        while queue:
            directory, depth = queue.popleft()
            try:
                items = mac_info.ListItemsInFolder(directory, EntryType.FOLDERS, False)
            except Exception:
                continue

            for item in sorted(items, key=lambda x: x['name'].lower()):
                name = item['name']
                if not name or name.startswith('.'):
                    continue
                item_path = directory + '/' + name
                if name.endswith('.app'):
                    if item_path not in seen_bundles:
                        seen_bundles.add(item_path)
                        bundle_contexts.append({
                            'bundle_path': item_path,
                            'scope': root_info['scope'],
                            'user': root_info['user'],
                            'uid': root_info['uid'],
                        })
                    continue
                if depth >= max_depth:
                    continue
                if item_path not in seen_dirs and mac_info.IsValidFolderPath(item_path):
                    seen_dirs.add(item_path)
                    queue.append((item_path, depth + 1))

    return bundle_contexts


def list_curated_app_bundles(mac_info, max_depth=2):
    '''Return shallow-discovered .app bundle paths from curated common roots.'''
    return [
        bundle_context['bundle_path']
        for bundle_context in list_curated_app_bundle_contexts(mac_info, max_depth)
    ]
