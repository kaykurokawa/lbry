# -*- coding: utf-8 -*-
"""
To create local builds and distributable .msi, run the following command:
python setup_win32.py build bdist_msi
"""
import opcode
import os
import pkg_resources
import sys

from cx_Freeze import setup, Executable
import requests.certs

from lbrynet import __version__

name = 'LBRY'
description = 'A decentralized media library and marketplace'
win_icon = os.path.join('packaging', 'windows', 'lbry-win32-app', 'icons', 'lbry256.ico')
wordlist_path = pkg_resources.resource_filename('lbryum', 'wordlist')

base_dir = os.path.abspath(os.path.dirname(__file__))

# Allow virtualenv to find distutils of base python installation
distutils_path = os.path.join(os.path.dirname(opcode.__file__), 'distutils')


def find_data_file(filename):
    if getattr(sys, 'frozen', False):
        # The application is frozen
        data_dir = os.path.dirname(sys.executable)
    else:
        # The application is not frozen
        # Change this bit to match where you store your data files:
        data_dir = os.path.dirname(__file__)
    return os.path.join(data_dir, filename)

console_scripts = ['lbrynet-stdin-uploader = lbrynet.lbrynet_console.LBRYStdinUploader:launch_stdin_uploader',
                  'lbrynet-stdout-downloader = lbrynet.lbrynet_console.LBRYStdoutDownloader:launch_stdout_downloader',
                  'lbrynet-create-network = lbrynet.create_network:main',
                  'lbrynet-launch-node = lbrynet.dht.node:main',
                  'lbrynet-launch-rpc-node = lbrynet.rpc_node:main',
                  'lbrynet-rpc-node-cli = lbrynet.node_rpc_cli:main',
                  'lbrynet-lookup-hosts-for-hash = lbrynet.dht_scripts:get_hosts_for_hash_in_dht',
                  'lbrynet-announce_hash_to_dht = lbrynet.dht_scripts:announce_hash_to_dht',
                  'lbrynet-daemon = lbrynet.lbrynet_daemon.LBRYDaemonControl:start',
                  'stop-lbrynet-daemon = lbrynet.lbrynet_daemon.LBRYDaemonControl:stop',
                  'lbrynet-cli = lbrynet.lbrynet_daemon.LBRYDaemonCLI:main']

# shortcut_table = [
#     ('DesktopShortcut',  # Shortcut
#      'DesktopFolder',  # Directory
#      name,  # Name
#      'TARGETDIR',  # Component
#      '[TARGETDIR]\{0}.exe'.format(name),  # Target
#      None,  # Arguments
#      description,  # Description
#      None,  # Hotkey
#      win_icon,  # Icon (doesn't work for some reason?)
#      None,  # IconIndex
#      None,  # ShowCmd
#      'TARGETDIR',  # WkDir
#      ),
#     ]
#
# msi_data = {'Shortcut': shortcut_table}

bdist_msi_options = {
    'upgrade_code': '{18c0e933-ad08-44e8-a413-1d0ed624c100}',
    'add_to_path': False,
    # Default install path is 'C:\Program Files\' for 32-bit or 'C:\Program Files (x86)\' for 64-bit
    # 'initial_target_dir': r'[LocalAppDataFolder]\{0}'.format(name),
    # 'data': msi_data
    }

build_exe_options = {
    'include_msvcr': True,
    'includes': [],
    'packages': ['cython',
                 'twisted',
                 'yapsy',
                 'appdirs',
                 'argparse',
                 'base58',
                 'colorama',
                 'cx_Freeze',
                 'dns',
                 'ecdsa',
                 'gmpy',
                 'googlefinance',
                 'jsonrpc',
                 'jsonrpclib',
                 'lbryum',
                 'loggly',
                 'miniupnpc',
                 'pbkdf2',
                 'google.protobuf',
                 'Crypto',
                 'bitcoinrpc',
                 'win32api',
                 'qrcode',
                 'requests',
                 'requests_futures',
                 'seccure',
                 'simplejson',
                 'six',
                 'aes',
                 'txjsonrpc',
                 'unqlite',
                 'wsgiref',
                 'zope.interface',
                 'os',
                 'pkg_resources'
                 ],
    'excludes': ['distutils', 'collections.sys', 'collections._weakref', 'collections.abc',
                 'Tkinter', 'tk', 'tcl', 'PyQt4', 'nose', 'mock'
                 'zope.interface._zope_interface_coptimizations'],
    'include_files': [(distutils_path, 'distutils'), (requests.certs.where(), 'cacert.pem'),
                      (os.path.join('packaging', 'windows', 'lbry-win32-app', 'icons', 'lbry16.ico'),
                       os.path.join('icons', 'lbry16.ico')),
                      (os.path.join(wordlist_path, 'chinese_simplified.txt'),
                       os.path.join('wordlist', 'chinese_simplified.txt')),
                      (os.path.join(wordlist_path, 'english.txt'), os.path.join('wordlist', 'english.txt')),
                      (os.path.join(wordlist_path, 'japanese.txt'), os.path.join('wordlist', 'japanese.txt')),
                      (os.path.join(wordlist_path, 'portuguese.txt'), os.path.join('wordlist', 'portuguese.txt')),
                      (os.path.join(wordlist_path, 'spanish.txt'), os.path.join('wordlist', 'spanish.txt'))
                      ],
    'namespace_packages': ['zope', 'google']}

exe = Executable(
    script=os.path.join('packaging', 'windows', 'lbry-win32-app', 'LBRYWin32App.py'),
    base='Win32GUI',
    icon=win_icon,
    compress=True,
    shortcutName=name,
    shortcutDir='DesktopFolder',
    targetName='{0}.exe'.format(name)
    # targetDir="LocalAppDataFolder"
    )

setup(
    name=name,
    version=__version__,
    description=name + ": " + description,
    url='lbry.io',
    author='LBRY, Inc.',
    keywords='LBRY',
    data_files=[],
    options={'build_exe': build_exe_options,
             'bdist_msi': bdist_msi_options},
    executables=[exe],
    )
