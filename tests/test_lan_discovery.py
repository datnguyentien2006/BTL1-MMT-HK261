import socket
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'btl_btlmmt'))
from web_ui.lan import invitation_info


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        interfaces = {
            'VMware VMnet8': ('192.168.133.1', True),
            'Wi-Fi': ('192.168.1.31', True),
            'Disconnected Ethernet': ('10.0.0.20', False),
            'Loopback': ('127.0.0.1', True),
            'No DHCP': ('169.254.10.20', True),
        }
        stats = {name: SimpleNamespace(isup=up) for name, (_, up) in interfaces.items()}
        addresses = {name: [SimpleNamespace(family=socket.AF_INET, address=ip)]
                     for name, (ip, _) in interfaces.items()}
        self.stats = patch('web_ui.lan.psutil.net_if_stats', return_value=stats)
        self.addresses = patch('web_ui.lan.psutil.net_if_addrs', return_value=addresses)
        self.stats.start()
        self.addresses.start()
        self.addCleanup(self.stats.stop)
        self.addCleanup(self.addresses.stop)

    def test_physical_interface_first_without_external_probe(self):
        with patch('socket.socket', side_effect=AssertionError('No network probe permitted')):
            info = invitation_info('0.0.0.0', 8765)
        self.assertEqual([entry['ip'] for entry in info['addresses']],
                         ['192.168.1.31', '192.168.133.1'])
        self.assertEqual(info['addresses'][0]['url'], 'http://192.168.1.31:8765')

    def test_actual_request_destination_first(self):
        info = invitation_info('0.0.0.0', 5000, '192.168.133.1')
        self.assertEqual(info['addresses'][0]['ip'], '192.168.133.1')

    def test_loopback_listener_never_advertises_lan(self):
        self.assertEqual(invitation_info('127.0.0.1', 5000),
                         {'local_only': True, 'addresses': []})

    def test_specific_bind_only_advertises_bound_address(self):
        info = invitation_info('192.168.133.1', 5000)
        self.assertEqual(len(info['addresses']), 1)
        self.assertEqual(info['addresses'][0]['ip'], '192.168.133.1')

    def test_discovery_failure_retains_successful_request_destination(self):
        with patch('web_ui.lan.psutil.net_if_stats', side_effect=OSError('Unavailable')):
            info = invitation_info('0.0.0.0', 5000, '192.168.1.31')
        self.assertEqual(info['addresses'][0]['url'], 'http://192.168.1.31:5000')
