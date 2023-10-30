import logging
import unittest
from scanning.vuln_scan import VulnScan
import os
import json


class TestVulnScan(unittest.TestCase):

    @classmethod
    def setup(cls, target):
        cls.scanner = VulnScan(target, log_level=logging.WARNING)
        cls.scanner._results = {"test": "test"}
        cls.results_dir = 'tests/test_files/results'

    def test_output_file_is_created(self):
        self.setup('test_target')
        self.scanner._output(directory=self.results_dir)
        self.assertTrue(os.path.exists(f'{self.results_dir}/{self.scanner._target}/{self.scanner._target}_vuln_scan.json'))

    def test_output_contents(self):
        self.setup('test_target')
        self.scanner._output(directory=self.results_dir)
        with open(f'{self.results_dir}/{self.scanner._target}/{self.scanner._target}_vuln_scan.json', 'r') as f:
            self.assertEqual(self.scanner._results, json.load(f))

    def test_get_results_ok(self):
        self.setup('test_target')
        with open(f'{self.results_dir}/{self.scanner._target}/{self.scanner._target}_vuln_scan.json', 'r') as f:
            self.assertEqual(self.scanner._get_results(directory=self.results_dir), json.load(f))

    def test_get_results_not_ok(self):
        self.setup('test_target')
        with self.assertRaises(FileNotFoundError) as error:
            self.scanner._get_results(directory='not_a_directory')
        self.assertEqual(error.exception.args[1], 'No such file or directory')

    def test_has_results(self):
        self.setup('test_target')
        self.assertTrue(self.scanner._has_results(directory=self.results_dir))

    def test_has_results_not_ok(self):
        self.setup('test_target')
        self.assertFalse(self.scanner._has_results(directory='not_a_directory'))

    def test_get_cves(self):
        self.scanner = VulnScan('192.168.0.1/24', log_level=logging.WARNING)
        self.results_dir = 'tests/test_files/results'

        with open(
            f'tests/test_files/{self.scanner._safe_target}/{self.scanner._safe_target}_cves.json',
            'r',
        ) as f:
            expected = json.load(f)

        with open(
            f'tests/test_files/{self.scanner._safe_target}/{self.scanner._safe_target}_vuln_scan.json',
            'r',
        ) as f:
            self.scanner._results = json.load(f)
            self.scanner.get_cves(directory=self.results_dir)

        with open(
            f'tests/test_files/{self.scanner._safe_target}/{self.scanner._safe_target}_cves.json',
            'r',
        ) as f:
            results = json.load(f)

        self.assertEqual(results, expected)
