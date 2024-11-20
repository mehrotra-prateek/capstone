#!/usr/bin/env python
import unittest
from unittest.mock import patch, MagicMock
import pandas as pd
import requests
from capstone.cvss import (
    read_csv_pandas,
    get_cve_cvss,
    process_cisa_vulnerabilities,
    process_cisa_vulnerabilities_to_df
)


class TestCVSSFunctions(unittest.TestCase):
    """Test cases for CVSS functions"""

    def setUp(self):
        """Set up test fixtures"""
        # Sample data for testing
        self.test_data = {
            'cveID': ['CVE-2021-1234', 'CVE-2021-5678'],
            'vendorProject': ['Test Vendor', 'Test Project'],
            'product': ['Product A', 'Product B']
        }
        self.test_df = pd.DataFrame(self.test_data)

    def test_read_csv_pandas_file_not_found(self):
        """Test read_csv_pandas with non-existent file"""
        result = read_csv_pandas('nonexistent.csv')
        self.assertIsNone(result)

    @patch('pandas.read_csv')
    def test_read_csv_pandas_success(self, mock_read_csv):
        """Test read_csv_pandas with successful read"""
        mock_read_csv.return_value = self.test_df
        result = read_csv_pandas('test.csv')
        self.assertIsInstance(result, pd.DataFrame)
        self.assertEqual(len(result), 2)

    @patch('pandas.read_csv')
    def test_read_csv_pandas_empty_file(self, mock_read_csv):
        """Test read_csv_pandas with empty file"""
        mock_read_csv.side_effect = pd.errors.EmptyDataError
        result = read_csv_pandas('empty.csv')
        self.assertIsNone(result)

    @patch('requests.get')
    def test_get_cve_cvss_success_v3(self, mock_get):
        """Test get_cve_cvss with CVSS v3 data"""
        # Mock successful API response with CVSS v3 data
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "vulnerabilities": [{
                "cve": {
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {
                                "baseScore": 7.5,
                            },
                            "baseSeverity": "HIGH"
                        }]
                    }
                }
            }]
        }
        mock_get.return_value = mock_response

        result = get_cve_cvss("CVE-2021-1234")
        self.assertEqual(result["cvss_score"], 7.5)
        self.assertEqual(result["severity"], "HIGH")

    @patch('requests.get')
    def test_get_cve_cvss_success_v2(self, mock_get):
        """Test get_cve_cvss with CVSS v2 data"""
        # Mock successful API response with CVSS v2 data
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "vulnerabilities": [{
                "cve": {
                    "metrics": {
                        "cvssMetricV2": [{
                            "cvssData": {
                                "baseScore": 6.5
                            },
                            "baseSeverity": "MEDIUM"
                        }]
                    }
                }
            }]
        }
        mock_get.return_value = mock_response

        result = get_cve_cvss("CVE-2021-5678")
        self.assertEqual(result["cvss_score"], 6.5)
        self.assertEqual(result["severity"], "MEDIUM")

    @patch('requests.get')
    def test_get_cve_cvss_api_error(self, mock_get):
        """Test get_cve_cvss with API error"""
        mock_get.side_effect = requests.RequestException("API Error")
        result = get_cve_cvss("CVE-2021-1234")
        self.assertIsNone(result["cvss_score"])
        self.assertIsNone(result["severity"])

    def test_process_cisa_vulnerabilities_invalid_df(self):
        """Test process_cisa_vulnerabilities with invalid DataFrame"""
        self.assertIsNone(process_cisa_vulnerabilities(None))

    def test_process_cisa_vulnerabilities_missing_column(self):
        """Test process_cisa_vulnerabilities with missing cveID column"""
        df_without_cveid = pd.DataFrame({'other_column': [1, 2, 3]})
        self.assertIsNone(process_cisa_vulnerabilities(df_without_cveid))

    @patch('capstone.cvss.get_cve_cvss')
    def test_process_cisa_vulnerabilities_to_df_success(
            self, mock_get_cve_cvss):
        """Test process_cisa_vulnerabilities_to_df with
        successful processing"""
        mock_get_cve_cvss.return_value = {
            "cvss_score": 7.5,
            "severity": "HIGH"
        }

        result_df = process_cisa_vulnerabilities_to_df(self.test_df, delay=0)

        self.assertIsInstance(result_df, pd.DataFrame)
        self.assertTrue('cvss_score' in result_df.columns)
        self.assertTrue('severity' in result_df.columns)
        self.assertEqual(len(result_df), 2)
        self.assertEqual(result_df['cvss_score'].iloc[0], 7.5)
        self.assertEqual(result_df['severity'].iloc[0], "HIGH")


def main():
    """ Execute all unit tests in the test suite """
    unittest.main()


if __name__ == '__main__':
    main()
