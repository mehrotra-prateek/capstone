#!/usr/bin/env python
"""
CVSS Score Retrieval Module

This module provides functionality to retrieve Common Vulnerability Scoring
system (CVSS) scores and severity ratings for CVE IDs using the National
Vulnerability Database (NVD) API.

The module includes functions to:
- Fetch CVSS scores (v2 and v3) for a given CVE ID
- Retrieve severity ratings
- Handle API responses and errors

Example:
    cve_id = "CVE-2002-0367"
    get_cve_cvss(cve_id)
"""
import time
import requests
import pandas as pd


def get_cve_cvss(cve_id):
    """
    Retrieve CVSS score and severity rating for a given CVE ID.

    This function queries the National Vulnerability Database (NVD) API
    to fetch CVSS scores (v2 or v3) and severity ratings for the
    specified CVE ID.

    Args:
        cve_id (str): The CVE ID to look up (e.g., "CVE-2002-0367")

    Returns:
        None: Prints the CVSS score and severity rating to stdout

    Raises:
        requests.RequestException: If there is an error fetching data
        from the NVD API

    Example:
        >>> get_cve_cvss("CVE-2002-0367")
        CVE ID: CVE-2002-0367
        CVSS v3 Score: 7.5
        Severity: HIGH
    """
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
    params = {"cveId": cve_id}

    try:
        response = requests.get(base_url, params=params, timeout=(5, 30))
        response.raise_for_status()
        data = response.json()

        # Extract the CVSS score from the response
        vulnerabilities = data.get("vulnerabilities", [])
        if vulnerabilities:
            impact = vulnerabilities[0].get("cve", {}).get("metrics", {})
            if "cvssMetricV31" in impact:
                cvss_v3 = impact["cvssMetricV31"][0]["cvssData"]
                return {
                    "cvss_score": cvss_v3["baseScore"],
                    "severity": cvss_v3["baseSeverity"]
                }
            elif "cvssMetricV2" in impact:
                cvss_v2 = impact["cvssMetricV2"][0]["cvssData"]
                return {
                    "cvss_score": cvss_v2["baseScore"],
                    "severity": impact["cvssMetricV2"][0]["baseSeverity"]
                }
        return {
            "cvss_score": None,
            "severity": None
        }

    except (requests.RequestException, KeyError) as e:
        print(f"Error fetching CVE data for {cve_id}: {e}")
        return {
            "cvss_score": None,
            "severity": None
        }


def process_cisa_vulnerabilities_to_df(dataframe, delay=1.0):
    """
    Process CVE IDs from CISA dataframe and create new DataFrame with CVSS
    data.

    Args:
        dataframe (pandas.DataFrame): DataFrame containing CVE IDs
        delay (float): Delay in seconds between API calls

    Returns:
        pandas.DataFrame: New DataFrame with added CVSS data columns
    """
    if dataframe is None:
        print("Error: No DataFrame provided")
        return None

    if 'cveID' not in dataframe.columns:
        print("Error: DataFrame does not contain 'cveID' column")
        return None

    # Create a copy of the original dataframe
    new_df = dataframe.copy()

    # Initialize new columns
    new_df['cvss_score'] = None
    new_df['severity'] = None

    total_cves = len(new_df)
    print(f"Processing {total_cves} CVE IDs...\n")

    for index, row in new_df.iterrows():
        cve_id = row['cveID']
        print(f"Processing {index + 1} of {total_cves}: {cve_id}")

        # Get CVSS data
        cvss_data = get_cve_cvss(cve_id)

        # Update the DataFrame
        new_df.at[index, 'cvss_score'] = cvss_data['cvss_score']
        new_df.at[index, 'severity'] = cvss_data['severity']

        # Add delay between requests
        if index < total_cves - 1:
            time.sleep(delay)

    return new_df


def read_csv_pandas(file_path):
    """
    Read CSV file using pandas and return a DataFrame

    Args:
        file_path (str): Path to the CSV file

    Returns:
        pandas.DataFrame: DataFrame containing the CSV data
        None: If there's an error reading the file

    Example:
        >>> df = read_csv_pandas('vulnerabilities.csv')
        >>> if df is not None:
        >>>     print(df.head())
    """
    try:
        df = pd.read_csv(file_path)
        return df
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found")
        return None
    except pd.errors.EmptyDataError:
        print(f"Error: File '{file_path}' is empty")
        return None
    except pd.errors.ParserError:
        print(
            f"Error: Unable to parse '{file_path}'."
            f"Check if it is a valid CSV file"
            )
        return None
    except OSError as e:
        print(f"Error reading CSV file: {e}")
        return None


def process_cisa_vulnerabilities(dataframe, delay=1.0):
    """
    Process CVE IDs from CISA dataframe and retrieve CVSS data for each.
    Includes rate limiting to avoid overwhelming the NVD API.

    Args:
        dataframe (pandas.DataFrame): DataFrame containing CVE IDs
                                    (must have 'cveID' column)
        delay (float): Delay in seconds between API calls (default: 1.0)

    Returns:
        None: Prints CVSS data for each CVE ID

    Example:
        >>> df = read_csv_pandas('known_exploited_vulnerabilities.csv')
        >>> if df is not None:
        >>>     process_cisa_vulnerabilities(df, delay=1.5)
    """
    if dataframe is None:
        print("Error: No DataFrame provided")
        return

    if 'cveID' not in dataframe.columns:
        print("Error: DataFrame does not contain 'cveID' column")
        return

    # Get unique CVE IDs to avoid duplicates
    cve_ids = dataframe['cveID'].unique()
    total_cves = len(cve_ids)

    print(f"Processing {total_cves} unique CVE IDs...\n")

    for index, cve_id in enumerate(cve_ids, 1):
        print(f"Processing {index} of {total_cves}: {cve_id}")
        get_cve_cvss(cve_id)
        print("-" * 50)  # Separator line for readability
        
        # Add delay between requests to avoid rate limiting
        if index < total_cves:  # Don't delay after the last item
            time.sleep(delay)


if __name__ == "__main__":
    FILE_PATH = "data/known_exploited_vulnerabilities.csv"
    # Read the original CSV
    cisa_df = read_csv_pandas(FILE_PATH)

    if cisa_df is not None:
        # Create enhanced DataFrame with CVSS data
        enhanced_df = process_cisa_vulnerabilities_to_df(cisa_df)
        if 'notes' in enhanced_df.columns:
            enhanced_df.drop('notes', axis=1, inplace=True)
        if enhanced_df is not None:
            # Save to new CSV
            NEW_CSV_NAME = "data/vulnerabilities_with_cvss.csv"
            enhanced_df.to_csv(NEW_CSV_NAME, index=False)
            print("Enhanced data saved to 'vulnerabilities_with_cvss.csv'")
