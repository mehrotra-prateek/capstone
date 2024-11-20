# Quantifying the Impact of data driven insights in CyberSecurity

## Executive Summary

### Objective
Cyber incidents are escalating in frequency and severity, making cybersecurity a critical priority for businesses. Organizations face the dual challenge of strengthening defenses while managing financial constraints.

This project demonstrates how data-driven cybersecurity strategies can improve resilience against ransomware threats. By analyzing the probability of exploitation and the impact of vulnerabilities, it provides actionable insights to guide investments in vulnerability detection and patch automation.

The study examines the correlation between vulnerabilities identified by the National Institute of Standards and Technology (NIST) and the Cybersecurity and Infrastructure Security Agency (CISA), focusing on those linked to ransomware. The goal is to equip decision-makers with tools to mitigate ransomware risks and optimize resource allocation effectively.

### Key Findings

* Data-driven insights help prioritize vulnerabilities based on exploit probability and impact.
* Automated patching minimizes the window of opportunity for attackers.

### Recommendations

1. Employ quantitative techniques to enhance vulnerability management and risk assessment.
1. Invest in automation to expedite patch deployment.
1. Continuously update risk models to account for emerging threats.

## Introduction

The increasing frequency and sophistication of ransomware attacks have made cybersecurity a top priority for organizations and regulators across the globe. Due to the widespread disruption, financial loss, and reputational damage from the incidents, orgnisations constantly struggle to balance the need for robust security with budgetary constraints and operational complexities, often resulting in delayed or inadequate responses to critical vulnerabilities. Furthermore, the qualitative nature of traditional risk management makes it difficult to justify investments in cybersecurity initiatives.

The project showcases how data-driven cybersecurity strategies can enhance organizational resilience and inform more precise risk assessments. By utilizing data-driven insights, organizations can make informed decisions about their cybersecurity investments and effectively address emerging requirements due to global geo-political and regulatory landscape.

## Data Collection
### Source 1: National Vulnerability Database from NIST
- NVD is the U.S. government repository of standards based vulnerability management data represented using the Security Content Automation Protocol (SCAP). This data enables automation of vulnerability management, security measurement, and compliance. 
- Data Format: API response from https://services.nvd.nist.gov/rest/json/cves/2.0/
    - Number of records: 270045

### Source 2: Cybersecurity and Infrastructure Security Agency (Known Exploited Vulnerabilities Catalog | CISA)
- Background: For the benefit of the cybersecurity community and network defenders—and to aid each organization in more effectively managing vulnerabilities and keeping pace with threat activity. CISA maintains the authoritative source of vulnerabilities that have been exploited in real-world scenarios. Organizations should utilize the KEV catalog as an input to their vulnerability management prioritization framework.
- Data Format: CSV
- File Name: known_exploited_vulnerabilities.csv
    - Data Structure: cveID, vendorProject, product, vulnerabilityName, dateAdded, shortDescription, requiredAction, dueDate, knownRansomwareCampaignUse, notes, cwes.
    - Number of records: ~1200

## Methodology

### Data Acquisition and Preparation
1. Data was sourced from the Cybersecurity and Infrastructure Security Agency (CISA) and the National Institute of Standards and Technology (NIST)
1. CSV data was downloaded from CISA, NIST and analyzed to understand its structure and information. 
    1. Input data files: ```data/known_exploited_vulnerabilities.csv```
1. The raw data was cleaned to remove inconsistencies and errors. Data from different sources was integrated and standardized to ensure compatibility.
    1. Code: ```capstone/cvss.py, analytics.ipynb```
    1. Data file created during processing and outputs: ```output/vulnerabilities_with_cvss.csv, output/vulnerabilities_with_cwes.csv, output/ransomware_probabilities.csv```

### Data Analysis and Modeling:

1. Relevant features were extracted from the data, such as vulnerability severity, exploitability, and potential impact.
1. Probability and Risk Calculation: Statistical techniques were employed to calculate the probability of a vulnerability being exploited and the associated risk of a ransomware incident.
1. Techniques like Principal Component Analysis (PCA) and Multiple Discriminant Analysis (MDA) were considered to reduce the dimensionality of the data and identify the most influential factors.
1. Data Visualization: Data visualizations were created to illustrate trends, patterns, and insights, including visualizations of products with frequent vulnerabilities.

## Conclusion

This project has demonstrated the value of a data-driven approach to cybersecurity. By analyzing vulnerability data from NIST and CISA, we have identified key vulnerabilities associated with ransomware incidents. 
1. Explore advanced analytics techniques, such as machine learning and artificial intelligence, to identify emerging threats and predict future attack patterns.
1. Access to a dataset of ransomware attacks, including geographical and temporal information, would further enrich the analysis. A request for this data has been submitted to few sources.
1. Consider incorporating data from additional sources, such as vulnerability databases, incident response reports, and dark web intelligence, to enhance the analysis.
