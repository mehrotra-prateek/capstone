# Capstone

Cybersecurity has become a critical concern for businesses of all sizes, as the frequency and severity of cyberattacks continue to rise. Organisations face the challenge of balancing the need for robust security measures with the financial constraints of their budgets. 
I will be attempting to analyse following data sets to assist organisations effectively allocate cybersecurity budgets to mitigate most significant risks while maximising ROI.

## Data Collection -
### Source 1: National Vulnerability Database from NIST
- NVD is the U.S. government repository of standards based vulnerability management data represented using the Security Content Automation Protocol (SCAP). This data enables automation of vulnerability management, security measurement, and compliance. 
- Data Format: API response from https://services.nvd.nist.gov/rest/json/cves/2.0/
    - 
    - Number of records: 270045

### Source 2: Cybersecurity and Infrastructure Security Agency (Known Exploited Vulnerabilities Catalog | CISA)
- Background: For the benefit of the cybersecurity community and network defenders—and to aid each organization in more effectively managing vulnerabilities and keeping pace with threat activity. CISA maintains the authoritative source of vulnerabilities that have been exploited in real-world scenarios. Organizations should utilize the KEV catalog as an input to their vulnerability management prioritization framework.
- Data Format: CSV
- File Name: known_exploited_vulnerabilities.csv
    - Data Structure: cveID, vendorProject, product, vulnerabilityName, dateAdded, shortDescription, requiredAction, dueDate, knownRansomwareCampaignUse, notes, cwes.
    - Number of records: ~1200

Method:
- Gather Data: 
- Download CSV data from CISA and study data structure
- Study data structure of NIST API
- Requested data access to list of ransomware attacks by geography and year on google sheets (pending)
- Downloaded a pdf and can possibly scrap pdf for some data
- Data Wrangling - cleaning up, combining, dimensionality reduction (PCA, MDA python sklearn )
- Data visualisation (Tableau vs matplotlib)
- Probability theory: probability of CVEs with no attack having an attack

