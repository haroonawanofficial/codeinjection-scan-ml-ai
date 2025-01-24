# Advanced Code Injection Vulnerability Scanner with Forms and Auto Crawl

![Scanner Banner](https://your-image-link.com/banner.png)

## 🚀 Overview

Advanced PHP Vulnerability Scanner is a powerful tool designed to identify and exploit vulnerabilities in PHP applications. It features automated crawling, diverse payload injections, AI-based detection, comprehensive reporting, and multiprocessing support to ensure efficient and accurate vulnerability assessments.

## 🔍 Features

- **Automated Crawling:** Recursively crawl target domains to discover PHP-related endpoints.
- **Extended PHP Extensions Support:** Scans `.php`, `.php3`, `.php4`, `.php5`, `.php7`, `.php8`, `.phtml`, and other PHP-related extensions.
- **Diverse Payloads:** Utilizes a wide range of payloads covering various vulnerabilities like XSS, SQL Injection, Command Injection, SSRF, IDOR, XML, Authorization Bypass, LFI, RFI, RCE, Crypto and more.
- **AI-Based Detection:** Leverages machine learning models to enhance vulnerability detection accuracy.
- **Comprehensive Reporting:** Generates detailed HTML reports highlighting discovered vulnerabilities.
- **Multiprocessing Support:** Speeds up the scanning process by utilizing multiple CPU cores.
- **Flexible Configuration:** Supports integration with Wayback Machine and CommonCrawl for extensive URL discovery.

## 🛠 Installation

1. **Clone the Repository:**
    ```bash
    git clone https://github.com/yourusername/codeinjection-scan-ml-ai.git
    cd codeinjection-scan-ml-ai
    ```

2. **Install Dependencies:**
    Ensure you have Python 3 installed. Install the required Python packages:
    ```bash
    pip install -r requirements.txt
    ```

3. **Install Additional Libraries (Optional):**
    - **WaybackPy:** For Wayback Machine URL extraction.
        ```bash
        pip install waybackpy
        ```
    - **CommonCrawl:** Ensure access to CommonCrawl data.

## 📝 Usage

### Basic Scan
Start scanning a target URL with default settings:
```bash
python phpscan.py --start-url http://testphp.vulnweb.com -db php_vulnerability_test.db -r -v --max-depth 3
