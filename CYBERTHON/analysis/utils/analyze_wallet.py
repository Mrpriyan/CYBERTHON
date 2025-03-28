import requests
import re
import ipaddress
import logging
import concurrent.futures
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# API KEYS (Store securely in .env instead of hardcoding)
ABUSEIPDB_API_KEY = "YOUR_ABUSEIPDB_API_KEY"
SERPAPI_KEY = "YOUR_SERPAPI_KEY"

# Configure Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Configure Session with Retry Mechanism
def create_session():
    session = requests.Session()
    retries = Retry(total=5, backoff_factor=2, status_forcelist=[500, 502, 503, 504])
    session.mount("https://", HTTPAdapter(max_retries=retries))
    return session

session = create_session()

# Google Dorking to Find Wallet Mentions
def google_dork(wallet_address):
    """
    Searches for leaked wallet information across multiple websites.

    Args:
        wallet_address (str): The Ethereum wallet address.

    Returns:
        list: A list of discovered links.
    """
    search_sites = [
        "pastebin.com", "github.com", "twitter.com", "reddit.com", "medium.com",
        "etherscan.io", "bitcoinforum.com", "cryptotalk.org", "bitcointalk.org",
        "stackexchange.com", "dune.com"
    ]

    links = set()

    def fetch_links(site):
        query = f"{wallet_address} site:{site}"
        url = f"https://serpapi.com/search.json?q={query}&api_key={SERPAPI_KEY}"
        try:
            response = session.get(url, timeout=10).json()
            if "organic_results" in response:
                for result in response["organic_results"]:
                    links.add(result["link"])
        except requests.RequestException as e:
            logging.warning(f"Failed to fetch results from SerpAPI for {site}: {e}")

    with concurrent.futures.ThreadPoolExecutor() as executor:
        executor.map(fetch_links, search_sites)

    return list(links)

# Extract IP Addresses from Web Pages
def extract_ips_from_links(links):
    """
    Scrapes web pages for IP addresses.

    Args:
        links (list): List of URLs to scan.

    Returns:
        list: Extracted valid IP addresses.
    """
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    found_ips = set()

    def fetch_and_extract_ips(link):
        try:
            response = session.get(link, timeout=5)
            response.raise_for_status()
            matches = ip_pattern.findall(response.text)
            for ip in matches:
                try:
                    ipaddress.ip_address(ip)  # Validate IP format
                    found_ips.add(ip)
                except ValueError:
                    continue
        except requests.RequestException:
            logging.warning(f"Failed to fetch {link}")

    with concurrent.futures.ThreadPoolExecutor() as executor:
        executor.map(fetch_and_extract_ips, links)

    return list(found_ips)

# Check IP Reputation in AbuseIPDB
def check_ip_reputation(ip):
    """
    Checks if an IP address is reported for malicious activity.

    Args:
        ip (str): The IP to check.

    Returns:
        int: The abuse confidence score (higher = more malicious).
    """
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}

    try:
        response = session.get(url, headers=headers, timeout=10).json()
        return response.get("data", {}).get("abuseConfidenceScore", 0)
    except requests.RequestException as e:
        logging.warning(f"Failed to check IP reputation for {ip}: {e}")
        return 0

# Main Wallet Analysis Function
def analyze_wallet(wallet_address):
    """
    Analyzes a wallet address to find leaked information and associated IPs.

    Args:
        wallet_address (str): The Ethereum wallet address.

    Returns:
        dict: Analysis results including links, extracted IPs, and malicious IPs.
    """
    logging.info(f"Starting analysis for wallet: {wallet_address}")

    # Step 1: Perform Google Dorking
    google_links = google_dork(wallet_address)
    logging.info(f"Discovered links: {google_links}")

    # Step 2: Extract IPs from the found links
    extracted_ips = extract_ips_from_links(google_links)
    logging.info(f"Extracted IPs: {extracted_ips}")

    # Step 3: Check IP reputation in parallel
    malicious_ips = {}
    with concurrent.futures.ThreadPoolExecutor() as executor:
        ip_scores = list(executor.map(check_ip_reputation, extracted_ips))
    
    for ip, score in zip(extracted_ips, ip_scores):
        if score > 50:  # Flag IPs with high abuse confidence
            malicious_ips[ip] = score
    
    if malicious_ips:
        logging.warning(f"Malicious IPs detected: {malicious_ips}")
    else:
        logging.info("No malicious IPs found.")

    return {
        "wallet_address": wallet_address,
        "found_links": google_links,
        "extracted_ips": extracted_ips,
        "malicious_ips": malicious_ips
    }

# Run Analysis with User Input
if __name__ == "__main__":
    wallet_to_analyze = input("Enter Ethereum wallet address: ").strip()
    
    if re.match(r"^0x[a-fA-F0-9]{40}$", wallet_to_analyze):  # Validate ETH address format
        result = analyze_wallet(wallet_to_analyze)
        print(result)
    else:
        print("Invalid Ethereum wallet address. Please enter a valid 42-character address starting with 0x.")
