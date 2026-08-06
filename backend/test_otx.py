from intelligence.threat_intel import threat_intel

def test_otx():
    print("Testing OTX AlienVault Integration...")
    # Using a known safe domain first
    target = "scanme.nmap.org"
    print(f"\n[+] Looking up: {target}")
    result = threat_intel.lookup_ioc(target, "domain")
    print(f"Result: {result}")

    # You can also test an IP
    target_ip = "8.8.8.8"
    print(f"\n[+] Looking up IP: {target_ip}")
    result_ip = threat_intel.lookup_ioc(target_ip, "ip")
    print(f"Result: {result_ip}")

if __name__ == "__main__":
    test_otx()
