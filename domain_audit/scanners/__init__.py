from domain_audit.scanners.dns_records import scan as dns_scan
from domain_audit.scanners.subdomains import scan as subdomain_scan
from domain_audit.scanners.ssl_check import scan as ssl_scan
from domain_audit.scanners.headers import scan as headers_scan
from domain_audit.scanners.whois_info import scan as whois_scan
from domain_audit.scanners.ports import scan as ports_scan
from domain_audit.scanners.email_security import scan as email_scan
from domain_audit.scanners.tech_detect import scan as tech_scan

SCANNERS = {
    "subdomains": subdomain_scan,
    "dns": dns_scan,
    "ssl": ssl_scan,
    "headers": headers_scan,
    "whois": whois_scan,
    "ports": ports_scan,
    "email": email_scan,
    "tech": tech_scan,
}
