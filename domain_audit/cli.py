from __future__ import annotations

import argparse
import json
import sys


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="domain-audit",
        description="Comprehensive domain health audit — DNS, SSL, WHOIS, headers, ports, email security, tech detection.",
    )
    parser.add_argument("domain", help="Domain to audit (e.g., example.com)")
    parser.add_argument(
        "--only",
        help="Comma-separated list of scanners to run (dns,subdomains,ssl,headers,whois,ports,email,tech)",
        default=None,
    )
    parser.add_argument(
        "--format",
        choices=["table", "json", "csv"],
        default="table",
        help="Output format (default: table)",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Output file path (for json/csv formats)",
        default=None,
    )
    parser.add_argument(
        "--deep",
        action="store_true",
        help="Deep subdomain scanning — probe each subdomain for DNS/SSL/HTTP (slower)",
    )

    args = parser.parse_args()

    # Strip protocol if user passed a URL
    domain = args.domain.replace("https://", "").replace("http://", "").strip("/")

    # Validate domain name
    from domain_audit.validators import validate_domain, DomainValidationError
    try:
        domain = validate_domain(domain)
    except DomainValidationError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    only = args.only.split(",") if args.only else None

    from domain_audit.core import audit

    if args.format == "json":
        result = audit(domain, only=only, show=False, deep_subdomains=args.deep)
        data = json.dumps(result.to_dict(), indent=2, default=str)
        if args.output:
            with open(args.output, "w") as f:
                f.write(data)
            print(f"JSON output written to {args.output}")
        else:
            print(data)

    elif args.format == "csv":
        result = audit(domain, only=only, show=False, deep_subdomains=args.deep)
        if args.output:
            result.to_csv(args.output)
            print(f"CSV output written to {args.output}")
        else:
            print(result.to_csv_string())

    else:
        # Table format — auto-display via show=True
        audit(domain, only=only, show=True, deep_subdomains=args.deep)


if __name__ == "__main__":
    main()
