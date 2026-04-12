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
        "--timeout",
        type=float,
        default=None,
        help="Override default timeout per scanner (seconds)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )

    args = parser.parse_args()

    # Strip protocol if user passed a URL
    domain = args.domain.replace("https://", "").replace("http://", "").strip("/")

    only = args.only.split(",") if args.only else None

    from domain_audit.core import audit

    if args.format == "json":
        # Suppress auto-display for JSON output
        import domain_audit.report as report
        original_display = report.display
        report.display = lambda r: None

        result = audit(domain, only=only)

        report.display = original_display

        data = json.dumps(result.to_dict(), indent=2, default=str)
        if args.output:
            with open(args.output, "w") as f:
                f.write(data)
            print(f"JSON output written to {args.output}")
        else:
            print(data)

    elif args.format == "csv":
        import domain_audit.report as report
        original_display = report.display
        report.display = lambda r: None

        result = audit(domain, only=only)

        report.display = original_display

        if args.output:
            result.to_csv(args.output)
            print(f"CSV output written to {args.output}")
        else:
            import csv
            import io
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(["module", "grade", "status", "finding", "detail", "fix"])
            for name, r in result.results.items():
                for finding in r.findings:
                    writer.writerow([
                        name,
                        finding.get("grade", "-"),
                        r.status,
                        finding.get("label", ""),
                        finding.get("detail", ""),
                        finding.get("fix", ""),
                    ])
            print(buf.getvalue())

    else:
        # Table format — auto-display handles it
        result = audit(domain, only=only)


if __name__ == "__main__":
    main()
