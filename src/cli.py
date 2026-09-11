import argparse
from pathlib import Path
from .ingestion import load_events, load_identities
from .detector import assess
from .reporting import render

def main():
    p=argparse.ArgumentParser(description="Offline defensive credential-access assessment")
    p.add_argument("--events",required=True); p.add_argument("--identity-context",required=True); p.add_argument("--output",required=True)
    a=p.parse_args()
    findings=assess(load_events(a.events),load_identities(a.identity_context))
    Path(a.output).write_text(render(findings),encoding="utf-8")
    print(f"wrote {len(findings)} findings to {a.output}")
if __name__ == "__main__": main()
