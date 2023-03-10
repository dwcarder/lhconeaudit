# lhconeaudit

This repo contains a snapshot of cric data and esnet routing tables for lhcone
taken at the same time, and then an audit script is provided to compare them.

## requirements
- pytricia https://github.com/jsommers/pytricia

## install
```
python3 -m venv audit
source cric-audit/bin/activate  # assuming bash
pip install pytricia
```

## usage
from the venv, run `audit.py`
Sorry, the update script to dump routing tables only works from within ESnet.

## or just see the results
the file output.txt contains the latest run.

# disclaimers, etc.
this is all best-effort
contact Dale W. Carder, dwcarder@es.net for details
