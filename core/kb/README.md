---
type: reference
status: active
owner: founder
created: 2026-03-19
updated: 2026-03-19
sensitivity: public
venture: PX-Open-Suite
product: px-secrets
tags: [secrets, sops, age, encryption, vault, open-source, AGPL-3.0]
---

# PX Secrets

## Overview

SOPS + AGE vault manager with a visual GUI. A single-file Flask app with embedded HTML/CSS/JS for managing encrypted secrets. Dark theme, local-first, no cloud dependency.

## Status

**v1.2.0** — Ready for open-source launch. Currently used internally for PX Agentic EOS secrets management.

## Key Features

- Visual GUI for SOPS+AGE encrypted YAML vaults
- Create, read, update, delete secrets through browser UI
- Dark theme with modern design
- Single-file deployment (one Python script)
- Flask + pywebview for native window experience

## Tech Stack

- Python, Flask, pywebview
- SOPS + AGE for encryption
- Single-file architecture (~1 file, all HTML/CSS/JS embedded)

## Launch Plan

Part of PX Open Suite staggered launch — planned for Week 2 (after PX Dictate).

## Related

- [[ventures/PX-Open-Suite/core/kb/README|PX Open Suite]] — Parent venture
