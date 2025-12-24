
# STPortScanner (Standalone EXE Fork)

This repository is a fork of **[STPortScanner](https://github.com/DebugST/STPortScanner)** by DebugST, modified to produce a **fully standalone executable**.

---

## Overview

The upstream STPortScanner executable **depends on an external DLL** at runtime.
This fork removes that dependency and delivers a **single self-contained `.exe`**, simplifying deployment and execution.

---

## What’s Different from Upstream

* Removed external DLL dependency
* Built as a **single standalone executable**
* No additional runtime files required (aside from configuration)
* More reliable execution on systems with restricted environments

---

## Use Cases

This build is suitable for:

* Portable or drop-and-run usage
* Lab and test environments
* Red team tooling
* Scenarios where dropping extra binaries or DLLs is undesirable

---

## Why This Fork Exists

Use this version if you need:

* A **one-file executable**
* No DLL-related runtime errors
* Minimal setup and faster execution

---

## Requirements

The following configuration files are still required at runtime:

* `config/config_defports.st`
* `config/config_probes.st`

These files define supported ports, services, and probe matching logic.

---

## Credits

All original credit goes to **DebugST** for the base project:
[https://github.com/DebugST/STPortScanner](https://github.com/DebugST/STPortScanner)

This fork only modifies the build/output format and does not claim ownership of the original work.


