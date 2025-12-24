## Cobalt Strike `execute-assembly` Build

This build is modified to run **cleanly via Cobalt Strike’s `execute-assembly`**.
It is designed for **in-memory execution** and avoids all filesystem interaction.

---

## Why This Exists

The upstream version reads configuration files from disk.
When run with `execute-assembly`, this can fail due to:

* No working directory
* Restricted filesystem access
* In-memory–only execution context
* Only a limited set of services in **Config.cs** due to size constraints.

This build removes that dependency entirely.

---

## What Changed

File-based config loading was removed and replaced with **in-memory configuration**.

**Upstream behavior**

* Reads `config_defports.st` and `config_probes.st` from disk
* Creates files if missing

**This build**

* No file reads or writes
* Config is initialized in code before execution

```csharp
Config.Initialize();
m_pc = new ProbeConfiger(
    Config.ConfigProbes,
    Config.ConfigDefPorts
);
```

---

## Configuration (Operator Notes)

To control what services and ports are scanned:

* `config/config_defports.st`
  Supported ports and service mappings

* `config/config_probes.st`
  Probe signatures and match rules

For `execute-assembly`, **embed these configs directly into the source** or inject them programmatically before initializing `ProbeConfiger`.

---

## Difference from Upstream

| Aspect                  | Upstream              | This Build                     |
| ----------------------- | --------------------- | ------------------------------ |
| Execution model         | Disk-based            | In-memory                      |
| Config loading          | Reads `.st` files     | Embedded / initialized in code |
| File creation           | Yes                   | No                             |
| `execute-assembly` safe | No                    | Yes                            |
| OPSEC                   | Weaker (FS artifacts) | Improved                       |

---

## TL;DR

* Safe for `execute-assembly`
* No filesystem artifacts
* Better OPSEC
* Same scanning logic as upstream

