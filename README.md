## Cobalt Strike (`execute-assembly`) Version

This version is modified to run correctly when executed via **Cobalt Strike’s `execute-assembly`** feature.

### Background

The original implementation loads configuration files directly from disk:

```csharp
if (!File.Exists("./config_defports.st"))
    ConfigerHelper.CreateConfigFile("./config_defports.st", false);

if (!File.Exists("./config_probes.st"))
    ConfigerHelper.CreateConfigFile("./config_probes.st", true);

m_pc = new ProbeConfiger(
    File.ReadAllText("./config_probes.st"),
    File.ReadAllText("./config_defports.st")
);
```

This approach does **not work reliably** with `execute-assembly`, since the assembly is executed **in-memory** and may not have access to the filesystem.

### Modification

To ensure compatibility with `execute-assembly`, configuration data is **embedded or initialized in code** instead of being read from disk.

The file-loading logic is removed and replaced with in-memory values (or empty strings):

```csharp
m_pc = new ProbeConfiger(
    "", // probes configuration (in-memory)
    ""  // default ports configuration (in-memory)
);
```

### Result

* No filesystem access required
* Compatible with in-memory execution
* Prevents file creation or read errors
* Works correctly with Cobalt Strike `execute-assembly`

### Notes

If custom probe or port configurations are needed, they should be:

* Embedded directly in the source code, or
* Passed as parameters before initializing `ProbeConfiger`
