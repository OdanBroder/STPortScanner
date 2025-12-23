# STPortScanner (Standalone EXE Fork)

This repository is a fork of **[STPortScanner](https://github.com/DebugST/STPortScanner)** by DebugST.

## 🔧 What’s Different?

In the original STPortScanner project, the executable **depends on an external DLL** to run correctly.

This fork removes that dependency and provides a **fully standalone `.exe`**, with **no additional DLL required**.

### Key Improvements

* **No external DLL dependency**
* **Single standalone executable**
* Easier deployment and execution
* Suitable for:

  * Portable usage
  * Lab environments
  * Red team tooling
  * Systems where dropping extra files is undesirable

## Why This Fork?

This version is useful when you want:

* A **one-file executable**
* No missing-DLL errors
* Simpler execution without setup or environment preparation

## Credits

All original credit goes to **DebugST** for the base project:
[https://github.com/DebugST/STPortScanner](https://github.com/DebugST/STPortScanner)

This fork only changes the build/output format and does not claim ownership of the original work.


