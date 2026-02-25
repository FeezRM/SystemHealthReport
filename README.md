# PowerShell System Health & Inventory Reporter

The **System Health/Inventory Reporter** script leverages PowerShell to gather key system metrics and present them in a beautiful, interactive HTML dashboard using the `PSWriteHTML` module (or falls back to terminal output if the module isn't available).

## Features

- **Modular Architecture**: Utilizing `Get-SystemHealthReport.ps1` with separate, maintainable helper functions for pulling exact data metrics:
  - **CPU Temperature**: Extracted via WMI `MSAcpi_ThermalZoneTemperature`.
  - **Disk Space**: Extracted via CIM `Win32_LogicalDisk`, filtering for standard drives (DriveType=3).
  - **Installed Software**: Rapidly parsed from registry `HKLM` hives.
  - **Running Services**: Interrogated via standard `Get-Service` querying.
- **Remote & Local Support**: Run queries easily against multiple remote machines simultaneously via the `-ComputerName` parameter, utilizing standard WinRM / CIM endpoint connections.
- **Dynamic Interactive Report**: Automatically generates an interactive multi-tab HTML dashboard with search elements and conditional formatting on fields like disk capacity (e.g. flagging drives under 10% free space in red).

## Prerequisites

This script uses standard native Windows technologies:

- Windows OS (Requires WMI/CIM, Event Logs, Windows Registry)
- PowerShell 5.1+
- The `PSWriteHTML` Module. If missing, simply add `-InstallPrerequisites` to your execution command.

> [!WARNING]
> Because this is a standard Windows administrative script using specific WMI/CIM endpoints, registry keys, and Windows service bindings, **it cannot be natively executed on macOS or Linux platforms**.

## Usage

To use the script in a Windows environment, open a PowerShell prompt (Administrator privileges recommended for certain WMI properties like CPU Temperature) and run:

```powershell
# Run locally and automatically install PSWriteHTML if missing
.\Get-SystemHealthReport.ps1 -InstallPrerequisites

# Run against multiple remote machines and save the report to a specific path
.\Get-SystemHealthReport.ps1 -ComputerName "Server01", "Desktop-Admin" -OutputPath "C:\Reports\Health.html"
```

## Dashboard Output

The output will be an interactive HTML dashboard containing your System Health, Logical Disks, Installed Software, and Running Services directly viewable in your preferred web browser.

## Stuff Incase

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```
