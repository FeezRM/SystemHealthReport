<#
.SYNOPSIS
    Gathers system health and inventory information from local or remote computers.
.DESCRIPTION
    Retrieves CPU temperature, disk space, installed software, and running services.
    Generates a visual HTML dashboard report using PSWriteHTML if available.
.PARAMETER ComputerName
    The name(s) of the computer(s) to query. Defaults to the local computer.
.PARAMETER OutputPath
    The path to save the generated HTML report. Defaults to a timestamped file in the current directory.
.PARAMETER InstallPrerequisites
    Switch to automatically install required modules (like PSWriteHTML) if missing.
#>

[CmdletBinding()]
param (
    [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [string[]]$ComputerName = $env:COMPUTERNAME,

    [Parameter()]
    [string]$OutputPath = ".\SystemHealthReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",

    [switch]$InstallPrerequisites
)

begin {
    $ErrorActionPreference = 'Stop'

    # Check for required modules
    $requiredModules = @('PSWriteHTML')
    foreach ($module in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            if ($InstallPrerequisites) {
                Write-Host "Installing missing module: $module" -ForegroundColor Yellow
                Install-Module -Name $module -Force -Scope CurrentUser -AllowClobber
            } else {
                Write-Warning "Required module '$module' is missing. The script will try to output basic objects, but report generation will fail. Run with -InstallPrerequisites to install."
            }
        } else {
            Import-Module $module
        }
    }

    # Helper function to get CPU Temperature
    function Get-CPUTemperature {
        param([string]$ComputerName)
        try {
            # WMI method (requires admin rights, hardware dependent)
            $tempObj = Get-WmiObject -Query "SELECT CurrentTemperature FROM MSAcpi_ThermalZoneTemperature" -Namespace "root/wmi" -ComputerName $ComputerName -ErrorAction Stop
            if ($tempObj) {
                $tempC = ($tempObj.CurrentTemperature / 10) - 273.15
                return [math]::Round($tempC, 2)
            }
        } catch {
            return "N/A (Access Denied / Not Supported)"
        }
        return "N/A"
    }

    # Helper function to get Disk Space
    function Get-DiskSpace {
        param([string]$ComputerName)
        try {
            $disks = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" -ComputerName $ComputerName -ErrorAction Stop
            $diskInfo = foreach ($disk in $disks) {
                $totalGB = [math]::Round($disk.Size / 1GB, 2)
                $freeGB = [math]::Round($disk.FreeSpace / 1GB, 2)
                $percentFree = if ($totalGB -gt 0) { [math]::Round(($freeGB / $totalGB) * 100, 2) } else { 0 }
                
                [PSCustomObject]@{
                    ComputerName = $ComputerName
                    DriveLetter  = $disk.DeviceID
                    VolumeName   = $disk.VolumeName
                    TotalGB      = $totalGB
                    FreeGB       = $freeGB
                    PercentFree  = $percentFree
                }
            }
            return $diskInfo
        } catch {
            Write-Warning "Failed to get disk space for $ComputerName : $_"
        }
    }

    # Helper function to get Installed Software
    function Get-InstalledSoftware {
        param([string]$ComputerName)
        # Using registry for faster and safer software inventory
        $paths = @(
            "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            "SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        )
        
        $softwareList = New-Object System.Collections.Generic.List[PSCustomObject]
        
        try {
            # Note: This is simplified for standard powershell remoting or local execution.
            # Using Invoke-Command for remote registry access ensures accuracy without requiring Remote Registry service.
            $scriptBlock = {
                $paths = @("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall")
                $installed = @()
                foreach ($path in $paths) {
                    if (Test-Path "HKLM:\$path") {
                        $keys = Get-ChildItem "HKLM:\$path"
                        foreach ($key in $keys) {
                            $name = $key.GetValue('DisplayName')
                            $version = $key.GetValue('DisplayVersion')
                            $publisher = $key.GetValue('Publisher')
                            $installDate = $key.GetValue('InstallDate')
                            if ($name) {
                                $installed += [PSCustomObject]@{
                                    Name        = $name
                                    Version     = $version
                                    Publisher   = $publisher
                                    InstallDate = $installDate
                                }
                            }
                        }
                    }
                }
                return $installed | Sort-Object Name -Unique
            }
            
            if ($ComputerName -eq $env:COMPUTERNAME -or $ComputerName -eq "localhost") {
                $result = Invoke-Command -ScriptBlock $scriptBlock
            } else {
                $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock -ErrorAction Stop
            }
            
            foreach ($item in $result) {
                $softwareList.Add([PSCustomObject]@{
                    ComputerName = $ComputerName
                    Name         = $item.Name
                    Version      = $item.Version
                    Publisher    = $item.Publisher
                })
            }
            return $softwareList
        } catch {
            Write-Warning "Failed to get software for $ComputerName : $_"
        }
    }

    # Helper function to get Running Services
    function Get-RunningServices {
        param([string]$ComputerName)
        try {
            $services = Get-Service -ComputerName $ComputerName -ErrorAction Stop | Where-Object Status -eq 'Running'
            $serviceInfo = foreach ($service in $services) {
                [PSCustomObject]@{
                    ComputerName = $ComputerName
                    Name         = $service.Name
                    DisplayName  = $service.DisplayName
                    Status       = $service.Status
                }
            }
            return $serviceInfo
        } catch {
            Write-Warning "Failed to get services for $ComputerName : $_"
        }
    }

    $allHealthData = New-Object System.Collections.Generic.List[PSCustomObject]
    $allDiskData = New-Object System.Collections.Generic.List[PSCustomObject]
    $allSoftwareData = New-Object System.Collections.Generic.List[PSCustomObject]
    $allServiceData = New-Object System.Collections.Generic.List[PSCustomObject]
}

process {
    foreach ($comp in $ComputerName) {
        Write-Host "Gathering data for $comp..." -ForegroundColor Cyan
        
        # Test connection first
        if (-not (Test-Connection -ComputerName $comp -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
            Write-Warning "Computer $comp is unreachable."
            continue
        }

        # 1. CPU Temperature
        $cpuTemp = Get-CPUTemperature -ComputerName $comp
        
        # 2. Disk Space
        $disks = Get-DiskSpace -ComputerName $comp
        if ($disks) { $allDiskData.AddRange($disks) }

        # OS Info via CIM
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $comp -ErrorAction SilentlyContinue
        $compSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $comp -ErrorAction SilentlyContinue

        $healthObj = [PSCustomObject]@{
            ComputerName   = $comp
            OS             = if ($os) { $os.Caption } else { "Unknown" }
            Manufacturer   = if ($compSystem) { $compSystem.Manufacturer } else { "Unknown" }
            Model          = if ($compSystem) { $compSystem.Model } else { "Unknown" }
            TotalRAM_GB    = if ($compSystem) { [math]::Round($compSystem.TotalPhysicalMemory / 1GB, 2) } else { 0 }
            CPUTemp        = $cpuTemp
            LastBootUpTime = if ($os) { $os.LastBootUpTime } else { "Unknown" }
        }
        $allHealthData.Add($healthObj)

        # 3. Installed Software
        $software = Get-InstalledSoftware -ComputerName $comp
        if ($software) { $allSoftwareData.AddRange($software) }

        # 4. Running Services
        $services = Get-RunningServices -ComputerName $comp
        if ($services) { $allServiceData.AddRange($services) }
    }
}

end {
    Write-Host "Data gathering complete. Generating report..." -ForegroundColor Green

    if (Get-Module -Name PSWriteHTML) {
        # Generate elegant HTML Report
        New-HTML -TitleText "System Health & Inventory Report" -FilePath $OutputPath {
            New-HTMLTabStyle -ColorizeTab
            
            New-HTMLTab -Name "Overview Dashboard" {
                New-HTMLSection -HeaderText "System Health Summary" {
                    New-HTMLTable -DataTable $allHealthData -DisableSearch -DisablePagination
                }
            }

            New-HTMLTab -Name "Disk Storage" {
                New-HTMLSection -HeaderText "Logical Disks" {
                    New-HTMLTable -DataTable $allDiskData {
                        New-HTMLTableCondition -Name "PercentFree" -Operator lt -Value 10 -BackgroundColor Red -Color White
                        New-HTMLTableCondition -Name "PercentFree" -Operator lt -Value 20 -BackgroundColor Orange
                    }
                }
            }

            New-HTMLTab -Name "Running Services" {
                New-HTMLSection -HeaderText "Running Services Inventory" {
                    New-HTMLTable -DataTable $allServiceData
                }
            }

            New-HTMLTab -Name "Installed Software" {
                New-HTMLSection -HeaderText "Installed Software Inventory" {
                    New-HTMLTable -DataTable $allSoftwareData
                }
            }
        } -ShowHTML
        
        Write-Host "Report saved to: $OutputPath" -ForegroundColor Green
    } else {
        # Fallback if PSWriteHTML is not available
        Write-Warning "PSWriteHTML not found. Outputting raw data to console."
        $summary = @{
            HealthSummary = $allHealthData
            Disks = $allDiskData
            SoftwareCount = $allSoftwareData.Count
            ServicesCount = $allServiceData.Count
        }
        $summary | Format-List
    }
}
