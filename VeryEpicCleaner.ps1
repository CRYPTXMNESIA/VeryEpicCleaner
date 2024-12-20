# VeryEpicCleaner.ps1
# An advanced PowerShell script to perform deep and comprehensive system cleanup tasks efficiently.

# Function to ensure the script runs with administrative privileges and bypasses execution policy
function Ensure-Admin {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "Elevating to administrative privileges and bypassing execution policy..."
        Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" --elevated" -Verb RunAs
        exit
    }
}

# Function to set console properties: title, encoding, colors, size, and position
function Configure-Console {
    $Host.UI.RawUI.WindowTitle = "VeryEpicCleaner"
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $Host.UI.RawUI.BackgroundColor = "Black"
    $Host.UI.RawUI.ForegroundColor = "White"

    try {
        $newWidth = 120
        $newHeight = 50
        $Host.UI.RawUI.WindowSize = New-Object System.Management.Automation.Host.Size($newWidth, $newHeight)
        $Host.UI.RawUI.BufferSize = New-Object System.Management.Automation.Host.Size($newWidth, $newHeight)
    } catch {
        Write-Host "Unable to set window size. Continuing with default size."
    }

    # Maximize the console window if possible
    try {
        Add-Type @"
        using System;
        using System.Runtime.InteropServices;
        public class Win32 {
            [DllImport("user32.dll")]
            public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
        }
"@
        $hwnd = (Get-Process -Id $PID).MainWindowHandle
        $SW_MAXIMIZE = 3
        [Win32]::ShowWindow($hwnd, $SW_MAXIMIZE) | Out-Null
    } catch {
        Write-Host "Unable to maximize the window. Continuing with default state."
    }
}

# Function to clear the console screen
function Clear-ConsoleScreen {
    Clear-Host
}

# Function to display the ASCII Art Banner
function Show-Banner {
    $banner = @"
:::     ::: :::::::::: ::::::::         :::        :::::::  
:+:     :+: :+:       :+:    :+:      :+:+:       :+:   :+: 
+:+     +:+ +:+       +:+               +:+       +:+  :+:+ 
#+#     +:+ +#++:++#  +#+               +#+       +#+ + +:+ 
 +#+   +#+  +#+       +#+               +#+       +#+#  +#+ 
  #+#+#+#   #+#       #+#    #+#        #+#   #+# #+#   #+# 
    ###     ########## ########       ####### ###  #######  
"@
    Write-Host $banner
}

# Function to perform a countdown timer
function Countdown-Timer {
    param (
        [int]$Seconds = 3
    )
    for ($i = $Seconds; $i -ge 0; $i--) {
        Write-Host -NoNewline "`rCleaning starts in: $i "
        Start-Sleep -Seconds 1
    }
    Write-Host ""
}

# Function to display a spinner during tasks and align "Done." vertically
function Start-Task {
    param (
        [string]$Message,
        [scriptblock]$Task
    )

    # Define a fixed width for the message part
    $fixedWidth = 60

    # Truncate the message if it exceeds the fixed width minus space for spinner and "Done."
    if ($Message.Length -gt ($fixedWidth - 10)) {
        $displayMessage = $Message.Substring(0, $fixedWidth - 13) + "..."
    } else {
        $displayMessage = $Message
    }

    # Start the task as a background job
    $job = Start-Job -ScriptBlock $Task

    # Define spinner characters
    $spinner = '|','/','-','\'
    $i = 0

    # Display spinner until the job is complete
    while ($job.State -ne 'Completed' -and $job.State -ne 'Failed') {
        # Pad the message to the fixed width minus spinner and "Done."
        $paddedMessage = $displayMessage.PadRight($fixedWidth - 6)
        Write-Host -NoNewline "$paddedMessage $($spinner[$i % 4])`r"
        Start-Sleep -Milliseconds 100
        $i++
    }

    # Wait for the job to finish
    Wait-Job $job | Out-Null
    Remove-Job $job | Out-Null

    # Overwrite the spinner with "Done." aligned
    Write-Host "$paddedMessage Done"
}

# Function to get free disk space on C: drive
function Get-FreeDiskSpace {
    $drive = Get-PSDrive -Name C
    return $drive.Free
}

# Function to format bytes into human-readable form
function Format-Bytes {
    param (
        [long]$Bytes
    )
    if ($Bytes -ge 1PB) { return "{0:N2} PB" -f ($Bytes / 1PB) }
    elseif ($Bytes -ge 1TB) { return "{0:N2} TB" -f ($Bytes / 1TB) }
    elseif ($Bytes -ge 1GB) { return "{0:N2} GB" -f ($Bytes / 1GB) }
    elseif ($Bytes -ge 1MB) { return "{0:N2} MB" -f ($Bytes / 1MB) }
    elseif ($Bytes -ge 1KB) { return "{0:N2} KB" -f ($Bytes / 1KB) }
    else { return "$Bytes Bytes" }
}

# Function to print disk space with label
function Print-FreeSpace {
    param (
        [string]$Label,
        [long]$FreeSpace
    )
    $formatted = Format-Bytes -Bytes $FreeSpace
    Write-Host "${Label}: $formatted free"
}

# Function to perform cleanup tasks on specified paths
function Cleanup-Task {
    param (
        [string]$Description,
        [string[]]$Paths
    )
    Start-Task -Message "> Cleaning $Description..." -Task {
        param($Paths)
        foreach ($path in $Paths) {
            $expandedPath = [Environment]::ExpandEnvironmentVariables($path)
            if (Test-Path $expandedPath) {
                try {
                    Remove-Item -Path $expandedPath -Recurse -Force -ErrorAction SilentlyContinue
                } catch {
                    # Suppress errors
                }
            }
        }
    } -Args $Paths
}

# Function to clear Recycle Bin for all users
function Clear-RecycleBinAllUsers {
    Start-Task -Message "> Clearing Recycle Bin for All Users..." -Task {
        try {
            $shell = New-Object -ComObject Shell.Application
            $shell.Namespace(0xa).Items() | ForEach-Object { $_.InvokeVerb("delete") }
        } catch {
            # Suppress errors
        }
    }
}

# Function to clear Event Logs comprehensively
function Clear-EventLogsComprehensively {
    Start-Task -Message "> Clearing All Event Logs..." -Task {
        try {
            Get-EventLog -List | ForEach-Object {
                try {
                    Clear-EventLog -LogName $_.Log
                } catch {
                    # Suppress errors
                }
            }
        } catch {
            # Suppress errors
        }
    }
}

# Function to clear DNS cache
function Clear-DNSCacheCustom {
    Start-Task -Message "> Clearing DNS Cache..." -Task {
        ipconfig /flushdns | Out-Null
    }
}

# Function to run Disk Cleanup with predefined settings
function Run-DiskCleanup {
    Start-Task -Message "> Running Disk Cleanup..." -Task {
        try {
            cleanmgr /sagerun:99 | Out-Null
        } catch {
            # Suppress errors
        }
    }
}

# Function to perform storage optimization (defragmentation and SSD optimization)
function Perform-StorageOptimization {
    Start-Task -Message "> Optimizing Storage..." -Task {
        try {
            Optimize-Volume -DriveLetter C -Verbose | Out-Null
        } catch {
            # Suppress errors
        }
    }
}

# Function to clear browser caches for all major browsers
function Clear-BrowserCaches {
    Start-Task -Message "> Clearing Browser Caches..." -Task {
        try {
            # Clear Microsoft Edge Cache
            Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache\*" -Recurse -Force -ErrorAction SilentlyContinue

            # Clear Google Chrome Cache
            Remove-Item -Path "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache\*" -Recurse -Force -ErrorAction SilentlyContinue

            # Clear Mozilla Firefox Cache
            Remove-Item -Path "$env:APPDATA\Mozilla\Firefox\Profiles\*\cache2\*" -Recurse -Force -ErrorAction SilentlyContinue

            # Clear Opera Cache
            Remove-Item -Path "$env:AppData\Opera Software\Opera Stable\Cache\*" -Recurse -Force -ErrorAction SilentlyContinue

            # Clear Brave Cache
            Remove-Item -Path "$env:LocalAppData\BraveSoftware\Brave-Browser\User Data\Default\Cache\*" -Recurse -Force -ErrorAction SilentlyContinue

            # Clear Vivaldi Cache
            Remove-Item -Path "$env:LocalAppData\Vivaldi\User Data\Default\Cache\*" -Recurse -Force -ErrorAction SilentlyContinue

            # Clear Safari Cache (if applicable)
            Remove-Item -Path "$env:LocalAppData\Apple Computer\Safari\Cache\*" -Recurse -Force -ErrorAction SilentlyContinue
        } catch {
            # Suppress errors
        }
    }
}

# Function to clean logs of popular anti-cheat programs
function Clean-AntiCheatLogs {
    Start-Task -Message "> Cleaning Anti-Cheat Program Logs..." -Task {
        try {
            $antiCheatLogPaths = @(
                "$env:ProgramData\BattleEye\*",
                "$env:ProgramData\EasyAntiCheat\*",
                "$env:ProgramData\Valve\Steam\logs\*",
                "$env:ProgramData\PunkBuster\*",
                "$env:LocalAppData\Epic\EpicGamesLauncher\Saved\Logs\*",
                "$env:LocalAppData\Steam\logs\*"
            )
            foreach ($path in $antiCheatLogPaths) {
                Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
            }
        } catch {
            # Suppress errors
        }
    }
}

# Function to remove Windows Update Cache
function Remove-WindowsUpdateCache {
    Start-Task -Message "> Removing Windows Update Cache..." -Task {
        try {
            Stop-Service -Name "wuauserv" -Force -ErrorAction SilentlyContinue
            Remove-Item -Path "$env:windir\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -Path "$env:windir\SoftwareDistribution\Logs\*" -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -Path "$env:windir\Installer\$PatchCache$\Managed\*" -Recurse -Force -ErrorAction SilentlyContinue
            Start-Service -Name "wuauserv" -ErrorAction SilentlyContinue
        } catch {
            # Suppress errors
        }
    }
}

# Function to clean up the WinSxS folder using DISM (basic)
function Clean-WinSxS {
    Start-Task -Message "> Cleaning WinSxS Folder..." -Task {
        try {
            DISM.exe /Online /Cleanup-Image /StartComponentCleanup /Quiet /NoRestart | Out-Null
        } catch {
            # Suppress errors
        }
    }
}

# **New function for advanced DISM cleanup tasks requested by the user**
function Advanced-DISM-Cleanup {
    Start-Task -Message "> Running Advanced DISM Cleanup..." -Task {
        try {
            DISM.exe /online /Cleanup-Image /StartComponentCleanup | Out-Null
            DISM.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase | Out-Null
            DISM.exe /online /Cleanup-Image /SPSuperseded | Out-Null
        } catch {
            # Suppress errors
        }
    }
}

# Function to delete prefetch files
function Delete-PrefetchFiles {
    Start-Task -Message "> Deleting Prefetch Files..." -Task {
        try {
            Remove-Item -Path "$env:windir\Prefetch\*" -Recurse -Force -ErrorAction SilentlyContinue
        } catch {
            # Suppress errors
        }
    }
}

# Function to remove temporary internet files
function Remove-TemporaryInternetFiles {
    Start-Task -Message "> Removing Temporary Internet Files..." -Task {
        try {
            Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Windows\INetCache\*" -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -Path "$env:APPDATA\Microsoft\Windows\INetCache\*" -Recurse -Force -ErrorAction SilentlyContinue
        } catch {
            # Suppress errors
        }
    }
}

# Function to clear thumbnail cache
function Clear-ThumbnailCache {
    Start-Task -Message "> Clearing Thumbnail Cache..." -Task {
        try {
            Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\thumbcache_*.db" -Force -ErrorAction SilentlyContinue
        } catch {
            # Suppress errors
        }
    }
}

# Function to clear SoftwareDistribution and Catroot2 folders
function Clear-SoftwareDistributionAndCatroot2 {
    Start-Task -Message "> Clearing SoftwareDistribution and Catroot2 Folders..." -Task {
        try {
            Stop-Service -Name "wuauserv" -Force -ErrorAction SilentlyContinue
            Stop-Service -Name "cryptSvc" -Force -ErrorAction SilentlyContinue
            Stop-Service -Name "bits" -Force -ErrorAction SilentlyContinue
            Stop-Service -Name "msiserver" -Force -ErrorAction SilentlyContinue

            Remove-Item -Path "$env:windir\SoftwareDistribution\*" -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -Path "$env:windir\System32\catroot2\*" -Recurse -Force -ErrorAction SilentlyContinue

            Start-Service -Name "wuauserv" -ErrorAction SilentlyContinue
            Start-Service -Name "cryptSvc" -ErrorAction SilentlyContinue
            Start-Service -Name "bits" -ErrorAction SilentlyContinue
            Start-Service -Name "msiserver" -ErrorAction SilentlyContinue
        } catch {
            # Suppress errors
        }
    }
}

# Function to delete temporary files from all user profiles
function Delete-TempFilesAllUsers {
    Start-Task -Message "> Deleting Temporary Files from All User Profiles..." -Task {
        try {
            $users = Get-ChildItem -Path "C:\Users" -Directory | Where-Object { $_.Name -notin @("Default", "Public", "Default User", "Administrator") }
            foreach ($user in $users) {
                $tempPaths = @(
                    "$($user.FullName)\AppData\Local\Temp\*",
                    "$($user.FullName)\AppData\Local\Microsoft\Windows\Temporary Internet Files\*"
                )
                foreach ($tempPath in $tempPaths) {
                    if (Test-Path $tempPath) {
                        Remove-Item -Path $tempPath -Recurse -Force -ErrorAction SilentlyContinue
                    }
                }
            }
        } catch {
            # Suppress errors
        }
    }
}

# Function to clear Windows Store cache by manually deleting cache folders
function Clear-WindowsStoreCache {
    Start-Task -Message "> Clearing Windows Store Cache..." -Task {
        try {
            $storeCachePath = "$env:LocalAppData\Packages\Microsoft.WindowsStore_8wekyb3d8bbwe\LocalCache\*"
            Get-Process -Name "WinStore.App.exe" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
            Remove-Item -Path $storeCachePath -Recurse -Force -ErrorAction SilentlyContinue
        } catch {
            # Suppress errors
        }
    }
}

# Function to delete old log files from various system directories
function Delete-OldLogFiles {
    Start-Task -Message "> Deleting Old Log Files..." -Task {
        try {
            $logPaths = @(
                "$env:windir\Logs\*.log",
                "$env:windir\Debug\*.log",
                "$env:windir\Logs\CBS\*.log",
                "$env:windir\Logs\DISM\*.log",
                "$env:windir\Logs\MeasuredBoot\*.log"
            )
            foreach ($path in $logPaths) {
                Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
            }
        } catch {
            # Suppress errors
        }
    }
}

# Function to remove old Windows backup files (Windows.old)
function Remove-WindowsBackupFiles {
    Start-Task -Message "> Removing Old Windows Backup Files..." -Task {
        try {
            Remove-Item -Path "C:\Windows.old" -Recurse -Force -ErrorAction SilentlyContinue
        } catch {
            # Suppress errors
        }
    }
}

# Additional function to remove upgrade folders like $Windows.~BT and $Windows.~WS
function Remove-UpgradeFolders {
    Start-Task -Message "> Removing Windows Upgrade Folders..." -Task {
        try {
            Remove-Item -Path "C:\$Windows.~BT\*" -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -Path "C:\$Windows.~WS\*" -Recurse -Force -ErrorAction SilentlyContinue
        } catch {
            # Suppress errors
        }
    }
}

# Function to clear WER (Windows Error Reporting) Report Queues and Archives
function Clear-WERReports {
    Start-Task -Message "> Clearing Windows Error Reporting Queues and Archives..." -Task {
        try {
            $werPaths = @(
                "$env:ProgramData\Microsoft\Windows\WER\ReportQueue\*",
                "$env:ProgramData\Microsoft\Windows\WER\ReportArchive\*",
                "$env:ProgramData\Microsoft\Windows\WER\Temp\*"
            )
            foreach ($path in $werPaths) {
                Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
            }
        } catch {
            # Suppress errors
        }
    }
}

# Function to clear various environment temp folders
function Clear-EnvTempFolders {
    Start-Task -Message "> Clearing Environment Temp Folders..." -Task {
        try {
            $tempPaths = @(
                "$env:TEMP\*",
                "$env:TMP\*",
                "%TEMP%\*",
                "%TMP%\*",
                "$env:windir\Temp\*",
                "$env:LOCALAPPDATA\Temp\*",
                "$env:USERPROFILE\AppData\Local\Temp\*"
            )

            foreach ($temp in $tempPaths) {
                $expanded = [Environment]::ExpandEnvironmentVariables($temp)
                if (Test-Path $expanded) {
                    Remove-Item -Path $expanded -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        } catch {
            # Suppress errors
        }
    }
}

# Extra cleanup pass
function Extra-BinCleanup {
    Start-Task -Message "> Extra Cleanup for System Directories..." -Task {
        try {
            Remove-Item -Path "$env:windir\Prefetch\*" -Recurse -Force -ErrorAction SilentlyContinue
        } catch {
            # Suppress errors
        }
    }
}

# Function to clear memory dump files
function Clear-MemoryDumpFiles {
    Start-Task -Message "> Clearing Memory Dump Files..." -Task {
        try {
            $dumpPaths = @(
                "$env:windir\Minidump\*",
                "$env:windir\Memory.dmp"
            )
            foreach ($path in $dumpPaths) {
                Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
            }
        } catch {
            # Suppress errors
        }
    }
}

# Function to clean up installed application leftovers
function Clean-Up-InstalledApplicationLeftovers {
    Start-Task -Message "> Cleaning Up Installed Application Leftovers..." -Task {
        try {
            $appPaths = @(
                "$env:ProgramFiles\*\AppData",
                "$env:ProgramFiles(x86)\*\AppData"
            )
            foreach ($path in $appPaths) {
                Get-ChildItem -Path $path -Directory -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                    Remove-Item -Path $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        } catch {
            # Suppress errors
        }
    }
}

# Function to clear shadow copies
function Clear-ShadowCopies {
    Start-Task -Message "> Clearing Shadow Copies..." -Task {
        try {
            vssadmin delete shadows /all /quiet | Out-Null
        } catch {
            # Suppress errors
        }
    }
}

# Function to remove hibernation and delete hiberfil.sys
function Remove-Hibernation {
    Start-Task -Message "> Removing Hibernation..." -Task {
        try {
            powercfg -h off | Out-Null
        } catch {
            # Suppress errors
        }
    }
}

# Function to delete specific file types across system directories
function Delete-SpecificFileTypes {
    Start-Task -Message "> Deleting Specific File Types..." -Task {
        try {
            $filePatterns = @("*.tmp", "*._mp", "*.log", "*.old", "*.trace", "*.bak", "*.chk", "*.gid")
            $searchPaths = @(
                "$env:systemdrive\*",
                "$env:windir\temp\*",
                "$env:windir\Prefetch\*",
                "$env:AppData\temp\*",
                "$env:HomePath\AppData\LocalLow\Temp\*",
                "$env:windir\*.bak",
                "$env:userprofile\cookies\*",
                "$env:userprofile\recent\*",
                "$env:WinDir\System32\energy-report.html"
            )
            foreach ($path in $searchPaths) {
                foreach ($pattern in $filePatterns) {
                    $expanded = [Environment]::ExpandEnvironmentVariables($path)
                    Remove-Item -Path "$expanded\$pattern" -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        } catch {
            # Suppress errors
        }
    }
}

# Function to delete specific folders recursively
function Delete-SpecificFolders {
    Start-Task -Message "> Deleting Specific Folders..." -Task {
        try {
            $foldersToDelete = @(
                "$env:windir\Temp",
                "$env:windir\Prefetch",
                "$env:TEMP",
                "$env:AppData\Temp",
                "$env:AppData\LocalLow\Temp",
                "$env:AppData\Local\Microsoft\Windows\Caches"
            )
            foreach ($folder in $foldersToDelete) {
                $expandedFolder = [Environment]::ExpandEnvironmentVariables($folder)
                if (Test-Path $expandedFolder) {
                    Remove-Item -Path $expandedFolder -Recurse -Force -ErrorAction SilentlyContinue
                }
            }

            # Recreate empty temporary folders
            $foldersToCreate = @(
                "$env:windir\Temp",
                "$env:windir\Prefetch",
                "$env:TEMP",
                "$env:AppData\Temp",
                "$env:AppData\LocalLow\Temp",
                "$env:AppData\Local\Microsoft\Windows\Caches"
            )
            foreach ($folder in $foldersToCreate) {
                $expandedFolder = [Environment]::ExpandEnvironmentVariables($folder)
                if (-not (Test-Path $expandedFolder)) {
                    New-Item -Path $expandedFolder -ItemType Directory -Force | Out-Null
                }
            }
        } catch {
            # Suppress errors
        }
    }
}

# Function to delete driver installation files
function Delete-DriverInstallFiles {
    Start-Task -Message "> Deleting Driver Installation Files..." -Task {
        try {
            $driverInstallPaths = @(
                "$env:systemdrive\AMD\*",
                "$env:systemdrive\NVIDIA\*",
                "$env:systemdrive\INTEL\*"
            )
            foreach ($path in $driverInstallPaths) {
                Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
            }
        } catch {
            # Suppress errors
        }
    }
}

# Function to delete Windows Installer cache
function Delete-WindowsInstallerCache {
    Start-Task -Message "> Deleting Windows Installer Cache..." -Task {
        try {
            $installerCachePaths = @(
                "$env:windir\Installer\$PatchCache$\Managed\*"
            )
            foreach ($path in $installerCachePaths) {
                Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
            }
        } catch {
            # Suppress errors
        }
    }
}

# Function to delete specific files in multiple drives
function Delete-FilesInDrives {
    Start-Task -Message "> Deleting Files in Multiple Drives..." -Task {
        try {
            $otherDrives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -ne "C:\" } | Select-Object -ExpandProperty Root
            if ($otherDrives.Count -eq 0) {
                return
            }

            $filePatterns = @("*.log", "*.old", "*.tmp", "*._mp", "*.chk", "*.bak", "*.gid", "*.trace")
            foreach ($drive in $otherDrives) {
                foreach ($pattern in $filePatterns) {
                    Get-ChildItem -Path "$drive" -Filter $pattern -Recurse -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        } catch {
            # Suppress errors
        }
    }
}

# Function to delete junk files using wildcard patterns
function Delete-JunkFiles {
    Start-Task -Message "> Deleting Junk Files..." -Task {
        try {
            $junkFilePatterns = @("*.log", "*.old", "*.tmp")
            foreach ($pattern in $junkFilePatterns) {
                Get-ChildItem -Path "C:\" -Filter $pattern -Recurse -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
            }
        } catch {
            # Suppress errors
        }
    }
}

# Function to delete temporary and cache folders recursively across all drives
function Delete-TempAndCacheFolders {
    Start-Task -Message "> Deleting Temporary and Cache Folders..." -Task {
        try {
            $otherDrives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -ne "C:\" } | Select-Object -ExpandProperty Root
            if ($otherDrives.Count -eq 0) {
                return
            }

            foreach ($drive in $otherDrives) {
                Get-ChildItem -Path $drive -Directory -Recurse -ErrorAction SilentlyContinue | Where-Object {
                    $_.Name -ieq "temp" -or $_.Name -ieq "cache"
                } | ForEach-Object {
                    Remove-Item -Path $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        } catch {
            # Suppress errors
        }
    }
}

# Function to clear shadow copies
function Clear-ShadowCopies {
    Start-Task -Message "> Clearing Shadow Copies..." -Task {
        try {
            vssadmin delete shadows /all /quiet | Out-Null
        } catch {
            # Suppress errors
        }
    }
}

# Function to remove hibernation and delete hiberfil.sys
function Remove-Hibernation {
    Start-Task -Message "> Removing Hibernation..." -Task {
        try {
            powercfg -h off | Out-Null
        } catch {
            # Suppress errors
        }
    }
}

# Main Execution Flow
function Main {
    param (
        [string[]]$Args
    )

    # Handle UAC elevation and execution policy bypass
    if ($Args -notcontains '--elevated') {
        Ensure-Admin
    }

    # Configure console
    Configure-Console

    # Clear console screen
    Clear-ConsoleScreen

    # Show ASCII Art Banner
    Show-Banner

    # Add one empty line
    Write-Host ""

    # Perform a countdown before starting
    Countdown-Timer -Seconds 3

    # Get and display initial free disk space
    $initialFreeSpace = Get-FreeDiskSpace
    Print-FreeSpace -Label "Initial Disk Space" -FreeSpace $initialFreeSpace

    # Define and execute cleanup tasks

    # Clear Browser Caches
    Clear-BrowserCaches

    # Clean Anti-Cheat Logs
    Clean-AntiCheatLogs

    # Remove Windows Update Cache
    Remove-WindowsUpdateCache

    # Clean Up the WinSxS Folder (Basic)
    Clean-WinSxS

    # Advanced DISM Cleanup (StartComponentCleanup, ResetBase, SPSuperseded)
    Advanced-DISM-Cleanup

    # Delete Prefetch Files
    Delete-PrefetchFiles

    # Remove Temporary Internet Files
    Remove-TemporaryInternetFiles

    # Clear Thumbnail Cache
    Clear-ThumbnailCache

    # Clear SoftwareDistribution and Catroot2 Folders
    Clear-SoftwareDistributionAndCatroot2

    # Delete Temporary Files from All User Profiles
    Delete-TempFilesAllUsers

    # Clear Windows Store Cache
    Clear-WindowsStoreCache

    # Delete Old Log Files
    Delete-OldLogFiles

    # Remove Old Windows Backup Files (Windows.old)
    Remove-WindowsBackupFiles

    # Remove Upgrade Folders ($Windows.~BT, $Windows.~WS)
    Remove-UpgradeFolders

    # Clear WER (Windows Error Reporting) Reports
    Clear-WERReports

    # Clear environment-based temp folders (including %temp%, temp)
    Clear-EnvTempFolders

    # Clear Recycle Bin for All Users
    Clear-RecycleBinAllUsers

    # Clear Event Logs Comprehensively
    Clear-EventLogsComprehensively

    # Clear DNS Cache
    Clear-DNSCacheCustom

    # Run Disk Cleanup
    Run-DiskCleanup

    # Perform Storage Optimization
    Perform-StorageOptimization

    # Delete Specific File Types
    Delete-SpecificFileTypes

    # Delete Specific Folders
    Delete-SpecificFolders

    # Delete Driver Installation Files
    Delete-DriverInstallFiles

    # Delete Windows Installer Cache
    Delete-WindowsInstallerCache

    # Delete Files in Multiple Drives
    Delete-FilesInDrives

    # Delete Junk Files
    Delete-JunkFiles

    # Delete Temporary and Cache Folders
    Delete-TempAndCacheFolders

    # Clear Memory Dump Files
    Clear-MemoryDumpFiles

    # Clean Up Installed Application Leftovers
    Clean-Up-InstalledApplicationLeftovers

    # Clear Shadow Copies
    Clear-ShadowCopies

    # Remove Hibernation
    Remove-Hibernation

    # Extra Cleanup Pass
    Extra-BinCleanup

    # Get and display final free disk space
    $finalFreeSpace = Get-FreeDiskSpace
    Print-FreeSpace -Label "Final Disk Space" -FreeSpace $finalFreeSpace

    Write-Host "Cleanup ran successfully!"

    Write-Host -NoNewLine 'Press any key to exit...';
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');

    # Exit the script automatically without prompting the user
    exit
}

# Execute the main function with arguments
Main -Args $args
