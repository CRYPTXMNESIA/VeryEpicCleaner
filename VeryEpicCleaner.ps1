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

    # Existing window size and position code (if any)
    try {
        $newWidth = 120
        $newHeight = 50
        $Host.UI.RawUI.WindowSize = New-Object System.Management.Automation.Host.Size($newWidth, $newHeight)
        $Host.UI.RawUI.BufferSize = New-Object System.Management.Automation.Host.Size($newWidth, $newHeight)
    } catch {
        Write-Host "Unable to set window size. Continuing with default size."
    }

    # try {
#     $newWidth = 120
#     $newHeight = 50
#     $Host.UI.RawUI.WindowSize = New-Object System.Management.Automation.Host.Size($newWidth, $newHeight)
#     $Host.UI.RawUI.BufferSize = New-Object System.Management.Automation.Host.Size($newWidth, $newHeight)
# } catch {
#     Write-Host "Unable to set window size. Continuing with default size."
# }

# try {
#     Add-Type @"
#     using System;
#     using System.Runtime.InteropServices;
#     public class Win32 {
#         [DllImport("user32.dll")]
#         public static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int X, int Y, int cx, int cy, uint uFlags);
#     }
# "@
#     $hwnd = (Get-Process -Id $PID).MainWindowHandle
#     $SWP_NOSIZE = 0x0001
#     $SWP_NOZORDER = 0x0004
#     $X = 100
#     $Y = 100
#     [Win32]::SetWindowPos($hwnd, [IntPtr]::Zero, $X, $Y, 0, 0, $SWP_NOSIZE -bor $SWP_NOZORDER) | Out-Null
# } catch {
#     Write-Host "Unable to set window position. Continuing without repositioning."
# }

    # **Add the Following Code to Maximize the Window**
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
    Write-Host "$paddedMessage Done."
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
                    # Suppress errors to maintain minimalistic output
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

# Function to stop and start specific services
function Stop-Start-Services {
    Start-Task -Message "> Restarting Windows Update Services..." -Task {
        $services = @("wuauserv", "bits")
        foreach ($service in $services) {
            try {
                Restart-Service -Name $service -Force -ErrorAction SilentlyContinue
            } catch {
                # Suppress errors
            }
        }
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

# Function to clean up the WinSxS folder using DISM
function Clean-WinSxS {
    Start-Task -Message "> Cleaning WinSxS Folder..." -Task {
        try {
            DISM.exe /Online /Cleanup-Image /StartComponentCleanup /Quiet /NoRestart | Out-Null
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
            # Define the Windows Store cache path
            $storeCachePath = "$env:LocalAppData\Packages\Microsoft.WindowsStore_8wekyb3d8bbwe\LocalCache\*"

            # Ensure the Store is not running
            Get-Process -Name "WinStore.App.exe" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

            # Delete the cache files
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
                "$env:windir\Prefetch\*",
                "$env:userprofile\cookies\*",
                "$env:userprofile\recent\*",
                "$env:WinDir\System32\energy-report.html"
            )
            foreach ($path in $searchPaths) {
                foreach ($pattern in $filePatterns) {
                    Remove-Item -Path "$path\$pattern" -Recurse -Force -ErrorAction SilentlyContinue
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
                "$env:Temp",
                "$env:AppData\Temp",
                "$env:AppData\LocalLow\Temp",
                "$env:AppData\Local\Microsoft\Windows\Caches"
            )
            foreach ($folder in $foldersToDelete) {
                if (Test-Path $folder) {
                    Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue
                }
            }

            # Recreate empty temporary folders
            $foldersToCreate = @(
                "$env:windir\Temp",
                "$env:windir\Prefetch",
                "$env:Temp",
                "$env:AppData\Temp",
                "$env:AppData\LocalLow\Temp",
                "$env:AppData\Local\Microsoft\Windows\Caches"
            )
            foreach ($folder in $foldersToCreate) {
                if (-not (Test-Path $folder)) {
                    New-Item -Path $folder -ItemType Directory -Force | Out-Null
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
            # Exclude all drives except C:\
            $otherDrives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -ne "C:\" } | Select-Object -ExpandProperty Root

            if ($otherDrives.Count -eq 0) {
                # No other drives found, skip cleaning
                return
            }

            $filePatterns = @("*.log", "*.old", "*.tmp", "*._mp", "*.chk", "*.bak", "*.gid", "*.trace")
            foreach ($drive in $otherDrives) {
                foreach ($pattern in $filePatterns) {
                    # Use wildcard to search recursively
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
            # Exclude all drives except C:\
            $otherDrives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -ne "C:\" } | Select-Object -ExpandProperty Root

            if ($otherDrives.Count -eq 0) {
                # No other drives found, skip cleaning
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

# Function to delete memory dump files
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
    # 1. Clear Browser Caches
    Clear-BrowserCaches

    # 2. Clean Anti-Cheat Logs
    Clean-AntiCheatLogs

    # 3. Remove Windows Update Cache
    Remove-WindowsUpdateCache

    # 4. Clean Up the WinSxS Folder
    Clean-WinSxS

    # 5. Delete Prefetch Files
    Delete-PrefetchFiles

    # 6. Remove Temporary Internet Files
    Remove-TemporaryInternetFiles

    # 7. Clear Thumbnail Cache
    Clear-ThumbnailCache

    # 8. Clear SoftwareDistribution and Catroot2 Folders
    Clear-SoftwareDistributionAndCatroot2

    # 9. Delete Temporary Files from All User Profiles
    Delete-TempFilesAllUsers

    # 10. Clear Windows Store Cache (Manually without wsreset.exe)
    Clear-WindowsStoreCache

    # 11. Delete Old Log Files
    Delete-OldLogFiles

    # 12. Remove Old Windows Backup Files
    Remove-WindowsBackupFiles

    # 13. Clear Recycle Bin for All Users
    Clear-RecycleBinAllUsers

    # 14. Clear Event Logs Comprehensively
    Clear-EventLogsComprehensively

    # 15. Clear DNS Cache
    Clear-DNSCacheCustom

    # 16. Restart Windows Update Services
    Stop-Start-Services

    # 17. Run Disk Cleanup
    Run-DiskCleanup

    # 18. Perform Storage Optimization
    Perform-StorageOptimization

    # 20. Delete Specific File Types
    Delete-SpecificFileTypes

    # 21. Delete Specific Folders
    Delete-SpecificFolders

    # 22. Delete Driver Installation Files
    Delete-DriverInstallFiles

    # 23. Delete Windows Installer Cache
    Delete-WindowsInstallerCache

    # 24. Delete Files in Multiple Drives
    Delete-FilesInDrives

    # 25. Delete Junk Files
    Delete-JunkFiles

    # 26. Delete Temporary and Cache Folders
    Delete-TempAndCacheFolders

    # 27. Clear Memory Dump Files
    Clear-MemoryDumpFiles

    # 28. Clean Up Installed Application Leftovers
    Clean-Up-InstalledApplicationLeftovers

    # 29. Clear Shadow Copies
    Clear-ShadowCopies

    # 30. Remove Hibernation
    Remove-Hibernation

    # Get and display final free disk space
    $finalFreeSpace = Get-FreeDiskSpace
    Print-FreeSpace -Label "Final Disk Space" -FreeSpace $finalFreeSpace

    # Calculate and display freed up space
    $freedSpace = $initialFreeSpace - $finalFreeSpace
    if ($freedSpace -ge 0) {
        $formattedFreedSpace = Format-Bytes -Bytes $freedSpace
        Write-Host "Freed up space: $formattedFreedSpace"
    } else {
        Write-Host "Freed up space: 0 Bytes (No additional space freed)"
    }

    Write-Host "Cleanup ran successfully!"

    Write-Host -NoNewLine 'Press any key to exit...';
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');

    # Exit the script automatically without prompting the user
    exit
}

# Execute the main function with arguments
Main -Args $args
