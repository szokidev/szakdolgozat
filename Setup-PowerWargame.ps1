<#
.SYNOPSIS
  PowerWargames - Complete 20-level PowerShell learning game with educational tasks
  Progressive difficulty covering essential PowerShell commands
#>

#region --- Configuration ---
$BasePath = "C:\PowerWargame"
$DockerPath = Join-Path $BasePath "Docker"
$FlagsFile = Join-Path $BasePath "Flags.json"
$ProgressFile = Join-Path $BasePath "progress.json"
$NumLevels = 20
$FlagPrefix = "FLAG-"
$FlagLength = 12
$ReadmeFileName = "readme.txt"
$LauncherPath = Join-Path $BasePath "Start-PowerWargame.ps1"
#endregion

#region --- Helper Functions ---
function Ensure-RunningAsAdmin {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Error "This script must be run as Administrator."
        exit 1
    }
}

function New-RandomFlag {
    param([int]$length = $FlagLength)
    $chars = ([char[]]"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
    -join (1..$length | ForEach-Object { $chars | Get-Random })
}

function Get-Sha256Hash {
    param([string]$InputString)
    
    $Bytes = [System.Text.Encoding]::UTF8.GetBytes($InputString) 
    $SHA256 = [System.Security.Cryptography.SHA256]::Create()
    
    $HashBytes = $SHA256.ComputeHash($Bytes)
    $HashString = [System.BitConverter]::ToString($HashBytes) -replace '-'
    
    return $HashString.ToLower()
}


function Path-Ensure {
    param([string]$p)
    if (-not (Test-Path $p)) { New-Item -Path $p -ItemType Directory -Force | Out-Null }
}

function Test-Docker {
    try {
        $null = Get-Command docker -ErrorAction Stop
        docker version | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Docker detected and running!" -ForegroundColor Green
            return $true
        }
    } catch {
        Write-Host "Docker is not running or not accessible." -ForegroundColor Red
        return $false
    }
    return $false
}

function Cleanup-OldContainers { 
    Write-Host "Cleaning up old PowerWargames containers..." -ForegroundColor Yellow
    
    for ($i = 1; $i -le $NumLevels; $i++) {
        $containerName = "level$i"
        docker stop $containerName 2>$null
        docker rm $containerName 2>$null
    }
    
    Write-Host "Cleanup completed." -ForegroundColor Green
}

function Create-Dockerfile {
    param([int]$level, [string]$flag)
    
    $levelPath = Join-Path $DockerPath "level$level"
    Path-Ensure $levelPath
    
    # CACHE BUSTER
    $buildId = (Get-Date).Ticks 

    if ($level -eq 5) {
        # Level 5: runtime environment variable
        $dockerfileContent = @"
FROM mcr.microsoft.com/powershell:7.4-ubuntu-22.04

# CACHE BUSTER: Ez a sor kényszeríti az újraépítést minden Setup futtatáskor
ENV BUILD_ID=$buildId

RUN apt-get update && apt-get install -y \
    file \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir /app
WORKDIR /app

COPY . /app/

ENV LEVEL_FLAG=PLACEHOLDER_FLAG_DO_NOT_USE

RUN chmod -R 755 /app

CMD [ "pwsh", "-NoExit", "-Command", "Write-Host 'Welcome to PowerWargames Level $level!'; Write-Host 'Check the readme.txt file for instructions.'; Set-Location /app" ]
"@
    } else {
        # Minden más szint
        $dockerfileContent = @"
FROM mcr.microsoft.com/powershell:7.4-ubuntu-22.04

# CACHE BUSTER: Ez a sor kényszeríti az újraépítést minden Setup futtatáskor
ENV BUILD_ID=$buildId

RUN apt-get update && apt-get install -y \
    file \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir /app
WORKDIR /app

COPY . /app/

ENV LEVEL_FLAG=PLACEHOLDER_FLAG_DO_NOT_USE

RUN chmod -R 755 /app

CMD [ "pwsh", "-NoExit", "-Command", "Write-Host 'Welcome to PowerWargames Level $level!'; Write-Host 'Check the readme.txt file for instructions.'; Set-Location /app" ]
"@
    }
    
    $dockerfileContent | Out-File -FilePath (Join-Path $levelPath "Dockerfile") -Encoding UTF8
}

function Build-DockerImage {
    param([int]$level)
    
    $levelPath = Join-Path $DockerPath "level$level"
    Write-Host "Building Docker image for level $level..." -ForegroundColor Cyan
    
    docker build --platform linux/amd64 --no-cache -t "powerwargames-level$level" $levelPath
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Failed to build Docker image for level $level" -ForegroundColor Red
        return $false
    }
    return $true
}

function Create-FreshContainers {
    Write-Host "Creating fresh containers..." -ForegroundColor Yellow
    
    for ($i = 1; $i -le $NumLevels; $i++) {
        $containerName = "level$i"
        Write-Host "Creating container: $containerName" -ForegroundColor Cyan
        
        docker stop $containerName 2>$null
        docker rm $containerName 2>$null
        
        docker run -d --name $containerName -it "powerwargames-level$i"
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Failed to create container for level $i" -ForegroundColor Red
            return $false
        }
    }
    
    Write-Host "All containers created successfully." -ForegroundColor Green
    return $true
}
#endregion

#region --- Level Implementation Functions ---

function Install-Level1 {
    param($levelPath, $flag)
    # Level 1: Basic File Reading (Kis bemelegítés)
    $welcomePath = Join-Path $levelPath "instruction_manual.txt"
    @"
Welcome to PowerWargames [Hard Edition].
This is the only easy level. Enjoy it while it lasts.

Your mission is to retrieve the flag.
The flag is: $flag

Command: Get-Content
"@ | Out-File -FilePath $welcomePath -Encoding UTF8
}

function Install-Level2 {
    param($levelPath, $flag)
    # Level 2: Deep Directory & Hidden Items
    $startDir = Join-Path $levelPath "Sector7"
    New-Item -Path $startDir -ItemType Directory -Force | Out-Null
    
    # Zaj generálás: Sok üres mappa
    1..10 | ForEach-Object { New-Item -Path (Join-Path $startDir "Zone_$_") -ItemType Directory -Force | Out-Null }
    
    $targetDir = Join-Path $startDir "Zone_4\Restricted\Archives"
    New-Item -Path $targetDir -ItemType Directory -Force | Out-Null
    
    $hiddenFile = Join-Path $targetDir ".secret_config"
    $flag | Out-File -FilePath $hiddenFile -Encoding UTF8
    
    # Olvashatóvá tesszük a fájlt (Linuxon alapból rejtett a ponttal kezdődő fájl)
    $readmePath = Join-Path $levelPath "readme.txt"
    @"
Level 2 - Hide and Seek
The flag is hidden deep within 'Sector7'.
The file name starts with a dot (.) which often denotes hidden files in Linux/Unix systems.

Task: Find the file and read it.
Hint: Get-ChildItem -Recurse -Force
"@ | Out-File -FilePath $readmePath -Encoding UTF8
}

function Install-Level3 {
    param($levelPath, $flag)
    # Level 3: Massive Log Analysis
    $logsDir = Join-Path $levelPath "Logs"
    New-Item -Path $logsDir -ItemType Directory -Force | Out-Null
    $logFile = Join-Path $logsDir "server_trace.log"
    
    Write-Host "  [Lvl3] Generating massive log file..." -ForegroundColor Cyan
    
    $logLevels = "INFO", "DEBUG", "WARN", "TRACE"
    $components = "AuthService", "Database", "NetworkStack", "UI", "Kernel"
    
    # 3000 sor zaj
    1..3000 | ForEach-Object {
        $timestamp = (Get-Date).AddSeconds(-$_).ToString("yyyy-MM-dd HH:mm:ss")
        $lvl = $logLevels | Get-Random
        $comp = $components | Get-Random
        "$timestamp [$lvl] [$comp] Operation ID-$_ completed. Latency: $(Get-Random -Min 10 -Max 500)ms" | Out-File -FilePath $logFile -Append -Encoding UTF8
    }
    
    # Flag elrejtése egyedi mintával
    $hiddenEntry = "2024-01-01 00:00:00 [CRITICAL] [Kernel] MEMORY DUMP: $flag"
    $content = Get-Content $logFile
    $content[(Get-Random -Min 1000 -Max 2000)] = $hiddenEntry
    $content | Set-Content $logFile
    
    $readmePath = Join-Path $levelPath "readme.txt"
    @"
Level 3 - Log Analysis
The server crashed. The administrators say there is a 'CRITICAL' kernel memory dump hidden in the 'Logs/server_trace.log'.
The log file contains thousands of entries.

Task: Filter the log to find the CRITICAL Kernel message.
Hint: Select-String or Where-Object
"@ | Out-File -FilePath $readmePath -Encoding UTF8
}

function Install-Level4 {
    param($levelPath, $flag)
    # Level 4: Complex Job/Object Investigation
    $scriptPath = Join-Path $levelPath "service_manager.ps1"
    
    @"
# Run this script to start the services
Write-Host "Starting simulated services..."
`$jobs = @()
1..20 | ForEach-Object {
    `$jobs += Start-Job -ScriptBlock { Start-Sleep 300 } -Name "Service_`$_"
}

# The flag is hidden in the 'Note' property of Service_13
`$targetJob = `$jobs | Where-Object Name -eq 'Service_13'
`$targetJob | Add-Member -MemberType NoteProperty -Name "DebugNote" -Value "FLAG: $flag"

Write-Host "Services started. 20 Background jobs are running."
Write-Host "One of the services (Service_13) is behaving oddly."
Write-Host "Inspect the properties of the job object itself."
"@ | Out-File -FilePath $scriptPath -Encoding UTF8

    $readmePath = Join-Path $levelPath "readme.txt"
    @"
Level 4 - Object Inspection
Run '.\service_manager.ps1' to start background jobs.
The flag is NOT in the output of the job.
The flag is hidden as a PROPERTY on the 'Service_13' job object.

Task: Find the job named 'Service_13' and inspect all its properties (even hidden ones).
Hint: Get-Job | Where ... | Select-Object *
"@ | Out-File -FilePath $readmePath -Encoding UTF8
}

function Install-Level5 {
    param($levelPath, $flag)
    # Level 5: Environment Variables with Noise
    $scriptPath = Join-Path $levelPath "init_env.ps1"
    @"
# Setting up environment...
1..50 | ForEach-Object {
    [Environment]::SetEnvironmentVariable("SYSTEM_VAR_`$_", "RandomData_`$(Get-Random)", "Process")
}
[Environment]::SetEnvironmentVariable("X_SECRET_CONFIG_X", "$flag", "Process")
Write-Host "Environment variables initialized."
"@ | Out-File -FilePath $scriptPath -Encoding UTF8

    $readmePath = Join-Path $levelPath "readme.txt"
    @"
Level 5 - Environment Scavenging
Run '.\init_env.ps1'. This script floods the environment with variables.
The flag is in a variable that contains the word 'SECRET' in its NAME.

Task: List all environment variables and filter by Name.
Hint: Get-ChildItem Env:
"@ | Out-File -FilePath $readmePath -Encoding UTF8
}

function Install-Level6 {
    param($levelPath, $flag)
    # Level 6: File Attributes & Stream simulation
    $vaultDir = Join-Path $levelPath "Vault"
    New-Item -Path $vaultDir -ItemType Directory -Force | Out-Null
    
    $file = Join-Path $vaultDir "empty_looking_file.txt"
    "Nothing to see here." | Out-File -FilePath $file -Encoding UTF8
    

    $flagFile = Join-Path $vaultDir "system_config.dat"
    $flag | Out-File -FilePath $flagFile -Encoding UTF8
   
    
    $readmePath = Join-Path $levelPath "readme.txt"
    @"
Level 6 - File Attributes
In the 'Vault' directory, there are files.
One file is marked as ReadOnly (Mode r--).

Task: Find the file that has ReadOnly attributes and read it.
Hint: Get-ChildItem | Where-Object { `$_.Mode -like '*r--*' }
"@ | Out-File -FilePath $readmePath -Encoding UTF8
}

function Install-Level7 {
    param($levelPath, $flag)
    # Level 7: Massive History Analysis
    $historyFile = Join-Path $levelPath ".bash_history_simulation"
    
    Write-Host "  [Lvl7] Generating history noise..." -ForegroundColor Cyan
    $cmds = "ls -la", "cd /var/www", "vim config.php", "git status", "docker ps", "netstat -tulpen"
    
    1..2000 | ForEach-Object {
        $cmd = $cmds | Get-Random
        "$cmd" | Out-File -FilePath $historyFile -Append -Encoding UTF8
    }
    
    # A flag elrejtése egy echo parancsban
    "echo '$flag' > /tmp/secret" | Out-File -FilePath $historyFile -Append -Encoding UTF8
    
    1..500 | ForEach-Object {
        $cmd = $cmds | Get-Random
        "$cmd" | Out-File -FilePath $historyFile -Append -Encoding UTF8
    }
    
    $readmePath = Join-Path $levelPath "readme.txt"
    @"
Level 7 - Forensic History
We recovered a command history file: '.bash_history_simulation'.
The attacker typed a command that echoes the flag.

Task: Search through the thousands of history lines to find the 'echo' command containing the flag.
"@ | Out-File -FilePath $readmePath -Encoding UTF8
}

function Install-Level8 {
    param($levelPath, $flag)
    # Level 8: Exact File Size Hunt 
    $baseDir = Join-Path $levelPath "Storage"
    New-Item -Path $baseDir -ItemType Directory -Force | Out-Null
    
    Write-Host "  [Lvl8] Generating file maze..." -ForegroundColor Cyan
    
    for ($i = 1; $i -le 10; $i++) {
        $subPath = Join-Path $baseDir "Sector_$i"
        New-Item -Path $subPath -ItemType Directory -Force | Out-Null
        for ($j = 1; $j -le 5; $j++) {
            $f = Join-Path $subPath "data_$(Get-Random).dat"
            $size = Get-Random -Min 100 -Max 2000
            if ($size -eq 1337) { $size = 1338 }
            [IO.File]::WriteAllBytes($f, (New-Object Byte[] $size))
        }
    }
    
    $targetDir = Join-Path $baseDir "Sector_$(Get-Random -Min 1 -Max 10)"
    $targetPath = Join-Path $targetDir "artifact.dat"
    $flagBytes = [Text.Encoding]::UTF8.GetBytes("FLAG: $flag")
    $padding = New-Object Byte[] (1337 - $flagBytes.Length)
    [IO.File]::WriteAllBytes($targetPath, ($padding + $flagBytes))
    
    $readmePath = Join-Path $levelPath "readme.txt"
    @"
Level 8 - The 1337 Byte Mystery
Somewhere in the 'Storage' directory tree, there is a file that is EXACTLY 1337 bytes in size.
The name is unknown. The content is mostly binary garbage, but the flag is at the end.

Task: Find the file by size and read the end of it.
Hint: Get-ChildItem -Recurse | Where-Object Length -eq ...
"@ | Out-File -FilePath $readmePath -Encoding UTF8
}

function Install-Level9 {
    param($levelPath, $flag)
    # Level 9: HTTP Header Manipulation
    $webDir = Join-Path $levelPath "WebServer"
    New-Item -Path $webDir -ItemType Directory -Force | Out-Null
    
    $serverScript = Join-Path $levelPath "start_secure_server.ps1"
    @"
Write-Host "Starting SECURE web server..."
try {
    `$listener = New-Object System.Net.HttpListener
    `$listener.Prefixes.Add('http://localhost:8080/')
    `$listener.Start()
    Write-Host 'Server listening on 8080. Authenticated Agents only.'
    
    while (`$listener.IsListening) {
        `$ctx = `$listener.GetContext()
        `$req = `$ctx.Request
        `$resp = `$ctx.Response
        
        if (`$req.UserAgent -eq 'PowerWargames-Agent') {
            `$msg = "ACCESS GRANTED. Flag: $flag"
            `$code = 200
        } else {
            `$msg = "ACCESS DENIED. Invalid User-Agent. Required: 'PowerWargames-Agent'"
            `$code = 403
        }
        
        `$buf = [Text.Encoding]::UTF8.GetBytes(`$msg)
        `$resp.StatusCode = `$code
        `$resp.OutputStream.Write(`$buf, 0, `$buf.Length)
        `$resp.Close()
    }
} catch { Write-Host "Error starting server" }
"@ | Out-File -FilePath $serverScript -Encoding UTF8
    
    $readmePath = Join-Path $levelPath "readme.txt"
    @"
Level 9 - HTTP Headers
Start the server: .\start_secure_server.ps1
Open a new terminal to interact.

The server rejects standard requests (403 Forbidden).
It requires a specific 'User-Agent' header: 'PowerWargames-Agent'.

Task: Use Invoke-WebRequest with the custom User-Agent to get the flag.
"@ | Out-File -FilePath $readmePath -Encoding UTF8
}

function Install-Level10 {
    param($levelPath, $flag)
    # Level 10: Logic Bug Fix (Infinite Loop)
    $brokenScript = Join-Path $levelPath "fix_me.ps1"
    @"
# This script is supposed to decrypt the flag but it hangs forever!
# FIX THE LOGIC. DO NOT JUST READ THE VARIABLE.

`$encrypted = "FLAG_HOLDER"
`$key = "$flag" 
`$i = 0

# BUG: This loop never ends because `$i` is never incremented!
while (`$i -lt 5) {
    Write-Host "Decrypting part `$i..."
    Start-Sleep -Milliseconds 100
    # Missing increment here!
}

Write-Host "Decryption complete: `$key"
"@ | Out-File -FilePath $brokenScript -Encoding UTF8
    
    $readmePath = Join-Path $levelPath "readme.txt"
    @"
Level 10 - Infinite Loop Debugging
The script 'fix_me.ps1' hangs forever because of a logic error (infinite loop).

Task:
1. Analyze the script.
2. Fix the loop logic so it terminates.
3. Run the fixed script to get the flag.
"@ | Out-File -FilePath $readmePath -Encoding UTF8
}

function Install-Level11 {
    param($levelPath, $flag)
    # Level 11: Double Encoding (Hex -> Base64)
    # Először Base64, aztán a Base64 string Hexává alakítva
    $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($flag))
    $hex = ($b64 | ForEach-Object { [System.BitConverter]::ToString([Text.Encoding]::UTF8.GetBytes($_)) }) -replace '-'
    
    $encodedFile = Join-Path $levelPath "mystery_code.txt"
    $hex | Out-File -FilePath $encodedFile -Encoding UTF8
    
    $readmePath = Join-Path $levelPath "readme.txt"
    @"
Level 11 - Onion Encoding
The content of 'mystery_code.txt' is encoded in layers.
Layer 1: Hexadecimal string
Layer 2: Base64 string

Task:
1. Convert the Hex string back to text (which is the Base64).
2. Decode the Base64 to get the flag.
Hint: -split '..' can help with regex splitting if needed, or looping through chars.
"@ | Out-File -FilePath $readmePath -Encoding UTF8
}

function Install-Level12 {
    param($levelPath, $flag)
    # Level 12: Dirty CSV Data 
    $csvFile = Join-Path $levelPath "payroll.csv"
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("ID;Name;Salary;Note")
    
    1..50 | ForEach-Object {
        $s = Get-Random -Min 20000 -Max 80000
        $lines.Add("$_;Worker_$_;`$$s;None") # $ jel a szám előtt!
    }
    
    
    $lines.Add("99;THE_TARGET;`$9,999,999;FLAG:$flag")
    
    51..100 | ForEach-Object {
        $s = Get-Random -Min 20000 -Max 60000
        $lines.Add("$_;Worker_$_;`$$s;None")
    }
    
    $lines | Out-File -FilePath $csvFile -Encoding UTF8
    
    $readmePath = Join-Path $levelPath "readme.txt"
    @"
Level 12 - Dirty Data
The 'payroll.csv' uses semicolons (;) and the Salary column contains '$' and ',' characters (e.g., `$50,000).

Task:
1. Import the CSV correctly.
2. Clean the Salary column (remove symbols).
3. Convert to Number (Int/Double).
4. Find the employee with the HIGHEST salary. The flag is in their Note.
"@ | Out-File -FilePath $readmePath -Encoding UTF8
}

function Install-Level13 {
    param($levelPath, $flag)
    # Level 13: Complex JSON Filtering
    $jsonFile = Join-Path $levelPath "data_dump.json"
    
    Write-Host "  [Lvl13] Generating JSON..." -ForegroundColor Cyan
    
    $users = @()
    1..50 | ForEach-Object {
        $users += @{ id = $_; name = "User$_"; role = "guest"; active = $false }
    }
    
    # A célpont elrejtve
    $users += @{ id = 999; name = "ADMIN"; role = "superadmin"; active = $true; metadata = @{ secret_key = $flag } }
    
    $data = @{
        timestamp = (Get-Date).ToString()
        system_status = "OK"
        database = @{
            users = $users
            logs = @("log1", "log2")
        }
    }
    
    $data | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonFile -Encoding UTF8
    
    $readmePath = Join-Path $levelPath "readme.txt"
    @"
Level 13 - JSON Drilling
'data_dump.json' contains a nested structure.
Deep inside 'database.users', there is ONE user with role 'superadmin'.

Task:
1. Parse the JSON.
2. Drill down to the users array.
3. Filter for the 'superadmin'.
4. Retrieve the 'metadata.secret_key' property.
"@ | Out-File -FilePath $readmePath -Encoding UTF8
}

function Install-Level14 {
    param($levelPath, $flag)
    # Level 14: Timestamp Hunting
    $timeDir = Join-Path $levelPath "Archive"
    New-Item -Path $timeDir -ItemType Directory -Force | Out-Null
    
    Write-Host "  [Lvl14] Time manipulation..." -ForegroundColor Cyan
    
    
    1..100 | ForEach-Object {
        $f = Join-Path $timeDir "doc_$_.txt"
        "noise" | Out-File $f
        $randDay = Get-Random -Min 1 -Max 365
        (Get-Item $f).LastWriteTime = (Get-Date).AddDays(-$randDay)
    }
    
    # A célpont: 2020-01-01
    $target = Join-Path $timeDir "ancient_scroll.txt"
    "Flag: $flag" | Out-File $target
    (Get-Item $target).LastWriteTime = Get-Date -Date "2020-01-01 12:00:00"
    
    $readmePath = Join-Path $levelPath "readme.txt"
    @"
Level 14 - Time Traveler
In the 'Archive' directory, find the file that was modified on:
January 1st, 2020 (2020-01-01).

Task: Filter files by LastWriteTime.
Hint: Get-ChildItem | Where-Object { `$_.LastWriteTime.Date -eq ... }
"@ | Out-File -FilePath $readmePath -Encoding UTF8
}

function Install-Level15 {
    param($levelPath, $flag)
    # Level 15: Module with Mandatory Parameter
    $modDir = Join-Path $levelPath "BlackBox"
    New-Item -Path $modDir -ItemType Directory -Force | Out-Null
    $modFile = Join-Path $modDir "BlackBox.psm1"
    
    @"
function Get-VaultContent {
    param(
        [Parameter(Mandatory=`$true)]
        [string]`$AccessCode
    )
    
    if (`$AccessCode -eq 'OPEN_SESAME') {
        return 'The flag is: $flag'
    } else {
        return 'Access Denied. Wrong code.'
    }
}
Export-ModuleMember -Function Get-VaultContent
"@ | Out-File -FilePath $modFile -Encoding UTF8
    
    $readmePath = Join-Path $levelPath "readme.txt"
    @"
Level 15 - Module Parameter Analysis
Import the module 'BlackBox/BlackBox.psm1'.
It has a function 'Get-VaultContent'.
If you run it without parameters, it asks for an 'AccessCode'.
The logic inside the module reveals the correct code.

Task:
1. Import the module.
2. Read the module content (Get-Content) OR examine the function logic to find the required AccessCode.
3. Run the function with the correct code.
"@ | Out-File -FilePath $readmePath -Encoding UTF8
}

function Install-Level16 {
    param($levelPath, $flag)
    # Level 16: Pipeline Filtering
    $logsDir = Join-Path $levelPath "SystemLogs"
    New-Item -Path $logsDir -ItemType Directory -Force | Out-Null
    $csvFile = Join-Path $logsDir "memory_dump.csv"
    
    Write-Host "  [Lvl16] Generating memory dump..." -ForegroundColor Cyan
    
    $procs = 1..1000 | ForEach-Object {
        [PSCustomObject]@{
            Id = $_
            Name = (Get-Random "svchost","chrome","pwsh","system")
            Mem = (Get-Random -Min 1000 -Max 100000000)
            Desc = "Normal"
        }
    }
    
    $target = [PSCustomObject]@{
        Id = 4048
        Name = "data_miner"
        Mem = 600000000 # > 500MB
        Desc = "FLAG: $flag"
    }
    
    ($procs + $target) | Sort-Object {Get-Random} | Export-Csv $csvFile -NoTypeInformation
    
    $readmePath = Join-Path $levelPath "readme.txt"
    @"
Level 16 - Pipeline Filtering
Analyze 'SystemLogs/memory_dump.csv'.
Find the process that matches ALL these criteria:
1. Name is 'data_miner'
2. Mem is greater than 500,000,000
3. Id is an EVEN number

The flag is in the Description.
Hint: Import-Csv | Where { ... -and ... -and ... }
"@ | Out-File -FilePath $readmePath -Encoding UTF8
}

function Install-Level17 {
    param($levelPath, $flag)
    # Level 17: De-obfuscation
    $malware = Join-Path $levelPath "suspect_script.ps1"
    
    # Karakterkódokból összerakott flag
    $chars = [char[]]$flag
    $payload = ($chars | ForEach-Object { "[char]$([int]$_)" }) -join "+"
    
    @"
# WARNING: OBFUSCATED CODE
# DO NOT RUN (Invoke-Expression) BLINDLY!
# Figure out what the string contains.

`$s = $payload
Write-Host "If I ran this, I would print the flag."
# To solve: Print `$s instead of executing it.
"@ | Out-File -FilePath $malware -Encoding UTF8
    
    $readmePath = Join-Path $levelPath "readme.txt"
    @"
Level 17 - De-obfuscation
'suspect_script.ps1' contains obfuscated code constructing a string from character codes.
Task: Determine the value of variable `$s WITHOUT running the dangerous parts.
Hint: You can edit the script or run just the variable definition part.
"@ | Out-File -FilePath $readmePath -Encoding UTF8
}

function Install-Level18 {
    param($levelPath, $flag)
    # Level 18: File Hash / Duplicate Hunt
    $dir = Join-Path $levelPath "Clones"
    New-Item -Path $dir -ItemType Directory -Force | Out-Null
    
    Write-Host "  [Lvl18] Attack of the Clones..." -ForegroundColor Cyan
    
    # 50 fájl ugyanazzal a tartalommal
    $dummyContent = "This is a decoy file."
    1..50 | ForEach-Object {
        $dummyContent | Out-File (Join-Path $dir "file_$_.txt")
    }
    
    # 1 fájl aminek más a hash-e (mert a flag van benne)
    $flag | Out-File (Join-Path $dir "file_27.txt")
    
    $readmePath = Join-Path $levelPath "readme.txt"
    @"
Level 18 - Broken Clone
In the 'Clones' directory, there are 51 files.
50 of them are identical (same content, same hash).
1 of them is different (contains the flag).

Task: Calculate the Hash (SHA256 or MD5) of all files and find the unique one.
Hint: Get-FileHash
"@ | Out-File -FilePath $readmePath -Encoding UTF8
}

function Install-Level19 {
    param($levelPath, $flag)
    # Level 19: Dynamic XOR Encryption
    $key = 123
    $bytes = [Text.Encoding]::UTF8.GetBytes($flag)
    $enc = $bytes | ForEach-Object { $_ -bxor $key }
    $b64 = [Convert]::ToBase64String($enc)
    
    $f = Join-Path $levelPath "encrypted.dat"
    $b64 | Out-File $f -Encoding UTF8
    
    $readmePath = Join-Path $levelPath "readme.txt"
    @"
Level 19 - XOR Decryption
'encrypted.dat' contains a Base64 string.
This string is the result of XOR encryption.
The Key is: 123

Task:
1. FromBase64String
2. XOR each byte with 123
3. Convert bytes to String (UTF8)
"@ | Out-File -FilePath $readmePath -Encoding UTF8
}

function Install-Level20 {
    param($levelPath, $flag)
    # Level 20: The Boss Fight
    $finalDir = Join-Path $levelPath "FinalBoss"
    New-Item -Path $finalDir -ItemType Directory -Force | Out-Null
    
    # Stage 1: Split flag into parts
    if ($flag.Length -gt 5) {
        $part1 = $flag.Substring(0, 5)
        $part2 = $flag.Substring(5)
    } else {
        $part1 = "FLAG-"
        $part2 = "ERROR"
    }
    
    # String megfordítása 
    $charArray = [char[]]$part2
    [array]::Reverse($charArray)
    $reversedPart2 = -join $charArray
    
    # Create a complex object
    $obj = @{
        Hint = "The flag is split."
        Part1 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($part1))
        Part2_Instructions = "Reverse this string: $reversedPart2"
    }
    
    $json = $obj | ConvertTo-Json
    $json | Out-File (Join-Path $finalDir "artifact.json") -Encoding UTF8
    
    $readmePath = Join-Path $levelPath "readme.txt"
    @"
Level 20 - The Final Exam
Analyze 'FinalBoss/artifact.json'.

It contains:
1. Part 1 of the flag: Base64 encoded.
2. Part 2 of the flag: Reversed plaintext string.

Task:
1. Decode Part 1.
2. Reverse Part 2 back to normal.
3. Combine them to get the full flag.

Good luck, Administrator.
"@ | Out-File -FilePath $readmePath -Encoding UTF8
}

#endregion

#region --- Main Setup Logic ---
Ensure-RunningAsAdmin

Write-Host "PowerWargames Setup - Optimized for Speed & Stability..." -ForegroundColor Green

# --- 1. TAKARÍTÁS (Deep Clean) ---
Write-Host "Performing clean sweep..." -ForegroundColor Magenta

# Konténerek leállítása és törlése
$oldContainers = docker ps -a --filter "name=level" --format "{{.Names}}"
if ($oldContainers) { 
    Write-Host "Removing old containers..." -ForegroundColor Gray
    docker stop $oldContainers 2>$null
    docker rm $oldContainers 2>$null 
}

# Régi imagek törlése
Write-Host "Removing old images..." -ForegroundColor Gray
docker rmi "powerwargames-base" -f 2>$null
$oldImages = docker images --format "{{.Repository}}:{{.Tag}}" | Where-Object { $_ -like "powerwargames-level*" }
foreach ($img in $oldImages) { docker rmi -f $img 2>$null }

# Cache ürítés a biztonság kedvéért
#docker builder prune -f -a | Out-Null

# Config fájlok törlése
if (Test-Path $FlagsFile) { Remove-Item $FlagsFile -Force }
if (Test-Path $ProgressFile) { Remove-Item $ProgressFile -Force }

if (-not (Test-Docker)) { Write-Host "Please start Docker Desktop." -ForegroundColor Red; exit 1 }

Write-Host "Creating base directories..." -ForegroundColor Yellow
Path-Ensure $BasePath; Path-Ensure $DockerPath

# --- 2. BASE IMAGE BUILDELÉSE ---
Write-Host "Step 1/3: Building Base Image (Downloads updates ONCE)..." -ForegroundColor Cyan

$baseDockerfile = @"
FROM mcr.microsoft.com/powershell:7.4-ubuntu-22.04
RUN apt-get update && apt-get install -y file && rm -rf /var/lib/apt/lists/*
RUN mkdir /app
WORKDIR /app
RUN chmod -R 755 /app
"@

$baseDockerPath = Join-Path $DockerPath "base"
Path-Ensure $baseDockerPath
$baseDockerfile | Out-File -FilePath (Join-Path $baseDockerPath "Dockerfile") -Encoding UTF8

# Build Base Image
docker build --platform linux/amd64 -t "powerwargames-base" $baseDockerPath
if ($LASTEXITCODE -ne 0) {
    Write-Host "CRITICAL ERROR: Failed to build Base Image. Check Internet connection." -ForegroundColor Red
    exit 1
}
Write-Host "Base Image Ready! Level generation will be instant." -ForegroundColor Green


# --- 3. FLAGEK ÉS TARTALOM GENERÁLÁSA ---
Write-Host "Step 2/3: Generating game content..." -ForegroundColor Yellow
$flagsMap = @{}

for ($i = 1; $i -le $NumLevels; $i++) {
    $levelKey = "level$i"
    $plainTextFlag = $FlagPrefix + (New-RandomFlag -length $FlagLength)
    $flagHash = Get-Sha256Hash -InputString $plainTextFlag
    
    # Hint szövegek:
    $hintText = switch ($i) {
        1 { "Read the 'instruction_manual.txt'. Command: Get-Content." }
        2 { "The file starts with a dot (.) and is hidden in 'Sector7'. Use: Get-ChildItem -Recurse -Force." }
        3 { "Search for 'CRITICAL' in the kernel logs. Use: Select-String or Where-Object." }
        4 { "The flag is a Property of the job object, not in the output. Use: Get-Job | Select-Object *" }
        5 { "List all environment variables and filter for 'SECRET'. Use: Get-ChildItem Env:" }
        6 { "Look for a file with ReadOnly attribute (Mode contains 'r'). Use: Get-ChildItem | Where-Object Mode -like '*r*'" }
        7 { "Search the history file for the 'echo' command. Use: Select-String 'echo'" }
        8 { "Find the file that is EXACTLY 1337 bytes. Use: Get-ChildItem -Recurse | Where-Object Length -eq 1337" }
        9 { "The server requires a specific User-Agent header. Use: Invoke-WebRequest -UserAgent 'PowerWargames-Agent'" }
        10 { "The script has an infinite loop. Edit it to increment `$i, or read the variable directly." }
        11 { "It's double encoded. First Convert Hex to String, then decode Base64." }
        12 { "Clean the Salary column (remove '$' and ','), cast to [int], and find the max value." }
        13 { "Parse the JSON, find the user with 'superadmin' role, and check metadata." }
        14 { "Filter files where LastWriteTime.Year is 2020. Use: Where-Object { `$_.LastWriteTime.Year -eq 2020 }" }
        15 { "Read the module source code to find the required password for the function." }
        16 { "Filter the CSV: Name='data_miner', Mem > 500MB, Id is Even. Remember to cast Mem to [int]." }
        17 { "Don't run the script! Print the variable `$s to see the flag. It's de-obfuscation." }
        18 { "Calculate hashes of all files. 50 are identical, 1 is unique. Use: Get-FileHash" }
        19 { "Decode Base64, then XOR each byte with 123, then convert to String." }
        20 { "Decode Part1 (Base64). Reverse the string of Part2. Join them together." }
        Default { "No hint available." }
    }
    
    $flagsMap[$levelKey] = @{ "flagHash"=$flagHash; "flag"=$plainTextFlag; "level"=$i; "hint"=$hintText }
}

# --- 4. SZINTEK ÉPÍTÉSE (FAST MODE - OFFLINE) ---
Write-Host "Step 3/3: Building Level Images (Offline Mode)..." -ForegroundColor Yellow

for ($i = 1; $i -le $NumLevels; $i++) {
    $levelKey = "level$i"
    $levelPath = Join-Path $DockerPath $levelKey
    $flag = $flagsMap[$levelKey].flag
    
    Path-Ensure $levelPath
    
    # Feladatfájlok generálása
    switch ($i) {
        1 { Install-Level1 -levelPath $levelPath -flag $flag }
        2 { Install-Level2 -levelPath $levelPath -flag $flag }
        3 { Install-Level3 -levelPath $levelPath -flag $flag }
        4 { Install-Level4 -levelPath $levelPath -flag $flag }
        5 { Install-Level5 -levelPath $levelPath -flag $flag }
        6 { Install-Level6 -levelPath $levelPath -flag $flag }
        7 { Install-Level7 -levelPath $levelPath -flag $flag }
        8 { Install-Level8 -levelPath $levelPath -flag $flag }
        9 { Install-Level9 -levelPath $levelPath -flag $flag }
        10 { Install-Level10 -levelPath $levelPath -flag $flag }
        11 { Install-Level11 -levelPath $levelPath -flag $flag }
        12 { Install-Level12 -levelPath $levelPath -flag $flag }
        13 { Install-Level13 -levelPath $levelPath -flag $flag }
        14 { Install-Level14 -levelPath $levelPath -flag $flag }
        15 { Install-Level15 -levelPath $levelPath -flag $flag }
        16 { Install-Level16 -levelPath $levelPath -flag $flag }
        17 { Install-Level17 -levelPath $levelPath -flag $flag }
        18 { Install-Level18 -levelPath $levelPath -flag $flag }
        19 { Install-Level19 -levelPath $levelPath -flag $flag }
        20 { Install-Level20 -levelPath $levelPath -flag $flag }
    }
    
    $flagsMap[$levelKey].folder = $levelPath

    # CACHE BUSTER ID
    $buildId = (Get-Date).Ticks

    # OPTIMALIZÁLT DOCKERFILE:
    $dockerfileContent = @"
FROM powerwargames-base:latest
ENV BUILD_ID=$buildId
COPY . /app/
ENV LEVEL_FLAG=PLACEHOLDER_FLAG_DO_NOT_USE
CMD [ "pwsh", "-NoExit", "-Command", "Write-Host 'Welcome to PowerWargames Level $i!'; Write-Host 'Check the readme.txt file for instructions.'; Set-Location /app" ]
"@
    $dockerfileContent | Out-File -FilePath (Join-Path $levelPath "Dockerfile") -Encoding UTF8
    
    # Buildelés   
    Write-Host "Building Level $i..." -NoNewline -ForegroundColor Cyan
    docker build --platform linux/amd64 -t "powerwargames-level$i" $levelPath | Out-Null
    if ($LASTEXITCODE -eq 0) { Write-Host " OK" -ForegroundColor Green } else { Write-Host " ERROR" -ForegroundColor Red }
}


# --- 5. BIZTONSÁGOS CONFIG MENTÉS ---
Write-Host "Saving secure configuration..." -ForegroundColor Yellow
$flagsToSave = @{}
foreach ($key in $flagsMap.Keys) {
    $entry = $flagsMap[$key]
    $flagsToSave[$key] = @{ "flagHash"=$entry.flagHash; "level"=$entry.level; "hint"=$entry.hint; "folder"=$entry.folder }
}
$flagsToSave | ConvertTo-Json -Depth 5 | Out-File -FilePath $FlagsFile -Encoding UTF8

$progress = @{ currentLevel = 1; unlockedLevels = @(1) }
$progress | ConvertTo-Json -Depth 5 | Out-File -FilePath $ProgressFile -Encoding UTF8


# --- 6. LAUNCHER GENERÁLÁS ---
Write-Host "Creating launcher..." -ForegroundColor Yellow
$launcherContent = @'
param()

$BasePath = "C:\PowerWargame"
$ProgressFile = Join-Path $BasePath "progress.json"
$FlagsFile = Join-Path $BasePath "Flags.json"

# --- Helper Functions ---
function Get-Sha256Hash {
    param([string]$InputString)
    $Bytes = [System.Text.Encoding]::UTF8.GetBytes($InputString)
    $SHA256 = [System.Security.Cryptography.SHA256]::Create()
    $HashBytes = $SHA256.ComputeHash($Bytes)
    return ([System.BitConverter]::ToString($HashBytes) -replace '-').ToLower()
}

function Get-CurrentProgress {
    if (Test-Path $ProgressFile) {
        return Get-Content $ProgressFile | ConvertFrom-Json
    }
    return @{ currentLevel = 1; unlockedLevels = @(1) }
}

function Update-Progress {
    param($newLevel)
    $progress = Get-CurrentProgress
    $progress.currentLevel = $newLevel
    
    if ($progress.unlockedLevels -notcontains $newLevel) {
        $progress.unlockedLevels += $newLevel
        $progress.unlockedLevels = $progress.unlockedLevels | Sort-Object | Get-Unique
    }
    
    $progress | ConvertTo-Json -Depth 5 | Out-File -FilePath $ProgressFile -Encoding UTF8
}

function Stop-AllContainers {
    Write-Host "Stopping all PowerWargames containers..." -ForegroundColor Yellow
    for ($i = 1; $i -le 20; $i++) {
        $containerName = "level$i"
        $running = docker ps --filter "name=$containerName" --format "{{.Names}}" 2>$null
        if ($running -eq $containerName) {
            docker stop $containerName 2>$null
            Write-Host "Stopped container: $containerName" -ForegroundColor Gray
        }
    }
}

function Cleanup-OldContainers {
    Write-Host "Cleaning up old PowerWargames containers..." -ForegroundColor Yellow
    for ($i = 1; $i -le 20; $i++) {
        $containerName = "level$i"
        docker stop $containerName 2>$null
        docker rm $containerName 2>$null
    }
    Write-Host "Cleanup completed." -ForegroundColor Green
}

function Remove-AllDockerImages {
    Write-Host "Stopping and removing all containers first..." -ForegroundColor Yellow
    Stop-AllContainers
    Cleanup-OldContainers
    Write-Host "Removing all PowerWargames Docker images..." -ForegroundColor Yellow
    
    # Base image törlése
    docker rmi powerwargames-base -f 2>$null
    
    $removedCount = 0
    for ($i = 1; $i -le 20; $i++) {
        $imageName = "powerwargames-level$i"
        docker rmi -f $imageName 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Removed image: $imageName" -ForegroundColor Green
            $removedCount++
        }
    }
    Write-Host "Docker images removal completed." -ForegroundColor Green
}

function Remove-GameData {
    Write-Host "Removing game data..." -ForegroundColor Yellow
    
    
    if (Test-Path $BasePath) {
        try {
            # Teljes könyvtár törlése
            Remove-Item -Path $BasePath -Recurse -Force -ErrorAction Stop
            Write-Host "All game data removed successfully." -ForegroundColor Green
            return $true
        }
        catch {
            # Ha hiba van (mert fut a script), akkor elkapjuk a hibát és szépen szólunk
            Write-Host "Warning: Could not remove the root folder '$BasePath' because this script is running inside it." -ForegroundColor Yellow
            Write-Host "The Docker images were removed, but please delete the folder manually after exiting." -ForegroundColor Cyan
            
            # Opcionális: Megpróbálhatjuk törölni a tartalmát (kivéve magát a scriptet)
            Get-ChildItem -Path $BasePath -Exclude "Start-PowerWargame.ps1" | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
            return $false
        }
    }
    return $false
}

function Start-DockerContainer {
    param($level)
    $containerName = "level$level"
    Write-Host "Starting Docker container for level $level..." -ForegroundColor Cyan
    Stop-AllContainers
    
    $exists = docker ps -a --filter "name=$containerName" --format "{{.Names}}" 2>$null
    if ($exists -ne $containerName) {
        Write-Host "Creating new container: $containerName" -ForegroundColor Yellow
        docker run -d --name $containerName -it "powerwargames-level$level" 2>$null
    } else {
        docker start $containerName 2>$null
    }
    
    Start-Sleep -Seconds 2
    if (docker ps --filter "name=$containerName" --format "{{.Names}}" 2>$null) {
        Write-Host "Container $containerName started successfully!" -ForegroundColor Green
        return $true
    }
    Write-Host "Container $containerName failed to start!" -ForegroundColor Red
    return $false
}

function Connect-To-Level {
    param($level)
    if (Start-DockerContainer -level $level) {
        Write-Host "=== Connected to Level $level ===" -ForegroundColor Green
        Write-Host "To enter the container, run this command in a NEW terminal:" -ForegroundColor Yellow
        Write-Host "  docker exec -it level$level pwsh" -ForegroundColor White -BackgroundColor Black
        Write-Host "`nTasks:" -ForegroundColor Cyan
        Write-Host "1. Go to /app"
        Write-Host "2. Read readme.txt"
        Write-Host "3. Find the flag and come back here to submit it!"
    }
}

function Show-Level {
    param($level)
    Clear-Host
    Write-Host "=== PowerWargames - Level $level ===" -ForegroundColor Yellow
    Write-Host "Instructions:" -ForegroundColor Cyan
    Write-Host "1. Use option [2] to start container"
    Write-Host "2. Connect with: docker exec -it level$level pwsh"
    Write-Host "3. Solve the task and submit flag here"
}

function Show-Hint {
    param($level)
    $flags = Get-Content $FlagsFile | ConvertFrom-Json
    $levelKey = "level$level"
    
    Write-Host "`n=== HINT SYSTEM ===" -ForegroundColor Magenta
    Write-Host "Are you sure you want a hint? (Y/N)" -ForegroundColor Yellow
    $confirm = Read-Host
    if ($confirm -eq 'Y' -or $confirm -eq 'y') {
        Write-Host "Decrypting hint..." -ForegroundColor Gray
        Start-Sleep -Seconds 1
        Write-Host "HINT: " -NoNewline -ForegroundColor Cyan
        Write-Host $flags.$levelKey.hint -ForegroundColor White
        Write-Host "`n(Don't give up! You can do it!)" -ForegroundColor Gray
    }
    Write-Host "Press Enter to continue..."
    Read-Host
}

function Submit-Flag {
    $flag = Read-Host "Enter the flag you found"
    if (-not $flag) { return $false }
    
    $flag = $flag.Trim()

    # Hashing input
    $enteredHash = Get-Sha256Hash -InputString $flag
    
    $flags = Get-Content $FlagsFile | ConvertFrom-Json
    $progress = Get-CurrentProgress
    
    for ($i = 1; $i -le 20; $i++) {
        $levelKey = "level$i"
        if ($flags.$levelKey.flagHash -eq $enteredHash) {
            Write-Host "Flag Verified! Correct!" -ForegroundColor Green
            
            if ($i -eq $progress.currentLevel) {
                $nextLevel = $i + 1
                if ($nextLevel -le 20) {
                    Update-Progress -newLevel $nextLevel
                    Write-Host "Level $i Complete! Unlocking Level $nextLevel..." -ForegroundColor Yellow
                    Start-DockerContainer -level $nextLevel
                } else {
                    Write-Host "ALL LEVELS COMPLETED! CONGRATULATIONS!" -ForegroundColor Magenta
                }
            } else {
                Write-Host "You found the flag for Level $i (You are currently on Level $($progress.currentLevel))" -ForegroundColor Gray
            }
            return $true
        }
    }
    
    Write-Host "Invalid Flag. Access Denied." -ForegroundColor Red
    Sleep -Seconds 1
    return $false
}

function Show-ContainerStatus {
    Write-Host "Current Container Status:" -ForegroundColor Cyan
    docker ps -a --filter "name=level" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>$null
}

function Reset-Progress {
    Write-Host "Resetting progress to Level 1..." -ForegroundColor Yellow
    Stop-AllContainers
    
    $progress = @{
        currentLevel = 1
        unlockedLevels = @(1)
    }
    $progress | ConvertTo-Json -Depth 5 | Out-File -FilePath $ProgressFile -Encoding UTF8
    Write-Host "Progress reset complete! You are back at Level 1." -ForegroundColor Green
}

function Show-MainMenu {
    Clear-Host
    $progress = Get-CurrentProgress
    Write-Host "=== PowerWargames ===" -ForegroundColor Green
    Write-Host "Current Level: $($progress.currentLevel)" -ForegroundColor White
    Write-Host "--------------------------"
    Write-Host "[1] Instructions"
    Write-Host "[2] Connect (Start Container)" 
    Write-Host "[3] Submit Flag"
    Write-Host "[4] Select Level"
    Write-Host "[5] Show Status"
    Write-Host "[6] Reset Progress"
    Write-Host "[7] Uninstall / Exit"
    Write-Host "[8] NEED A HINT?" -ForegroundColor Magenta
    Write-Host ""
    return Read-Host "Choose option"
}

# Main Loop
while ($true) {
    $choice = Show-MainMenu
    $progress = Get-CurrentProgress
    
    switch ($choice) {
        '1' { Show-Level -level $progress.currentLevel; Read-Host }
        '2' { Connect-To-Level -level $progress.currentLevel; Read-Host }
        '3' { if (Submit-Flag) { Read-Host } else { Start-Sleep -Seconds 1 } }
        '4' { 
            $sel = Read-Host "Select Level (1-20)"
            if ($sel -in $progress.unlockedLevels) { Update-Progress -newLevel $sel } 
        }
        '5' { Show-ContainerStatus; Read-Host }
        '6' { 
             $c = Read-Host "Reset progress? (Y/N)"
             if ($c -eq 'Y') { Reset-Progress; Read-Host }
        }
        '7' {
            Stop-AllContainers
            Cleanup-OldContainers
            $c = Read-Host "Full Uninstall (removes images/data)? (Y/N)"
            if ($c -eq 'Y') { 
            Remove-AllDockerImages; 
            Remove-GameData
            }
            exit
        }
        '8' { Show-Hint -level $progress.currentLevel }
    }
}
'@
$launcherContent | Out-File -FilePath $LauncherPath -Encoding UTF8

Write-Host "`n=== Setup Complete ===" -ForegroundColor Green
Write-Host "PowerWargames successfully installed!" -ForegroundColor Yellow
Write-Host "`nNext steps:" -ForegroundColor Cyan
Write-Host "1. Start: PowerShell -ExecutionPolicy Bypass -File `"$LauncherPath`"" -ForegroundColor White
Write-Host "2. Learn PowerShell through progressive challenges" -ForegroundColor White
#endregion