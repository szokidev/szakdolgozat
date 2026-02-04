# ⚔️ PowerWargames – PowerShell Learning Game

## 📖 Overview
**PowerWargames** is an educational **20-level PowerShell learning environment** designed to teach PowerShell scripting and system administration through hands-on challenges.  
Each level presents a unique task that requires using different PowerShell commands and concepts in isolated Docker containers.

---

## 🎯 Learning Objectives
- Master essential PowerShell commands  
- Learn file system navigation and manipulation  
- Understand process management and environment variables  
- Practice data parsing (CSV, JSON, logs)  
- Develop debugging and problem-solving skills  
- Learn basic encryption and string manipulation  

---

## 🛠 Prerequisites
- Windows 10/11 or Windows Server  
- Docker Desktop installed and running  
- PowerShell 5.1 or newer  
- Administrator privileges  

---

## ⚡ Quick Start

### 1️⃣ Setup the Game
```powershell
# Download the setup script and run as Administrator
PowerShell -ExecutionPolicy Bypass -File "Setup-PowerWargame.ps1"
```

### 2️⃣ Start Playing
```powershell
# After setup completes, run the launcher:
PowerShell -ExecutionPolicy Bypass -File "C:\PowerWargame\Start-PowerWargame.ps1"
```

---

## 🎮 How to Play

### 🕹 Game Structure
- 20 progressive levels with increasing difficulty  
- Educational focus – each level teaches specific PowerShell concepts  
- Container-based – each level runs in isolated Docker containers  
- Flag-based progression – find flags to unlock subsequent levels  

### 🔁 Game Flow
1. Start the launcher and view current level instructions  
2. Connect to the level container using option **[2]**  
3. Enter the container with the provided Docker command  
4. Read the `readme.txt` for level objectives  
5. Use PowerShell commands to solve the challenge  
6. Find the flag and submit it in the launcher  
7. Progress to the next level upon successful flag submission  

### 🧭 Launcher Menu Options
| Option | Description |
|:------:|-------------|
| [1] | Show current level instructions |
| [2] | Connect to current level container |
| [3] | Submit flag |
| [4] | Switch to previously completed levels |
| [5] | Show container status |
| [6] | Exit |

---

## 🏗 Level Overview

### Level 1–5: Fundamentals
- **Level 1:** File reading with `Get-Content`  
- **Level 2:** Directory exploration with `Get-ChildItem`  
- **Level 3:** Text searching with `Select-String`  
- **Level 4:** Process management with `Get-Job`  
- **Level 5:** Environment variables with `Get-ChildItem Env:`

### Level 6–10: Intermediate Skills
- **Level 6:** File permissions and attributes  
- **Level 7:** Command history analysis  
- **Level 8:** Recursive file searching  
- **Level 9:** Web content analysis  
- **Level 10:** Script debugging  

### Level 11–15: Data Processing
- **Level 11:** Base64 encoding/decoding  
- **Level 12:** CSV data analysis with `Import-Csv`  
- **Level 13:** JSON parsing with `ConvertFrom-Json`  
- **Level 14:** File timestamp analysis  
- **Level 15:** PowerShell modules  

### Level 16–20: Advanced Concepts
- **Level 16:** Process output monitoring  
- **Level 17:** String manipulation  
- **Level 18:** File size analysis  
- **Level 19:** Basic encryption (XOR)  
- **Level 20:** Multi-step puzzle challenge  

---

## 🐛 Troubleshooting

### Common Issues

#### 🧱 Docker not starting
- Ensure Docker Desktop is running  
- Run PowerShell as Administrator  

#### 🧩 Container connection issues
```powershell
# Check if containers are running
docker ps -a

# Restart specific container
docker restart levelX
```

#### 🌐 Level 9 Web Server ASCII output
Use `Invoke-RestMethod` instead of `Invoke-WebRequest`:
```powershell
Invoke-RestMethod http://localhost:8080/
```

Or decode manually:
```powershell
$response = Invoke-WebRequest http://localhost:8080/
[System.Text.Encoding]::UTF8.GetString($response.Content)
```

#### 🌿 Level 5 Environment Variables
Remember to run the setup script first:
```powershell
. .\set_env.ps1
$env:POWERWARGAME_SECRET
```

### 🔄 Reset Game
```powershell
# Stop all containers
docker stop $(docker ps -aq --filter "name=level")

# Remove all containers
docker rm $(docker ps -aq --filter "name=level")

# Reset progress files
Remove-Item "C:\PowerWargame\progress.json" -Force
```

---

## 🎓 Educational Value
This game covers essential PowerShell topics:

- **File System Operations:** Navigation, searching, permissions  
- **Text Processing:** Filtering, pattern matching, log analysis  
- **Process Management:** Job control, environment variables  
- **Data Formats:** CSV, JSON, Base64 handling  
- **Scripting:** Debugging, modules, automation  
- **Security:** Basic encryption, secure data handling  

---

## 🔧 Technical Details
- **Platform:** Docker containers running PowerShell 7.4 on Ubuntu  
- **Isolation:** Each level runs in separate containers  
- **Security:** Only one container runs at a time, preventing level skipping  
- **Persistence:** Progress saved locally in JSON files  
- **Network:** No external dependencies or internet connection required  

---

## 📝 Project Structure
```
C:\PowerWargame\
├── Docker\                  # Level containers and Dockerfiles
│   ├── level1\              # Level-specific files
│   ├── level2\
│   └── ...
├── Flags.json               # Level flags (encrypted)
├── progress.json            # Player progress tracking
└── Start-PowerWargame.ps1   # Game launcher
```

---

## 🤝 Contributing
This educational project is designed for PowerShell learners.  
You can:
- Suggest new level ideas  
- Report issues or improvements  
- Share with other PowerShell learners  

---

## ⚠️ Disclaimer
This is an **educational tool**.  
Some techniques demonstrated should be used responsibly in production environments.

---

### 🚀 Happy Learning!
**Master PowerShell one level at a time!**
