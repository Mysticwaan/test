# 🛡️ Home SOC in Azure: Threat Detection with Microsoft Sentinel

![image](https://github.com/user-attachments/assets/ff2c1c0e-e3ff-4635-87d0-ef0a4d7273ef)

This project demonstrates the deployment of a **deliberately vulnerable Windows virtual machine** in Microsoft Azure for the purpose of **observing real-world brute-force attacks**. The VM sends logs to Microsoft Sentinel via Log Analytics, and login failure data is enriched with geolocation information to visualize the attack sources on a global map.

---

## 🔐 Part 1: Deploying a Vulnerable Windows VM Honeypot

### 🧱 Step 1: Create the Azure Infrastructure

1. **Create a Resource Group**
   - Open Azure Portal → "Create a resource" → "Resource Group"
   - Choose a name like `RG-SOC-Lab` and region (e.g., East US 2)
     
![image](https://github.com/user-attachments/assets/938fd769-f2d0-415e-9a72-6e41bed1c567)

2. **Set Up Virtual Network**
   - Create a VNet with a new subnet (e.g., `Vnet-soc-lab`)

![image](https://github.com/user-attachments/assets/1526ab82-d6ad-4b5c-b678-eb1dcad68359)


3. **Deploy a Windows VM**
   - Go to "Create a resource" → "Windows Server 2022 Datacenter"
   - Basic config:
     - VM name: `CORP-NET-TEAST-1`
     - Username: use a decoy (e.g., `labuser`)
     - Password: weak but still valid (e.g., `P@ssw0rd123`)
   - Public Inbound Ports: Allow RDP (port 3389)
   - Network: Use your previously created VNet and subnet
  
 ![image](https://github.com/user-attachments/assets/cfa0a427-d2a8-409a-93fc-86065e89bd9a)

4. **Disable the Internal Firewall**
   - In the VM:
     - Run `wf.msc` command to open the settings
     - Turn off Windows Defender Firewall for all profiles
     - 
![image](https://github.com/user-attachments/assets/3c980cde-af78-4651-a1fe-77d288d22ffc)

> ⚠️ **Warning:** This VM is intentionally insecure. Do not use real credentials. Monitor billing and stop/delete resources when finished.

---

### 📈 Step 2: Set Up Log Analytics

1. **Create Log Analytics Workspace**
   - Go to "Monitor" → "Logs" → "Create Log Analytics Workspace"
   - Name it `HoneypotLogs` or similar

2. **Install Azure Monitor Agent**
   - Go to the VM → "Extensions + Applications"
   - Add "Azure Monitor Agent"
   - Connect it to your Log Analytics Workspace

3. **Enable Data Collection Rules**
   - Under "Monitoring" → "Data Collection Rules"
   - Add a new rule to collect **Security Events** from your VM

---

### 🧪 Step 3: Test Logging in Log Analytics

After a few minutes of uptime, try RDP brute-forcing the machine yourself or wait for real-world bots.

#### 🔍 Run this KQL query:

```kql
SecurityEvent
| where EventID == 4625
```

This shows failed login attempts. Look for entries with `EventID 4625`, which indicate failed logins.

You can also run:

```kql
SecurityEvent
| where EventID == 4625
| summarize Count = count() by Account
```

---

## 🔍 Part 2: Enriching Logs with Geolocation + Sentinel Map

### 🌐 Step 1: Connect to Microsoft Sentinel

1. Go to "Microsoft Sentinel"
2. Create a Sentinel instance and attach it to your existing Log Analytics Workspace
3. Confirm that `SecurityEvent` logs appear in Sentinel

---

### 🗺️ Step 2: Add IP Geolocation Watchlist

1. **Download or create a geolocation CSV** with these columns:
   - `network`, `country_name`, `city_name`, `latitude`, `longitude`

2. **Create a Watchlist in Sentinel**
   - Go to Sentinel → "Configuration" → "Watchlist"
   - Name: `go`, Alias: `go`, Search key: `network`
   - Upload your CSV file

3. **Check the watchlist is working:**

```kql
_GetWatchlist('go')
```

---

### 🔁 Step 3: Enrich Security Logs with Geolocation

```kql
SecurityEvent
| where EventID == 4625
| extend AttackerIP = IPAddress
| join kind=leftouter (
    _GetWatchlist('go')
) on $left.AttackerIP == $right.network
| project TimeGenerated, Computer, AttackerIP, country_name, city_name, latitude, longitude
```

---

### 📊 Step 4: Visualize Attacks on a World Map

1. Go to Microsoft Sentinel → "Workbooks"
2. Create a new workbook
3. In the Advanced Editor, paste this (replace with your enriched query):

```kql
SecurityEvent
| where EventID == 4625
| extend AttackerIP = IPAddress
| join kind=leftouter (
    _GetWatchlist('go')
) on $left.AttackerIP == $right.network
| summarize Count = count() by country_name, city_name, latitude, longitude
```

4. Click the **Visualize** tab
   - Choose **Map**
   - Configure:
     - Latitude: `latitude`
     - Longitude: `longitude`
     - Size: `Count`
     - Tooltip: `country_name`, `city_name`

5. Save the workbook as `Windows VM Attack Map`

---

## 🧪 Example KQL Queries

**Last 10 login attempts:**

```kql
SecurityEvent
| where EventID == 4625
| top 10 by TimeGenerated desc
```

**Top attacking IPs:**

```kql
SecurityEvent
| where EventID == 4625
| summarize Count = count() by IPAddress
| top 10 by Count desc
```

**Unique attacker locations:**

```kql
SecurityEvent
| where EventID == 4625
| extend AttackerIP = IPAddress
| join kind=leftouter (
    _GetWatchlist('go')
) on $left.AttackerIP == $right.network
| summarize Count = count() by country_name, city_name
```

---

## 🧠 Lessons Learned

- **Honeypot VMs** are quickly scanned and attacked by global bots once exposed to the internet.
- **Microsoft Sentinel** can serve as a full SIEM solution with log ingestion, enrichment, alerting, and visualization.
- **KQL (Kusto Query Language)** is powerful for filtering and analyzing security data.
- **Geolocation enrichment** provides critical insight into attacker origins and behaviors.

---

## 🧯 Cleanup Resources

To avoid Azure charges:

1. Delete your VM and related disks
2. Remove the Log Analytics workspace
3. Delete the resource group (`HoneypotRG`)
4. Remove the Sentinel instance

---

## 📚 References

- [Microsoft Sentinel Docs](https://learn.microsoft.com/en-us/azure/sentinel/)
- [KQL Tutorial](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/)
- [IP Geolocation Data](https://db-ip.com/db/download/ip-to-city-lite)
- [KC7 Cyber (Free KQL Labs)](https://www.kc7cyber.com)

---

## ⚠️ Disclaimer

This lab is for **educational and research purposes only**. Never expose production systems to the internet without protection. Use test credentials only, and regularly audit your Azure usage and billing.

---
