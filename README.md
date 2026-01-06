# Rootcastle Network Monitor v6.0

<p align="center">
  <img src="https://img.shields.io/badge/Platform-UWP-blue?style=for-the-badge&logo=windows" alt="Platform">
  <img src="https://img.shields.io/badge/Language-VB.NET-purple?style=for-the-badge&logo=dotnet" alt="Language">
  <img src="https://img.shields.io/badge/AI-SOFIA-00CCFF?style=for-the-badge&logo=openai" alt="AI">
  <img src="https://img.shields.io/badge/License-Proprietary-red?style=for-the-badge" alt="License">
</p>

<p align="center">
  <strong>Enterprise-Grade Network Surveillance Dashboard with AI-Powered Security Analysis</strong>
</p>

<p align="center">
  Powered by <strong>/REI</strong> — Rootcastle Engineering & Innovation
</p>

---

## 🎯 Overview

**Rootcastle Network Monitor** is a comprehensive UWP (Universal Windows Platform) network monitoring and security analysis application that combines **real-time traffic telemetry**, **host discovery**, **port scanning**, and an **AI-powered security analyst (SOFIA)** in a single operator-friendly dashboard.

Built with a distinctive Matrix-themed UI, it provides network administrators, security professionals, and IT operators with powerful visibility into network activity, potential threats, and performance metrics.

---

## ✨ Key Features

### 📡 Live Network Monitoring
- **Interface Selection**: Automatic detection of all active network interfaces
- **Real-time Throughput**: Live IN/OUT bandwidth monitoring with visual graphs
- **Traffic Visualization**: Animated topology view showing data flow direction
- **Uptime Tracking**: Session duration and connection stability monitoring
- **Protocol Distribution**: TCP/UDP/ICMP/Other packet breakdown with live counters

### 📊 Traffic Analysis
- **Bandwidth Usage**: Percentage-based utilization display
- **Traffic History**: 60-point rolling graph visualization
- **Top Talkers**: Identification of highest traffic-generating hosts
- **Application Breakdown**: Traffic categorization by service/port
- **Conversation Tracking**: Host-to-host communication monitoring

### 🔍 NMAP-Style Network Scanner
- **Multiple Scan Types**:
  - Quick Scan (common ports)
  - Full Scan (1-1024)
  - Stealth Scan
  - UDP Scan
  - Service Detection
  - OS Detection
  - Vulnerability Scan
- **Network Discovery**: /24 subnet auto-discovery
- **Custom Port Ranges**: Flexible port specification (e.g., `22,80,443` or `1-1000`)
- **CIDR Support**: Scan entire subnets with `/24` notation
- **Host Detection**: Ping-based and TCP connect scanning
- **OS Fingerprinting**: TTL-based operating system detection

### 📦 Packet Capture & Analysis
- **Live Packet Log**: Real-time packet capture display
- **Connection Tracking**: Active connection list with protocol/endpoint info
- **Packet Details**: Expandable view for individual packet inspection
- **Recording Mode**: Capture sessions for later analysis
- **Filter Support**: Protocol-based and custom expression filtering

### 🛡️ Security & Threat Detection
- **Suspicious Traffic Detection**: Configurable heuristics for anomaly detection
- **Port Scan Detection**: Identification of scanning behavior patterns
- **DoS/DDoS Indicators**: Burst traffic pattern recognition
- **TLS/PKI Analysis**:
  - TLS 1.3 / TLS 1.2 / Weak TLS counters
  - Certificate monitoring
- **DNS Security Insights**:
  - Query counting
  - NXDOMAIN tracking
  - DNS tunneling heuristics
- **Zero-Trust Visibility**: Identity/Resource/Access event logging
- **Real-time Alerts**: Configurable alert thresholds with notification feed

### 🤖 SOFIA AI Assistant (OpenRouter Integration)
- **Natural Language Queries**: Ask questions about your network in plain language
- **Multi-Language Support**: Turkish, English, German, French, Spanish, Japanese, Chinese
- **AI Model Selection**: Choose from multiple LLM providers:
  - LLaMA 3.2 3B (Free)
  - LLaMA 3.1 8B (Free)
  - Mistral 7B (Free)
  - Gemma 2 9B (Free)
  - Qwen 2.5 7B (Free)
  - DeepSeek V3 (Paid)
  - GPT-4o Mini (Paid)
  - Claude 3.5 Haiku (Paid)
- **Quick Analysis Actions**:
  - 📊 Traffic Analysis
  - 🛡️ Security Scan
  - 🔥 Firewall Recommendations
  - 📝 Executive Summary
  - 🎯 Anomaly Detection
  - 📈 Performance Analysis
  - 🔍 Top Talkers Report
  - ⚠️ Incident Response

### 📈 QoS Metrics
- **Latency Monitoring**: Real-time ping latency tracking
- **Jitter Calculation**: Network stability measurement
- **Packet Loss**: Loss percentage estimation
- **Throughput**: Mbps-based speed calculation

### 🎨 User Interface
- **Matrix-Themed Design**: Distinctive dark terminal aesthetic
- **Tabbed Navigation**: Monitor / Scanner / Security / AI sections
- **Live Terminal Output**: Real-time system event logging
- **Responsive Panels**: Collapsible detail views
- **Auto-Scroll**: Configurable log scrolling behavior

---

## 🏗️ Technical Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Rootcastle Network Monitor               │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │  UI Layer   │  │  AI Engine  │  │  Network Engine     │ │
│  │  (XAML/UWP) │  │  (SOFIA)    │  │  (System.Net)       │ │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘ │
│         │                │                     │            │
│  ┌──────┴────────────────┴─────────────────────┴──────────┐│
│  │                   Core Services                        ││
│  │  • Traffic Monitor    • Packet Capture                 ││
│  │  • Port Scanner       • Threat Detection               ││
│  │  • QoS Metrics        • Alert Management               ││
│  └────────────────────────────────────────────────────────┘│
├─────────────────────────────────────────────────────────────┤
│  External APIs: OpenRouter (AI) • ipify.org (WAN IP)       │
└─────────────────────────────────────────────────────────────┘
```

### Technology Stack
| Component | Technology |
|-----------|------------|
| Platform | Universal Windows Platform (UWP) |
| Language | VB.NET |
| UI Framework | XAML |
| Network APIs | `System.Net.NetworkInformation`, `System.Net.Sockets` |
| HTTP Client | `Windows.Web.Http` |
| JSON Processing | `Windows.Data.Json` |
| AI Integration | OpenRouter API |

---

## 📁 Project Structure

```
App1/
├── App.xaml                 # Application resources and startup
├── App.xaml.vb              # Application code-behind
├── MainPage.xaml            # Main UI layout (Matrix-themed dashboard)
├── MainPage.xaml.vb         # Core application logic
│   ├── Initialization       # App startup and timer setup
│   ├── Interface Selection  # Network adapter management
│   ├── Monitoring           # Real-time traffic capture
│   ├── UI Display           # Graph and topology rendering
│   ├── Packet Capture       # Connection tracking
│   ├── Security & Alerts    # Threat detection logic
│   ├── QoS Metrics          # Performance measurements
│   ├── SOFIA AI             # OpenRouter integration
│   └── NMAP Scanner         # Port scanning engine
├── Models.vb                # Data models
│   ├── ConnectionInfo       # Packet/connection data
│   ├── NmapHostResult       # Scan results
│   ├── CertInfo             # TLS certificate data
│   ├── AssetInfo            # Network asset inventory
│   ├── ConversationInfo     # Host communication tracking
│   ├── ZeroTrustEvent       # Security events
│   └── PacketLogEntry       # Log entries
└── Assets/                  # Application icons and images
```

---

## 🚀 Getting Started

### System Requirements
- **Operating System**: Windows 10 (Build 17763) or Windows 11
- **Development**: Visual Studio 2019/2022 with UWP workload
- **Runtime**: .NET Native / .NET 5+

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/rootcastleco/-REI-network-analyzer.git
   cd -REI-network-analyzer
   ```

2. **Open in Visual Studio**
   - Open `App1.sln`
   - Select `Debug` | `x86` or `x64`
   - Set startup project to `App1`

3. **Build and Deploy**
   - Press `F5` or select `Debug > Start Debugging`
   - Deploy to `Local Machine`

### Configuration

#### OpenRouter API Key (Required for SOFIA AI)
1. Visit [https://openrouter.ai](https://openrouter.ai)
2. Create a free account
3. Generate an API key
4. In the app, go to **Settings (⚙️)**
5. Enter your API key (format: `sk-or-v1-...`)

---

## 📖 Usage Guide

### Basic Monitoring
1. Select a network interface from the dropdown
2. Click **▶ START** to begin monitoring
3. View real-time traffic in the topology and graph panels

### Network Scanning
1. Navigate to **🔍 SCANNER** tab
2. Enter target IP or range (e.g., `192.168.1.0/24`)
3. Select scan type
4. Click **🔍 SCAN** or **🌐 DISCOVER**

### AI Analysis
1. Navigate to **🧠 SOFIA AI** tab
2. Select preferred AI model and language
3. Use quick action buttons or type a custom query
4. Review AI-generated analysis and recommendations

---

## ⚠️ Security & Ethical Use

This software is intended for **authorized network monitoring, security testing, and educational purposes only**.

### Disclaimer
- Only scan networks you own or have explicit permission to test
- Unauthorized network scanning may violate local laws
- The developers are not responsible for misuse of this tool

### Recommended Use Cases
- ✅ Monitoring your home/office network
- ✅ Security auditing with proper authorization
- ✅ Network troubleshooting and diagnostics
- ✅ Educational and learning purposes
- ❌ Scanning third-party networks without permission
- ❌ Malicious reconnaissance or attacks

---

## 📜 Intellectual Property Notice

```
╔══════════════════════════════════════════════════════════════════╗
║                    INTELLECTUAL PROPERTY NOTICE                  ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  Rootcastle Network Monitor v6.0                                 ║
║  Copyright © 2024-2025 Rootcastle Engineering & Innovation      ║
║                                                                  ║
║  All rights reserved.                                            ║
║                                                                  ║
║  This software, including but not limited to its source code,   ║
║  design, architecture, user interface, documentation, and all   ║
║  associated intellectual property, is the exclusive property    ║
║  of Rootcastle Engineering & Innovation.                        ║
║                                                                  ║
║  Unauthorized copying, modification, distribution, or use of    ║
║  this software, in whole or in part, is strictly prohibited     ║
║  without prior written consent from the copyright holder.       ║
║                                                                  ║
║  SOFIA AI Engine and the Matrix-themed UI design are            ║
║  proprietary components of this software.                       ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
```

---

## 👨‍💻 About the Developer

<table>
<tr>
<td width="150" align="center">
  <img src="https://github.com/rootcastleco.png" width="100" style="border-radius:50%">
</td>
<td>

### Batuhan Ayrıbaş
**Multidisciplinary Software & Systems Engineer**

Founder and Lead Engineer at **Rootcastle Engineering & Innovation**

With extensive hands-on experience in:
- 🖥️ Full-stack application development
- 🌐 IoT platforms and embedded systems
- 📊 Data-driven architectures
- 🔧 Applied engineering solutions

Rootcastle blends practical engineering with long-term system thinking to transform complex ideas into reliable, production-ready products.

</td>
</tr>
</table>

### Contact & Links
- 🏢 **Organization**: [Rootcastle Engineering & Innovation](https://github.com/rootcastleco)
- 📧 **Email**: Contact via GitHub
- 🔗 **Repository**: [github.com/rootcastleco/-REI-network-analyzer](https://github.com/rootcastleco/-REI-network-analyzer)

---

## 📋 Version History

| Version | Date | Changes |
|---------|------|---------|
| 6.0 | 2025 | SOFIA AI integration, Multi-language support, Enhanced scanner |
| 5.0 | 2024 | NMAP-style scanner, Threat detection, Matrix UI |
| 4.0 | 2024 | Packet capture, QoS metrics |
| 3.0 | 2024 | Traffic visualization, Topology view |
| 2.0 | 2024 | Basic monitoring features |
| 1.0 | 2024 | Initial release |

---

## 🙏 Acknowledgments

- **OpenRouter** for AI model access
- **Microsoft** for the UWP platform
- The open-source community for inspiration

---

<p align="center">
  <strong>Rootcastle Network Monitor</strong><br>
  <em>Built with precision. Designed for professionals.</em><br><br>
  <img src="https://img.shields.io/badge/Made%20with-❤️-red?style=flat-square" alt="Made with love">
  <img src="https://img.shields.io/badge/Powered%20by-/REI-00FF00?style=flat-square" alt="Powered by REI">
</p>