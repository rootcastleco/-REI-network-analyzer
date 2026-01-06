# Rootcastle Network Monitor (Rootcastle /REI)

A UWP (VB.NET) network monitoring and analysis dashboard with scanning, telemetry visualizations, security insights, and an optional SOFIA AI assistant.

> Developed by **Rootcastle Engineering & Innovation**, an independent engineering and software studio focused on building robust, scalable, and production-ready digital systems.
>
> The project is led by **Batuhan Ayrıbaş**, a multidisciplinary software and systems engineer with hands-on experience in full-stack development, IoT platforms, data-driven architectures, and applied engineering. Rootcastle blends practical engineering with long-term system thinking to turn complex ideas into reliable products.

---

## Key Features

### Monitoring & Telemetry
- Network interface selection and live monitoring
- Real-time throughput (in/out), total bytes, packet counters
- Uptime tracking
- Live traffic graph
- Protocol distribution (TCP/UDP/ICMP/Other)
- Top talkers (hosts by traffic volume)

### Security Visibility (simulation-friendly + extensible)
- Suspicious activity detection toggle
- Threat counters (port scan / DoS / ARP spoof)
- DNS insight counters (queries / NXDOMAIN / tunneling signals)
- TLS/PKI counters (TLS 1.3 / TLS 1.2 / weak) and certificate list
- Zero-trust style events list (identity → resource access)

### Scanning & Utilities
- “NMAP-like” TCP connect scanning (quick/full/custom port sets)
- Ping-based local discovery (e.g., /24)
- Host results view with open ports and basic OS guessing
- Packet sender utilities (TCP / UDP probe, ping, traceroute)

### Packet Capture & Analysis (simulation-friendly)
- Connection list and packet details panel
- Optional raw packet byte storage
- Header parsing + hex dump visualization

### SOFIA AI Assistant (Optional)
- OpenRouter chat completion integration
- Model and language selection
- Quick actions (traffic/security/performance summaries)

---

## Tech Stack

- **UWP (Universal Windows Platform)**
- **VB.NET** + XAML
- `System.Net.NetworkInformation` for interface/statistics
- `Windows.Web.Http` and `Windows.Data.Json` for optional AI calls

---

## Repository Layout

- `App1/MainPage.xaml` — Main UI
- `App1/MainPage.xaml.vb` — Monitoring/scanning/security/AI logic
- `App1/App.xaml` — App bootstrap

---

## Build & Run

### Prerequisites
- Windows 10/11
- Visual Studio 2022 (or newer)
- UWP development workload

### Steps
1. Open the project in Visual Studio.
2. Select a target architecture (x64 recommended).
3. Build and run.

---

## SOFIA AI Setup (Optional)

This project supports OpenRouter-compatible chat completions.

1. Create an API key: https://openrouter.ai/keys
2. In the app, open Settings (⚙️) and set your OpenRouter key.
3. Choose a model and language in the SOFIA AI tab.

Tip: You can use free-tier models such as `meta-llama/llama-3.2-3b-instruct:free`.

---

## Notes / Disclaimer

- Parts of the telemetry/capture/detection pipeline are **simulated** for demonstration/testing.
- True packet capture on Windows typically requires a capture driver/library (e.g., Npcap) and proper protocol parsing.
- Use responsibly. Scanning networks you do not own/manage may be illegal.
- Persist sessions (traffic history, alerts, scans) to local storage
- Add protocol-aware decoders
- Add export formats (JSON, PCAP stub/export integration)

---

## License
Specify a license for public use (e.g., MIT) or keep proprietary.

---

## Credits
- Rootcastle Engineering & Innovation
- Project Lead: Batuhan Ayrıbaş- Persistent storage for sessions
- More robust export formats (full HTML report, JSON, PCAP)
- Unit tests for parsers and heuristics

---

## License

Add your license information here (e.g., MIT/Apache-2.0). If no license is provided, default copyright applies.

---

## Credits

- Rootcastle Engineering & Innovation
- Project lead: Batuhan Ayrıbaş