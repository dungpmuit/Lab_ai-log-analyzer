# AI Security SOC Agent

An AI Agent system automatic analyzes server logs, rates security threats by LLM AP, automatic problem responses (SOAR) and send real-time alerts via a **Telegram Bot**.

The project is performance-optimized using **Multi-threading** to process large log files concurrently.

---

## Features

* Automated Log Parsing**: Reads and extracts essential log data (IP, Port, Failed logins).
* AI-Powered Threat Analysis**: Utilizes `Gemini 3.5 Flash` to evaluate attack contexts, assess threat risk levels (Low/Medium/High/Critical), and recommend immediate remadiation steps for system administrators.
* Multi-threaded Execution**: Employs `concurrent.futures.ThreadPoolExecutor` to process multiple high-risk IPs concurrently, significantly cutting down API wait times.
* SOAR Active Response**: Automatically extracts and appends policy-violating IP addresses to a local blacklist `blacklisted_ips.txt`.
* Real-time Telegram Alerting**: Connects with the Telegram Bot API to deliver imediate push notifications to SOC Analysts upon dectecting threats.
* Security Best Practices**: Manages sensitive credentials (API Keys and Bot Tokens) securely via environment variables ('.env') to prevent secret exposure on public repositories.
* **AI Security & Guardrails (Production-Ready)**:
  * **Prompt Isolation (XML Delimiters)**: Wraps raw log entries inside `<raw_log_data>` tags to prevent **Indirect Prompt Injection (OWASP LLM01)** and instruction hijacking.
  * **Structured Output Enforcement (JSON Schema)**: Enforces strict JSON responses from Gemini to ensure deterministic output parsing and prevent execution crashes.
  * **Deterministic Tuning**: Configured with low `temperature` for consistent, objective threat scoring.

## System Architecture & Workflow

```text
[ Server Logs ] 
       │
       ▼
[ Log Parser & Threat Detection ] ──(Safe IP)──► [ Pass / Ignore ]
       │
 (Suspicious IP)
       │
       ├──────────────────────────────────────────┐
       ▼                                          ▼
[ Multi-threaded Worker Pool ]          [ Local Blacklist ]
       │                           (Save to blacklisted_ips.txt)
       ▼
[ Gemini AI Analysis Engine ]
       │
       ▼
[ Telegram Bot Notification ] ──► 🚨 Real-time Alert to Telegram
```

## Getting Started

### 1.Prerequisites
* Python 3.9+
* A Telegram Account (with a Bot created via `@BotFather`)
* A Google Gemini API Key

### 2.Installation

1. Clone the repository:
    ```bash
    git clone [https://github.com/dungpmuit/Lab_ai-log-analyzer.git](https://github.com/dungpmuit/Lab_ai-log-analyzer.git)
    cd Lab_ai-log-analyzer
    ```
2. Create and activate a Virtual Environment:
    ```bash
    python3 -m venv .venv
    source .venv/bin/activate
    ```
3. Install required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## Configuration
* Create a `.env` file in the root directory of the project and populate it with your
    secret keys:

    ```bash
    GEMINI_API_KEY=your_gemini_api_key_here
    TELEGRAM_BOT_TOKEN=your_telegram_bot_token_here
    TELEGRAM_CHAT_ID=your_telegram_chat_id_here
    ```

## Usage

### 1. Add or edit log entries in `server_logs.txt`:
    192.168.1.10,80,0
    10.0.0.15,22,5
    172.16.0.4,443,1

### 2. Run the AI SOC Agent:
    python3 log_file_analyzer.py

### 3. Sample AI Output (Structured JSON)
```json
{
  "threat_type": "SSH Brute-Force",
  "risk_level": "HIGH",
  "recommended_action": "Isolate the host immediately and block SSH access.",
  "summary": "Internal IP 192.168.1.99 performed 100 failed login attempts on port 22."
}
```

## Project Structure
    Lab_ai-log-analyzer/
    ├── .env                  # Environment variables (Excluded from Git)
    ├── .gitignore            # Git ignore configuration
    ├── log_file_analyzer.py  # Core script for AI SOC Agent
    ├── server_logs.txt       # Sample input log file
    ├── blacklisted_ips.txt   # Output file containing blocked IP addresses
    ├── requirements.txt      # Python dependencies list
    └── README.md             # Project documentation
    

## Author

* Dung Pham Minh
* Github: @dungpmuit

## 🛣️ Roadmap

- [x] Multi-threaded log processing
- [x] SOAR Automation (Blacklist + Telegram Alerts)
- [x] AI Guardrails (XML Isolation & JSON Output Enforcement)
- [ ] Threat Intelligence Enrichment (AbuseIPDB API Integration)
- [ ] Vector DB / Semantic Search for anomaly detection


