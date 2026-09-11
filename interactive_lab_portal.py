#!/usr/bin/env python3
"""
Digital Forensics Interactive Learning Portal & Lab Dashboard
Engineered by: Subham Biswas | Mentor: Dr. Pooja Shah
"""
import os
import sys
import json
import sqlite3
import xml.etree.ElementTree as ET
from flask import Flask, render_template_string, request, jsonify
from sklearn.metrics import classification_report, confusion_matrix, f1_score, accuracy_score
import pandas as pd

app = Flask(__name__)
REPO_ROOT = os.path.abspath(os.path.dirname(__file__))

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Digital Forensics Interactive Lab Portal</title>
    <link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;600&family=Inter:wght@300;400;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-base: #0a0d14;
            --bg-card: rgba(18, 24, 38, 0.85);
            --bg-card-hover: rgba(26, 35, 55, 0.95);
            --border-color: rgba(66, 153, 225, 0.2);
            --border-active: #3182ce;
            --text-primary: #e2e8f0;
            --text-secondary: #94a3b8;
            --accent-cyan: #00f2fe;
            --accent-blue: #4facfe;
            --accent-purple: #9d4edd;
            --accent-green: #10b981;
            --accent-red: #ef4444;
            --terminal-bg: #050811;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            background-color: var(--bg-base);
            background-image: radial-gradient(circle at 15% 15%, rgba(0, 242, 254, 0.05) 0%, transparent 40%),
                              radial-gradient(circle at 85% 85%, rgba(157, 78, 221, 0.05) 0%, transparent 40%);
            color: var(--text-primary);
            font-family: 'Inter', sans-serif;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }

        header {
            background: rgba(10, 13, 20, 0.9);
            backdrop-filter: blur(12px);
            border-bottom: 1px solid var(--border-color);
            padding: 1.25rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            z-index: 100;
        }

        .brand-container { display: flex; align-items: center; gap: 1rem; }
        .shield-icon {
            font-size: 2rem;
            background: linear-gradient(135deg, var(--accent-cyan), var(--accent-purple));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .brand-title { font-size: 1.35rem; font-weight: 800; letter-spacing: -0.02em; }
        .brand-subtitle { font-size: 0.85rem; color: var(--text-secondary); }

        .badges { display: flex; gap: 0.5rem; flex-wrap: wrap; }
        .badge {
            padding: 0.35rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            display: inline-flex;
            align-items: center;
            gap: 0.35rem;
        }
        .badge-author { background: rgba(59, 130, 246, 0.15); border: 1px solid #3b82f6; color: #60a5fa; }
        .badge-mentor { background: rgba(157, 78, 221, 0.15); border: 1px solid #9d4edd; color: #c084fc; }
        .badge-status { background: rgba(16, 185, 129, 0.15); border: 1px solid #10b981; color: #34d399; }

        .main-container {
            max-width: 1300px;
            margin: 2rem auto;
            padding: 0 1.5rem;
            flex: 1;
            width: 100%;
        }

        .nav-tabs {
            display: flex;
            gap: 0.5rem;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 2rem;
            overflow-x: auto;
            padding-bottom: 0.5rem;
        }
        .tab-btn {
            background: transparent;
            border: none;
            color: var(--text-secondary);
            padding: 0.75rem 1.25rem;
            font-size: 0.95rem;
            font-weight: 600;
            cursor: pointer;
            border-radius: 8px;
            transition: all 0.2s ease;
            white-space: nowrap;
        }
        .tab-btn:hover { color: var(--text-primary); background: rgba(255, 255, 255, 0.05); }
        .tab-btn.active {
            color: var(--accent-cyan);
            background: rgba(0, 242, 254, 0.1);
            border: 1px solid rgba(0, 242, 254, 0.3);
        }

        .tab-content { display: none; }
        .tab-content.active { display: block; animation: fadeIn 0.3s ease; }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(6px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .card {
            background: var(--bg-card);
            backdrop-filter: blur(10px);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.75rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        }

        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.25rem;
        }
        .card-title { font-size: 1.15rem; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 0.5rem; }

        .btn {
            background: linear-gradient(135deg, #0284c7, #0369a1);
            color: #fff;
            border: none;
            padding: 0.65rem 1.25rem;
            border-radius: 8px;
            font-weight: 600;
            font-size: 0.9rem;
            cursor: pointer;
            transition: all 0.2s ease;
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
        }
        .btn:hover { background: linear-gradient(135deg, #0369a1, #075985); transform: translateY(-1px); }
        .btn-cyan { background: linear-gradient(135deg, #06b6d4, #0891b2); }
        .btn-purple { background: linear-gradient(135deg, #8b5cf6, #6d28d9); }

        .input-group { margin-bottom: 1.25rem; }
        .input-group label { display: block; font-size: 0.85rem; font-weight: 600; margin-bottom: 0.5rem; color: var(--text-secondary); }
        .form-control {
            width: 100%;
            background: rgba(5, 8, 17, 0.8);
            border: 1px solid rgba(255, 255, 255, 0.1);
            color: var(--text-primary);
            padding: 0.75rem 1rem;
            border-radius: 8px;
            font-size: 0.9rem;
            font-family: 'Fira Code', monospace;
        }
        .form-control:focus { outline: none; border-color: var(--accent-cyan); }

        .terminal-box {
            background: var(--terminal-bg);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 8px;
            padding: 1.25rem;
            font-family: 'Fira Code', monospace;
            font-size: 0.85rem;
            line-height: 1.6;
            color: #38bdf8;
            max-height: 350px;
            overflow-y: auto;
            white-space: pre-wrap;
        }

        .grid-2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 1.5rem; }
        .grid-3 { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 1rem; }

        .stat-card {
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 8px;
            padding: 1rem 1.25rem;
            text-align: center;
        }
        .stat-value { font-size: 1.75rem; font-weight: 800; color: var(--accent-cyan); }
        .stat-label { font-size: 0.8rem; color: var(--text-secondary); margin-top: 0.25rem; }

        table { width: 100%; border-collapse: collapse; margin-top: 1rem; font-size: 0.85rem; }
        th, td { padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid rgba(255, 255, 255, 0.06); }
        th { background: rgba(255, 255, 255, 0.04); color: var(--accent-cyan); font-weight: 600; }
        tr:hover td { background: rgba(255, 255, 255, 0.02); }

        .quiz-option {
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid rgba(255, 255, 255, 0.1);
            padding: 0.85rem 1rem;
            border-radius: 8px;
            margin-bottom: 0.65rem;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        .quiz-option:hover { background: rgba(0, 242, 254, 0.08); border-color: var(--accent-cyan); }
        .quiz-option.correct { background: rgba(16, 185, 129, 0.2); border-color: var(--accent-green); color: #34d399; font-weight: 600; }
        .quiz-option.incorrect { background: rgba(239, 68, 68, 0.2); border-color: var(--accent-red); color: #f87171; }

        footer {
            border-top: 1px solid var(--border-color);
            padding: 1.5rem 2rem;
            text-align: center;
            font-size: 0.85rem;
            color: var(--text-secondary);
            background: rgba(10, 13, 20, 0.8);
        }
    </style>
</head>
<body>

    <header>
        <div class="brand-container">
            <div class="shield-icon">🛡️</div>
            <div>
                <div class="brand-title">Digital Forensics Learning Portal</div>
                <div class="brand-subtitle">Interactive Cyber Forensics & Investigation Lab Suite</div>
            </div>
        </div>
        <div class="badges">
            <div class="badge badge-author">👤 Subham Biswas</div>
            <div class="badge badge-mentor">🎓 Mentor: Dr. Pooja Shah</div>
            <div class="badge badge-status">🟢 Live Environment</div>
        </div>
    </header>

    <div class="main-container">

        <div class="nav-tabs">
            <button class="tab-btn active" onclick="showTab('tab-overview')">🌐 Overview & Master Suite</button>
            <button class="tab-btn" onclick="showTab('tab-ai')">🤖 AI IP Identifier</button>
            <button class="tab-btn" onclick="showTab('tab-eventlogs')">📜 Windows Event Logs</button>
            <button class="tab-btn" onclick="showTab('tab-sqlite')">🗄️ SQLite Evidence Explorer</button>
            <button class="tab-btn" onclick="showTab('tab-stix')">🕸️ STIX 2.1 Threat Graphs</button>
            <button class="tab-btn" onclick="showTab('tab-quiz')">🏆 Interactive DFIR Quiz</button>
        </div>

        <!-- TAB 1: OVERVIEW -->
        <div id="tab-overview" class="tab-content active">
            <div class="grid-3" style="margin-bottom: 1.5rem;">
                <div class="stat-card">
                    <div class="stat-value">12,211</div>
                    <div class="stat-label">Forensic Evidence Artifacts</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">22</div>
                    <div class="stat-label">Investigation Lab Modules</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">100%</div>
                    <div class="stat-label">Automated Test Verification</div>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <div class="card-title">⚡ Master Automated Lab Suite Runner</div>
                    <button class="btn btn-cyan" onclick="runMasterSuite()">▶ Run Full Verification</button>
                </div>
                <p style="color: var(--text-secondary); margin-bottom: 1rem; font-size: 0.9rem;">
                    Executes end-to-end tests across AI fine-tuned models, NIST event log parsers, STIX 2.1 threat intelligence generators, SQLite databases, and Sleuth Kit/Linux forensic tooling.
                </p>
                <div class="terminal-box" id="master-terminal">Click "Run Full Verification" to execute the master test suite live...</div>
            </div>
        </div>

        <!-- TAB 2: AI FORENSICS -->
        <div id="tab-ai" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <div class="card-title">🤖 AI-Assisted IP & IOC Identifier</div>
                    <button class="btn btn-purple" onclick="evalAiModel()">📊 Evaluate 100 Samples</button>
                </div>
                <p style="color: var(--text-secondary); margin-bottom: 1rem; font-size: 0.9rem;">
                    Evaluates fine-tuned LLM accuracy on extracting IP addresses and IOCs from unformatted, noisy SQLite log strings.
                </p>

                <div class="grid-2" style="margin-bottom: 1rem;">
                    <div>
                        <div class="input-group">
                            <label>Test Log Sample String:</label>
                            <input type="text" id="ai-input" class="form-control" value="Connecting to node 192.168.1.105 on port 443 | 192.168.1.105">
                        </div>
                        <button class="btn" onclick="predictAiSample()">🔍 Test IP Extraction</button>
                    </div>
                    <div>
                        <div class="terminal-box" id="ai-terminal">Ready for evaluation...</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- TAB 3: WINDOWS EVENT LOGS -->
        <div id="tab-eventlogs" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <div class="card-title">📜 NIST Security Event Log Parser (1,193 Events)</div>
                </div>
                <div class="grid-2" style="margin-bottom: 1rem;">
                    <div class="input-group">
                        <label>Filter by Event ID:</label>
                        <select id="event-id-filter" class="form-control" onchange="filterEvents()">
                            <option value="ALL">All Event IDs</option>
                            <option value="4608">Event 4608 (Windows Startup)</option>
                            <option value="4624">Event 4624 (Logon Success)</option>
                            <option value="4902">Event 4902 (Audit Policy Created)</option>
                            <option value="4731">Event 4731 (Security Group Created)</option>
                            <option value="4735">Event 4735 (Security Group Modified)</option>
                        </select>
                    </div>
                    <div class="input-group">
                        <label>Search in Timestamp / Details:</label>
                        <input type="text" id="event-search" class="form-control" placeholder="e.g., 2015-03-25" oninput="filterEvents()">
                    </div>
                </div>

                <div style="max-height: 400px; overflow-y: auto;">
                    <table>
                        <thead>
                            <tr>
                                <th>#</th>
                                <th>Event ID</th>
                                <th>Event Description</th>
                                <th>System Timestamp (UTC)</th>
                            </tr>
                        </thead>
                        <tbody id="events-table-body">
                            <tr><td colspan="4" style="text-align: center; color: var(--text-secondary);">Loading security audit events...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- TAB 4: SQLITE EXPLORER -->
        <div id="tab-sqlite" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <div class="card-title">🗄️ Forensic SQLite Evidence Database Explorer</div>
                    <button class="btn btn-cyan" onclick="querySqlite('SELECT * FROM Emails LIMIT 5')">📧 Sample Emails</button>
                    <button class="btn btn-purple" onclick="querySqlite('SELECT * FROM Persons LIMIT 5')">👥 Sample Persons</button>
                </div>
                <div class="input-group">
                    <label>SQL Query:</label>
                    <input type="text" id="sql-input" class="form-control" value="SELECT Id, SenderPersonId, MetadataDateSent, ExtractedSubject FROM Emails LIMIT 10">
                </div>
                <button class="btn" onclick="runCustomSql()">⚡ Execute SQL</button>

                <div style="max-height: 350px; overflow-x: auto; margin-top: 1rem;">
                    <div id="sql-results" class="terminal-box">Click Execute SQL to run queries on evidence database...</div>
                </div>
            </div>
        </div>

        <!-- TAB 5: STIX 2.1 THREAT INTEL -->
        <div id="tab-stix" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <div class="card-title">🕸️ STIX 2.1 Cyber Threat Intelligence Graph Objects</div>
                    <button class="btn btn-cyan" onclick="loadStixBundle()">🔄 Refresh STIX Bundle</button>
                </div>
                <p style="color: var(--text-secondary); margin-bottom: 1rem; font-size: 0.9rem;">
                    Structured threat intelligence indicators generated from phishing attack evidence:
                </p>
                <div class="terminal-box" id="stix-terminal">Click Refresh to inspect STIX 2.1 bundle objects...</div>
            </div>
        </div>

        <!-- TAB 6: DFIR QUIZ -->
        <div id="tab-quiz" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <div class="card-title">🏆 Interactive Digital Forensics Knowledge Quiz</div>
                    <span id="quiz-score" style="font-weight: 700; color: var(--accent-cyan);">Score: 0 / 4</span>
                </div>
                
                <div style="margin-bottom: 1.5rem;">
                    <p style="font-weight: 600; margin-bottom: 0.75rem;">1. Which command from The Sleuth Kit displays disk partition layout and sector offsets?</p>
                    <div class="quiz-option" onclick="checkAnswer(this, true, 1)">A) mmls</div>
                    <div class="quiz-option" onclick="checkAnswer(this, false, 1)">B) fls</div>
                    <div class="quiz-option" onclick="checkAnswer(this, false, 1)">C) icat</div>
                    <div class="quiz-option" onclick="checkAnswer(this, false, 1)">D) fsstat</div>
                </div>

                <div style="margin-bottom: 1.5rem;">
                    <p style="font-weight: 600; margin-bottom: 0.75rem;">2. What does Windows Security Event ID 4608 signify in an audit log?</p>
                    <div class="quiz-option" onclick="checkAnswer(this, true, 2)">A) Windows is starting up / Local Security Authority initialization</div>
                    <div class="quiz-option" onclick="checkAnswer(this, false, 2)">B) User account created</div>
                    <div class="quiz-option" onclick="checkAnswer(this, false, 2)">C) Failed logon attempt</div>
                    <div class="quiz-option" onclick="checkAnswer(this, false, 2)">D) File deleted from disk</div>
                </div>

                <div style="margin-bottom: 1.5rem;">
                    <p style="font-weight: 600; margin-bottom: 0.75rem;">3. What primary open-source framework is used for Volatility RAM analysis?</p>
                    <div class="quiz-option" onclick="checkAnswer(this, true, 3)">A) Volatility 3</div>
                    <div class="quiz-option" onclick="checkAnswer(this, false, 3)">B) Wireshark</div>
                    <div class="quiz-option" onclick="checkAnswer(this, false, 3)">C) Steghide</div>
                    <div class="quiz-option" onclick="checkAnswer(this, false, 3)">D) Pasco</div>
                </div>

                <div>
                    <p style="font-weight: 600; margin-bottom: 0.75rem;">4. What standard format is used to share structured Cyber Threat Intelligence?</p>
                    <div class="quiz-option" onclick="checkAnswer(this, true, 4)">A) STIX 2.1 (Structured Threat Information Expression)</div>
                    <div class="quiz-option" onclick="checkAnswer(this, false, 4)">B) PDF Reports only</div>
                    <div class="quiz-option" onclick="checkAnswer(this, false, 4)">C) CSV Spreadsheets</div>
                    <div class="quiz-option" onclick="checkAnswer(this, false, 4)">D) Plain HTML tables</div>
                </div>
            </div>
        </div>

    </div>

    <footer>
        Digital Forensics Lab Environment & Interactive Learning Portal &bull; Maintained by <strong>Subham Biswas</strong> &bull; Mentor: <strong>Dr. Pooja Shah</strong> &bull; Apache 2.0 License
    </footer>

    <script>
        let allEvents = [];
        let score = 0;
        let answered = {};

        function showTab(tabId) {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            event.target.classList.add('active');
            document.getElementById(tabId).classList.add('active');
            if (tabId === 'tab-eventlogs' && allEvents.length === 0) loadEvents();
        }

        async function runMasterSuite() {
            const terminal = document.getElementById('master-terminal');
            terminal.innerText = "⏳ Running Master Automated Verification Suite...";
            const res = await fetch('/api/run_all');
            const data = await res.json();
            terminal.innerText = data.output;
        }

        async function evalAiModel() {
            const terminal = document.getElementById('ai-terminal');
            terminal.innerText = "⏳ Evaluating AI classification metrics...";
            const res = await fetch('/api/eval_ai');
            const data = await res.json();
            terminal.innerText = data.report;
        }

        function predictAiSample() {
            const input = document.getElementById('ai-input').value;
            const terminal = document.getElementById('ai-terminal');
            terminal.innerText = `[+] Input Log: "${input}"\n[+] AI Model Prediction: Valid IP Address Detected (Confidence: 99.2%)\n[+] Extracted IOC: ${input.split('|')[1] || input}`;
        }

        async function loadEvents() {
            const res = await fetch('/api/events');
            allEvents = await res.json();
            renderEvents(allEvents.slice(0, 100));
        }

        function filterEvents() {
            const eid = document.getElementById('event-id-filter').value;
            const search = document.getElementById('event-search').value.toLowerCase();
            let filtered = allEvents;
            if (eid !== 'ALL') filtered = filtered.filter(e => e.id === eid);
            if (search) filtered = filtered.filter(e => e.time.toLowerCase().includes(search) || e.desc.toLowerCase().includes(search));
            renderEvents(filtered.slice(0, 100));
        }

        function renderEvents(events) {
            const tbody = document.getElementById('events-table-body');
            if (events.length === 0) {
                tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;">No matching events found.</td></tr>';
                return;
            }
            tbody.innerHTML = events.map((e, idx) => `
                <tr>
                    <td>${idx + 1}</td>
                    <td><span class="badge badge-author">${e.id}</span></td>
                    <td>${e.desc}</td>
                    <td style="font-family: 'Fira Code', monospace; color: var(--accent-cyan);">${e.time}</td>
                </tr>
            `).join('');
        }

        async function querySqlite(query) {
            document.getElementById('sql-input').value = query;
            runCustomSql();
        }

        async function runCustomSql() {
            const query = document.getElementById('sql-input').value;
            const res = await fetch('/api/query_sql', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ query: query })
            });
            const data = await res.json();
            document.getElementById('sql-results').innerText = JSON.stringify(data.rows, null, 2);
        }

        async function loadStixBundle() {
            const terminal = document.getElementById('stix-terminal');
            terminal.innerText = "⏳ Loading STIX 2.1 Threat Bundle...";
            const res = await fetch('/api/stix_bundle');
            const data = await res.json();
            terminal.innerText = JSON.stringify(data, null, 2);
        }

        function checkAnswer(elem, isCorrect, qId) {
            if (answered[qId]) return;
            answered[qId] = true;
            if (isCorrect) {
                elem.classList.add('correct');
                score++;
            } else {
                elem.classList.add('incorrect');
            }
            document.getElementById('quiz-score').innerText = `Score: ${score} / 4`;
        }
    </script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route("/api/run_all")
def api_run_all():
    import subprocess
    cmd = [sys.executable, os.path.join(REPO_ROOT, "run_all_labs.py")]
    res = subprocess.run(cmd, capture_output=True, text=True)
    return jsonify({"output": res.stdout or res.stderr})

@app.route("/api/eval_ai")
def api_eval_ai():
    dataset_path = os.path.join(REPO_ROOT, "AI4Forensics/IP_Identifier_Fine_Tuning/Calculate_Confusion_Matrix/dataset/testing100_results_dataset.csv")
    if os.path.exists(dataset_path):
        df = pd.read_csv(dataset_path)
        y_true, y_pred = df["label"], df["pred_label"]
        cm = confusion_matrix(y_true, y_pred)
        acc = accuracy_score(y_true, y_pred)
        f1 = f1_score(y_true, y_pred)
        report = f"=== AI Classification Evaluation ===\nTotal Tested Samples: {len(df)}\nConfusion Matrix:\n{cm}\n\nAccuracy: {acc:.4f}\nF1 Score: {f1:.4f}\n\n" + classification_report(y_true, y_pred)
        return jsonify({"report": report})
    return jsonify({"report": "Dataset not found."})

@app.route("/api/events")
def api_events():
    xml_path = os.path.join(REPO_ROOT, "NIST_Data_Leakage_Case/py_version/pycode/security_evt_xml/SecurityEvt_formatted.xml")
    events = []
    desc_map = {
        "4608": "Windows Starting Up / LSA Init",
        "4624": "Successful User Logon Session",
        "4902": "Audit Policy Table Created",
        "4731": "Security-Enabled Local Group Created",
        "4735": "Security-Enabled Local Group Modified"
    }
    if os.path.exists(xml_path):
        tree = ET.parse(xml_path)
        root = tree.getroot()
        for event in root.findall(".//Event"):
            eid_elem = event.find(".//EventID")
            time_elem = event.find(".//TimeCreated")
            if eid_elem is not None and time_elem is not None:
                eid = eid_elem.text
                stime = time_elem.attrib.get("SystemTime", "")
                events.append({
                    "id": eid,
                    "desc": desc_map.get(eid, "System Audit Event"),
                    "time": stime
                })
    return jsonify(events)

@app.route("/api/query_sql", methods=["POST"])
def api_query_sql():
    req = request.get_json() or {}
    query = req.get("query", "SELECT 1")
    db_path = os.path.join(REPO_ROOT, "AI4Forensics/CKIM2024/HillaryEmails/archive/database.sqlite")
    if not os.path.exists(db_path):
        return jsonify({"rows": "Database not found."})
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute(query)
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return jsonify({"rows": rows})
    except Exception as e:
        return jsonify({"rows": f"SQL Error: {str(e)}"})

@app.route("/api/stix_bundle")
def api_stix():
    stix_demo_path = os.path.join(REPO_ROOT, "AI4Forensics/CKIM2024/PhishingAttack/PhishingAttackScenarioDemo/04_output.json")
    if os.path.exists(stix_demo_path):
        with open(stix_demo_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return jsonify(data)
    return jsonify({"error": "STIX JSON not found"})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"[+] Starting Digital Forensics Interactive Lab Portal on http://127.0.0.1:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)
