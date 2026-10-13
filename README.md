# SOC Swarm CTI: Autonomous Multi-Agent Cyber Threat Intelligence and Breach Investigation Platform

SOC Swarm CTI is a complete, enterprise-grade, autonomous multi-agent Cyber Threat Intelligence (CTI) application powered by **Gemini 3.8 Flash** and **Vertex AI**. It continuously ingests public cyber and AI security disclosures, orchestrates an 8-agent swarm to investigate attacks, extracts defanged IOCs and behavioral IOAs, tracks incident version updates with content diffs, maintains persistent long-term memory via dense vector embeddings, and alerts analysts via formatted HTML emails with preview support.

---

## 1. Architecture Overview

### The 8 Specialized Agents
1. **Threat Discovery Agent**: Periodically polls RSS/Atom feeds (CISA Advisories, The Hacker News, BleepingComputer, SANS ISC, arXiv AI Security) and filters signal from noise.
2. **Breach Investigation Agent**: Extracts what happened, affected entities, access vectors, root causes, and explicit unknowns.
3. **IOC Extraction Agent**: Hybrid deterministic regex + LLM extraction identifying IP, domain, hash, URL, and CVE indicators with contextual roles.
4. **Attack Chain Agent**: Maps observed adversary behavior to MITRE ATT&CK techniques and extracts behavioral Indicators of Attack (IOAs).
5. **Historical RAG Agent**: Correlates new threats against historical incidents and knowledge chunks via `text-embedding-004` cosine similarity.
6. **Defensive Recommendations Agent**: Generates prioritized mitigations across Immediate, Short-term, Long-term, Detection, and Preventive categories.
7. **Evidence Verification Agent**: Acts as an independent reviewer checking claim grounding and rejecting hallucinated artifacts.
8. **Report & Notification Agent**: Formats executive alerts and dispatches emails via the Gmail API with interactive HTML previews.

---

## 2. Quickstart & Local Execution

### Option A: Streamlit 5-Minute MVP Dashboard
```bash
cd backend
uv run streamlit run ../streamlit_app.py --server.port 8501 --server.address 0.0.0.0
```
- Open in browser: `http://localhost:8501`
- Includes: Live Dashboard, Threat Intel Feed with Version History, IOC Explorer with CSV export, IOA Explorer, Gemini 3.8 Flash Threat Intel Chat, and Gmail Notification Center.

### Option B: Full-Stack React + FastAPI Application
```bash
# Terminal 1 - Backend API
cd backend
uv run python -m uvicorn app.main:app --host 0.0.0.0 --port 8000

# Terminal 2 - Frontend UI
cd frontend
npm run dev -- --host 0.0.0.0 --port 5173
```
- Frontend: `http://localhost:5173`
- Backend API Docs: `http://localhost:8000/docs`

---

## 3. Google Cloud Run Deployment

SOC Swarm CTI is containerized and ready for 1-click serverless deployment on Google Cloud Run:

```bash
chmod +x deploy_cloud_run.sh
./deploy_cloud_run.sh
```

---

## 4. Key Features

- **Grounding & Provenance**: Every IOC, MITRE technique, and timeline event is tied to source passage citations. No facts are invented.
- **AI Security & General Cyber Monitoring**: Monitors prompt injection, LLM leakage, malicious MCP tools, alongside ransomware and zero-days.
- **Incident Versioning & Update Detection**: Detects modified advisory text, preserves version history snapshots, and computes content diffs.
- **Strict IOC Defanging**: All IPs, domains, and URLs are defanged (`[.]`, `hxxp://`) to prevent accidental analyst clicks.
- **Behavioral IOA Extraction**: Extracts adversary techniques and Sigma/EDR detection queries with CSV export.
- **Prompt Injection Defense**: Advisory bodies and feed contents are treated strictly as passive evidence.
- **Gmail Integration & Preview Center**: Supports OAuth 2.0 Gmail dispatch; defaults to an interactive HTML preview center when token credentials are pending.
- **Persistent RAG Knowledge Base**: SQLite-backed dense vector store utilizing Vertex AI `text-embedding-004` (768 dimensions) for instant semantic correlation.
