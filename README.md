# Advanced Web Application Security Testing Tool with Threat Intelligence Dashboard (WAST)

Final-year style project: a **local Flask app** that crawls a single domain (depth-limited), runs **heuristic** SQL injection and reflected XSS checks (including automatic form submissions), uses **ThreadPoolExecutor** for parallel URL work, and shows results on a **Bootstrap + Chart.js** dashboard with **VirusTotal** and **ip-api.com** threat context.

> **Legal warning:** Use only on systems you own or are **explicitly authorized** to test. Unauthorized scanning can be illegal and unethical.

## Tech stack

- **Backend:** Python 3.10+, Flask  
- **Frontend:** HTML, CSS, Bootstrap 5, Chart.js  
- **Database:** SQLite (`database.db`, created automatically)  
- **Libraries:** `requests`, `beautifulsoup4`, `urllib3` (retries). **`concurrent.futures`** is in the standard library (used via `ThreadPoolExecutor`).

## Project layout

```
Web-Testing/
├── app.py
├── config.example.ini
├── requirements.txt
├── README.md
├── database.db          # created on first run
├── logs/                # created on first run (app.log)
├── scanner/
│   ├── __init__.py
│   ├── crawler.py
│   ├── sqli.py
│   ├── xss.py
│   └── scanner.py
├── integrations/
│   ├── __init__.py
│   ├── virustotal.py
│   └── ipinfo.py
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── results.html
│   └── report.html
└── static/
    ├── style.css
    └── charts.js
```

## Installation

1. **Python 3.10+** recommended.  
2. Create a virtual environment (optional but recommended):

   ```bash
   python -m venv .venv
   .venv\Scripts\activate
   ```

3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

## API keys (`config.ini`)

1. Copy `config.example.ini` to **`config.ini`** in the project root.  
2. **VirusTotal:** paste your key from [VirusTotal API key page](https://www.virustotal.com/gui/my-apikey) into `[virustotal] api_key`.  
   - Free tier is rate-limited; the app checks only a few URLs per scan (`vt_max_urls`, `vt_delay_seconds` in `[scanner]`).  
3. **ip-api.com** is used **without a key** for non-commercial / lab use; see [ip-api.com terms](https://ip-api.com/docs/legal).

## Run the application

```bash
python app.py
```

Open **http://127.0.0.1:5000** in your browser.

`use_reloader=False` is set so background scan threads are not duplicated when the dev server reloads.

## Usage

1. On the home page, enter a target **http(s) URL** (or a hostname; `https://` is added if the scheme is missing).  
2. Click **Start scan**. You are redirected to `/results/<scan_id>`.  
3. While status is `pending` or `running`, the page **polls** `/api/scan/<id>/status` every 3 seconds and reloads when finished.  
4. Open **HTML report:** `/report/<scan_id>` (print or save as PDF from the browser).

## Rate limiting (misuse reduction)

- Approximately **one new scan per 90 seconds** per client IP (in-memory).  
- VirusTotal calls are **throttled** between URL lookups.

## Routes

| Route | Description |
|--------|-------------|
| `/` | Home — URL input |
| `POST /scan` | Start scan (redirects to results) |
| `/results/<scan_id>` | Dashboard with charts and tables |
| `/report/<scan_id>` | Printable HTML report |
| `/api/scan/<scan_id>/status` | JSON: `{ "status", "error_message" }` |

## Database schema

- **scans:** `id`, `target_url`, `timestamp`, `status`, `error_message`  
- **vulnerabilities:** `id`, `scan_id`, `type` (SQLi / XSS), `url`, `payload`, `severity`  
  - Evidence text is appended under the payload as a second line: `Evidence: ...`  
- **threat_intel:** `id`, `scan_id`, `url`, `virustotal_status`, `ip`, `country`, `isp`

## Limitations (honest scope)

- Findings are **heuristic** (pattern matching, reflection checks, length deltas). Expect **false positives and false negatives**.  
- This is **not** a replacement for professional DAST or manual review.  
- Crawling respects **same-domain** links and **max depth / max pages** caps.

## Example workflow

1. Run a local vulnerable lab app (e.g. DVWA, WebGoat) **only if you are allowed to**.  
2. Point WAST at `http://127.0.0.1/...` (or your lab URL).  
3. Review SQLi/XSS rows and cross-check with threat intel.

---

*Built for educational demonstration of secure coding, threading, REST integration, and responsible disclosure practices.*
