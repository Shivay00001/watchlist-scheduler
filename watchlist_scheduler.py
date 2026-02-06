#!/usr/bin/env python3
"""
watchlist_scheduler.py
Daily scheduler that monitors your HackerOne program watchlist,
runs passive recon, and notifies you via Telegram/Slack on new findings.
"""

import os
import json
import time
import hashlib
import logging
from datetime import datetime, timedelta
from pathlib import Path
import schedule
import requests
from dotenv import load_dotenv

# Import your existing orchestrator
from auto_bounty_orchestrator import PassiveRecon, triage_findings, build_markdown_report

load_dotenv()

# Configuration
WATCHLIST_FILE = "watchlist.json"
STATE_FILE = "scheduler_state.json"
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")
SCHEDULE_HOUR = "03:00"  # Run at 3 AM daily
LOG_FILE = "watchlist_scheduler.log"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

class WatchlistManager:
    def __init__(self):
        self.watchlist = self.load_watchlist()
        self.state = self.load_state()
    
    def load_watchlist(self):
        """Load programs to monitor from watchlist.json"""
        if not os.path.exists(WATCHLIST_FILE):
            default = {
                "programs": [
                    {
                        "name": "Example Corp",
                        "handle": "example-corp",
                        "url": "https://example.com",
                        "priority": "high",
                        "enabled": True
                    }
                ]
            }
            with open(WATCHLIST_FILE, 'w') as f:
                json.dump(default, f, indent=2)
            print(f"[+] Created default {WATCHLIST_FILE} - edit it to add your programs")
        
        with open(WATCHLIST_FILE, 'r') as f:
            return json.load(f)
    
    def load_state(self):
        """Load previous scan state to detect new findings"""
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE, 'r') as f:
                return json.load(f)
        return {"scans": {}}
    
    def save_state(self):
        with open(STATE_FILE, 'w') as f:
            json.dump(self.state, f, indent=2)
    
    def get_findings_hash(self, findings):
        """Create hash of findings to detect changes"""
        findings_str = json.dumps(sorted([f.get('title','') + f.get('url','') for f in findings]))
        return hashlib.sha256(findings_str.encode()).hexdigest()
    
    def scan_program(self, program):
        """Run passive recon on a program"""
        url = program['url']
        handle = program['handle']
        
        logging.info(f"Starting scan for {handle}: {url}")
        print(f"\n[*] Scanning {program['name']} ({handle})...")
        
        try:
            # Run passive recon
            recon = PassiveRecon(url, max_pages=30, rate_limit=1.0)
            recon.fetch_robots()
            recon.fetch_sitemap()
            tls = recon.get_tls_info()
            recon.crawl()
            
            findings = recon.findings
            mapped = triage_findings(findings)
            
            # Check if findings are new
            current_hash = self.get_findings_hash(findings)
            previous_hash = self.state['scans'].get(handle, {}).get('findings_hash', '')
            
            scan_result = {
                'timestamp': datetime.utcnow().isoformat(),
                'findings_count': len(findings),
                'findings_hash': current_hash,
                'findings': mapped,
                'pages_visited': len(recon.visited)
            }
            
            # Update state
            self.state['scans'][handle] = scan_result
            self.save_state()
            
            # Notify if new findings
            if current_hash != previous_hash and findings:
                self.notify_new_findings(program, scan_result)
            
            logging.info(f"Scan completed for {handle}: {len(findings)} findings")
            return scan_result
            
        except Exception as e:
            logging.error(f"Scan failed for {handle}: {e}")
            print(f"[!] Error scanning {handle}: {e}")
            return None
    
    def notify_new_findings(self, program, scan_result):
        """Send notification about new findings"""
        findings_count = scan_result['findings_count']
        message = f"""
🎯 *New Findings Detected*

Program: {program['name']} ({program['handle']})
Target: {program['url']}
Findings: {findings_count}
Timestamp: {scan_result['timestamp']}

Top Findings:
"""
        # Add top 3 findings to message
        for i, finding in enumerate(scan_result['findings'][:3], 1):
            message += f"\n{i}. {finding.get('title')} - {finding.get('severity')}"
        
        # Send to Telegram
        if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
            self.send_telegram(message)
        
        # Send to Slack
        if SLACK_WEBHOOK_URL:
            self.send_slack(message)
        
        print(f"[+] Notification sent for {program['handle']}")
    
    def send_telegram(self, message):
        """Send message via Telegram Bot"""
        try:
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
            data = {
                "chat_id": TELEGRAM_CHAT_ID,
                "text": message,
                "parse_mode": "Markdown"
            }
            resp = requests.post(url, json=data, timeout=10)
            if resp.status_code == 200:
                logging.info("Telegram notification sent")
            else:
                logging.warning(f"Telegram failed: {resp.status_code}")
        except Exception as e:
            logging.error(f"Telegram error: {e}")
    
    def send_slack(self, message):
        """Send message via Slack Webhook"""
        try:
            data = {"text": message}
            resp = requests.post(SLACK_WEBHOOK_URL, json=data, timeout=10)
            if resp.status_code == 200:
                logging.info("Slack notification sent")
            else:
                logging.warning(f"Slack failed: {resp.status_code}")
        except Exception as e:
            logging.error(f"Slack error: {e}")
    
    def run_daily_scan(self):
        """Run scan for all enabled programs in watchlist"""
        print(f"\n{'='*60}")
        print(f"Starting Daily Scan - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}")
        
        enabled_programs = [p for p in self.watchlist['programs'] if p.get('enabled', True)]
        print(f"[+] Found {len(enabled_programs)} enabled programs")
        
        results = []
        for program in enabled_programs:
            result = self.scan_program(program)
            if result:
                results.append(result)
            # Rate limit between programs
            time.sleep(5)
        
        print(f"\n[✓] Daily scan completed. Scanned {len(results)} programs.")
        logging.info(f"Daily scan completed: {len(results)} programs scanned")

def setup_watchlist():
    """Interactive setup for adding programs to watchlist"""
    print("\n=== Watchlist Setup ===")
    print("Add HackerOne programs you want to monitor daily\n")
    
    watchlist = {"programs": []}
    
    while True:
        print("\nAdd a program:")
        name = input("Program name (e.g., 'Uber'): ").strip()
        if not name:
            break
        
        handle = input("H1 handle (e.g., 'uber'): ").strip()
        url = input("Target URL (e.g., 'https://uber.com'): ").strip()
        priority = input("Priority (high/medium/low) [high]: ").strip() or "high"
        
        watchlist['programs'].append({
            "name": name,
            "handle": handle,
            "url": url,
            "priority": priority,
            "enabled": True
        })
        
        more = input("\nAdd another? (y/n): ").strip().lower()
        if more != 'y':
            break
    
    with open(WATCHLIST_FILE, 'w') as f:
        json.dump(watchlist, f, indent=2)
    
    print(f"\n[+] Watchlist saved to {WATCHLIST_FILE}")
    print(f"[+] Added {len(watchlist['programs'])} programs")

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Watchlist Scheduler - Daily Bug Bounty Automation")
    parser.add_argument("--setup", action="store_true", help="Setup watchlist interactively")
    parser.add_argument("--run-now", action="store_true", help="Run scan immediately (bypass schedule)")
    parser.add_argument("--daemon", action="store_true", help="Run as daemon (scheduled)")
    args = parser.parse_args()
    
    if args.setup:
        setup_watchlist()
        return
    
    manager = WatchlistManager()
    
    if args.run_now:
        manager.run_daily_scan()
        return
    
    if args.daemon:
        print(f"[+] Scheduler started. Will run daily at {SCHEDULE_HOUR}")
        print("[+] Press Ctrl+C to stop")
        
        # Schedule daily scan
        schedule.every().day.at(SCHEDULE_HOUR).do(manager.run_daily_scan)
        
        # Keep running
        try:
            while True:
                schedule.run_pending()
                time.sleep(60)
        except KeyboardInterrupt:
            print("\n[!] Scheduler stopped")
    else:
        print("Usage:")
        print("  --setup      Setup watchlist")
        print("  --run-now    Run scan immediately")
        print("  --daemon     Run as scheduled daemon")

if __name__ == "__main__":
    main()