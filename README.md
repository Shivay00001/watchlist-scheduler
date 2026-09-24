# Watchlist Scheduler

An enterprise-grade solution engineered for high performance.

![Language](https://img.shields.io/badge/Language-Python-blue)
![Status](https://img.shields.io/badge/Status-Active-success)
![License](https://img.shields.io/badge/License-MIT-green)

## 🚀 Overview

Welcome to the **Watchlist Scheduler** repository. This project is built to deliver a robust and scalable solution tailored to modern development standards.

## ✨ Features

- **High Performance:** Optimized for speed and efficiency.
- **Scalable Architecture:** Designed to grow with your needs.
- **Clean Codebase:** Follows best practices and industry standards.
- **Secure by Default:** Engineered with security in mind.

## 🛠️ Prerequisites

Ensure you have the following installed in your environment before proceeding:
- Appropriate runtime/compiler for `Python`
- Standard development tools

## 📦 Installation

Follow standard installation steps for `Python` to set up the project locally:

1. Clone the repository:
   ```bash
   git clone https://github.com/Shivay00001/watchlist-scheduler.git
   ```
2. Navigate to the project directory:
   ```bash
   cd watchlist-scheduler
   ```
3. Install dependencies according to the standard `Python` ecosystem.

## 💻 Usage

Run the project using standard execution commands for `Python`. Ensure all environment variables and configurations are set prior to execution.

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the issues page.

## 📝 License

This project is licensed under standard terms.

---

## 🔧 Wave-1 fix notes (2026-09-24)

- **Fixed import:** `watchlist_scheduler.py` imported `auto_bounty_orchestrator`
  (`PassiveRecon`, `triage_findings`, `build_markdown_report`), which did not exist
  anywhere in the repo. Created a **real implementation** in
  `auto_bounty_orchestrator.py` — passive recon only (robots.txt, sitemap.xml, TLS
  certificate handshake, polite same-domain crawl recording passive findings such as
  exposed Server headers and leftover HTML comments), plus triage and a Markdown
  report builder. Added `beautifulsoup4` to `requirements.txt`.
- **Fixed Dockerfile:** `CMD` pointed at nonexistent `main.py`; now runs
  `watchlist_scheduler.py`.
- **Honest notifications:** the "Notification sent" message now only prints when a
  channel actually fired; otherwise it says no channels are configured.
- Verified 2026-09-24: `python watchlist_scheduler.py --run-now` scanned
  `https://example.com` end-to-end (1 page visited, 2 findings triaged, state saved,
  exit 0). Telegram/Slack not exercised (no tokens in sandbox — set
  `TELEGRAM_BOT_TOKEN`/`TELEGRAM_CHAT_ID` or `SLACK_WEBHOOK_URL` in `.env`).
- Usage: `python watchlist_scheduler.py --setup` (interactive), `--run-now` (one
  scan), `--daemon` (daily at 03:00).
