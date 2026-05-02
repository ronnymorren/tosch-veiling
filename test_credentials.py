import os
import sys
import smtplib
from pathlib import Path
from email.mime.text import MIMEText
from dotenv import load_dotenv

# Zorg dat de .env altijd gevonden wordt naast dit script
load_dotenv(dotenv_path=Path(__file__).parent / ".env", override=True)

# Windows terminal: UTF-8 forceren
sys.stdout.reconfigure(encoding="utf-8")

def test_anthropic():
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
        msg = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=10,
            messages=[{"role": "user", "content": "Zeg alleen: OK"}]
        )
        print("✓ Anthropic API: werkt")
    except Exception as e:
        print(f"✗ Anthropic API: {e}")

def test_gmail():
    try:
        addr = os.getenv("GMAIL_ADDRESS")
        pwd = os.getenv("GMAIL_APP_PASSWORD")
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(addr, pwd)
        print("✓ Gmail SMTP: werkt")
    except Exception as e:
        print(f"✗ Gmail SMTP: {e}")

def test_duckduckgo():
    try:
        from ddgs import DDGS
        results = list(DDGS().images("iPhone 15 Pro", max_results=1))
        if results:
            print(f"✓ DuckDuckGo afbeeldingen: werkt ({results[0]['image'][:60]}...)")
        else:
            print("✗ DuckDuckGo afbeeldingen: geen resultaten")
    except Exception as e:
        print(f"✗ DuckDuckGo afbeeldingen: {e}")

if __name__ == "__main__":
    print("=== Credentials test ===\n")
    test_anthropic()
    test_gmail()
    test_duckduckgo()
    print("\n=== Klaar ===")
