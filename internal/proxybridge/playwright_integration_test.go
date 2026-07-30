package proxybridge

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestPlaywrightIntegration is opt-in because it needs a real authenticated
// SOCKS5 subscription and makes external requests. It never prints the
// upstream proxy URL or credentials.
func TestPlaywrightIntegration(t *testing.T) {
	if os.Getenv("PROXYBRIDGE_PLAYWRIGHT_TEST") != "1" {
		t.Skip("set PROXYBRIDGE_PLAYWRIGHT_TEST=1 for the external smoke test")
	}
	python := strings.TrimSpace(os.Getenv("GROK_PYTHON"))
	chrome := strings.TrimSpace(os.Getenv("CHROME_PATH"))
	upstream := strings.TrimSpace(os.Getenv("WEBSHARE_PROXY"))
	if python == "" || chrome == "" || upstream == "" {
		t.Fatal("GROK_PYTHON, CHROME_PATH, and WEBSHARE_PROXY are required")
	}
	bridge, err := Start(upstream)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, python, "-c", playwrightSmokeScript)
	command.Env = append(os.Environ(),
		"PROXYBRIDGE_URL="+bridge.URL(),
		"PROXYBRIDGE_CHROME="+chrome,
	)
	output, err := command.CombinedOutput()
	if err != nil {
		if upstreamErr := bridge.lastError(); upstreamErr != nil {
			t.Fatalf("Playwright smoke failed: %v; upstream=%v (%s)", err, upstreamErr, strings.TrimSpace(string(output)))
		}
		t.Fatalf("Playwright smoke failed: %v (%s)", err, strings.TrimSpace(string(output)))
	}
	var result struct {
		Cloudflare int `json:"cloudflare"`
		XAI        int `json:"xai"`
	}
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("decode Playwright result: %v (%s)", err, strings.TrimSpace(string(output)))
	}
	if result.Cloudflare != 200 {
		t.Fatalf("Cloudflare trace status=%d, want 200", result.Cloudflare)
	}
	if result.XAI == 0 {
		t.Fatal("accounts.x.ai returned no HTTP response")
	}
	t.Logf("Playwright proxy bridge reachable: cloudflare=%d xai=%d", result.Cloudflare, result.XAI)
}

const playwrightSmokeScript = `
import asyncio
import json
import os
from playwright.async_api import async_playwright

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(
            executable_path=os.environ["PROXYBRIDGE_CHROME"],
            headless=True,
            proxy={"server": os.environ["PROXYBRIDGE_URL"]},
            args=[
                "--disable-background-networking",
                "--disable-component-update",
                "--disable-default-apps",
                "--disable-sync",
                "--no-first-run",
            ],
        )
        page = await browser.new_page()
        cf = await page.goto(
            "https://www.cloudflare.com/cdn-cgi/trace",
            wait_until="domcontentloaded",
            timeout=20000,
        )
        xai = await page.goto(
            "https://accounts.x.ai/sign-up",
            wait_until="commit",
            timeout=20000,
        )
        print(json.dumps({
            "cloudflare": cf.status if cf else 0,
            "xai": xai.status if xai else 0,
        }))
        await browser.close()

asyncio.run(main())
`
