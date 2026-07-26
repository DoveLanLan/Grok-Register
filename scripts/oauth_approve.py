#!/usr/bin/env python3
"""Approve an x.ai OAuth Device Flow through the real accounts.x.ai UI.

Configuration is read as one JSON document from stdin so account passwords,
SSO cookies, and device user codes never appear in the process argument list.
Stdout contains exactly one small JSON result and never echoes credentials.
"""
from __future__ import annotations

import argparse
import asyncio
import glob
import json
import os
import re
import sys
import time
from pathlib import Path
from urllib.parse import unquote, urlsplit, urlunsplit


POSITIVE_WORDS = (
    "continue",
    "allow",
    "approve",
    "authorize",
    "confirm",
    "sign in",
    "log in",
    "next",
    "继续",
    "允许",
    "同意",
    "批准",
    "授权",
    "确认",
    "登录",
    "下一步",
)
NEGATIVE_WORDS = ("deny", "cancel", "reject", "禁止", "拒绝", "取消")


def playwright_proxy(raw: str) -> dict[str, str]:
    value = (raw or "").strip()
    config = {"server": value}
    if not value:
        return config
    try:
        parsed = urlsplit(value)
        if not parsed.scheme or not parsed.hostname:
            return config
        if parsed.username is None and parsed.password is None:
            return config
        host = parsed.hostname
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        if parsed.port is not None:
            host = f"{host}:{parsed.port}"
        config["server"] = urlunsplit(
            (parsed.scheme, host, parsed.path, parsed.query, "")
        )
        if parsed.username is not None:
            config["username"] = unquote(parsed.username)
        if parsed.password is not None:
            config["password"] = unquote(parsed.password)
    except ValueError:
        return {"server": value}
    return config


def find_chrome() -> str:
    env = (os.environ.get("CHROME_PATH") or "").strip()
    if env and os.path.isfile(env):
        return env
    matches: list[str] = []
    for home in (os.path.expanduser("~"), "/root", "/home/charles"):
        if not home:
            continue
        base = os.path.join(home, ".cloakbrowser")
        matches.extend(glob.glob(os.path.join(base, "chromium-*", "chrome")))
        matches.extend(
            glob.glob(
                os.path.join(
                    base, "chromium-*", "Chromium.app", "Contents", "MacOS", "Chromium"
                )
            )
        )
    if matches:
        return sorted(matches)[-1]
    for path in (
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    ):
        if os.path.isfile(path):
            return path
    return ""


def safe_url(raw: str) -> str:
    try:
        parsed = urlsplit(raw)
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
    except ValueError:
        return ""


def validate_verification_url(raw: str) -> str:
    parsed = urlsplit(raw)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or host not in {"accounts.x.ai", "auth.x.ai"}:
        raise ValueError("verification URL is not an allowed x.ai HTTPS host")
    return raw


async def first_visible(page, selectors: tuple[str, ...]):
    for selector in selectors:
        locator = page.locator(selector)
        count = min(await locator.count(), 5)
        for index in range(count):
            item = locator.nth(index)
            try:
                if await item.is_visible():
                    return item
            except Exception:
                continue
    return None


async def element_label(element) -> str:
    for getter in (
        lambda: element.inner_text(timeout=1000),
        lambda: element.get_attribute("value", timeout=1000),
        lambda: element.get_attribute("aria-label", timeout=1000),
        lambda: element.get_attribute("title", timeout=1000),
    ):
        try:
            value = await getter()
            if value and value.strip():
                return re.sub(r"\s+", " ", value.strip())
        except Exception:
            continue
    return ""


async def click_positive_action(page) -> str:
    controls = page.locator(
        'button, input[type="submit"], input[type="button"], [role="button"]'
    )
    count = min(await controls.count(), 40)
    candidates: list[tuple[int, object, str]] = []
    for index in range(count):
        control = controls.nth(index)
        try:
            if not await control.is_visible() or not await control.is_enabled():
                continue
        except Exception:
            continue
        label = (await element_label(control)).lower()
        if not label or any(word in label for word in NEGATIVE_WORDS):
            continue
        for priority, word in enumerate(POSITIVE_WORDS):
            if word in label:
                candidates.append((priority, control, label[:80]))
                break
    if not candidates:
        return ""
    candidates.sort(key=lambda item: item[0])
    _, control, label = candidates[0]
    try:
        await control.scroll_into_view_if_needed(timeout=3000)
        await control.click(timeout=7000)
    except Exception:
        box = await control.bounding_box()
        if not box:
            return ""
        x = box["x"] + box["width"] / 2
        y = box["y"] + box["height"] / 2
        await page.mouse.move(max(0, x - 20), max(0, y - 5))
        await page.mouse.move(x, y, steps=8)
        await page.mouse.click(x, y, delay=80)
    return label


async def handle_login(page, email: str, password: str) -> str:
    email_input = await first_visible(
        page,
        (
            'input[type="email"]',
            'input[name="email"]',
            'input[autocomplete="username"]',
            'input[name="username"]',
        ),
    )
    password_input = await first_visible(
        page,
        (
            'input[type="password"]',
            'input[name="password"]',
            'input[autocomplete="current-password"]',
        ),
    )
    if email_input is None and password_input is None:
        return ""
    if not email or not password:
        raise RuntimeError("browser_login_required_but_credentials_missing")
    if email_input is not None:
        try:
            current = await email_input.input_value(timeout=1000)
        except Exception:
            current = ""
        if current.strip().lower() != email.strip().lower():
            await email_input.fill(email, timeout=5000)
    if password_input is not None:
        await password_input.fill(password, timeout=5000)
    action = await click_positive_action(page)
    if action:
        return "login:" + action
    if password_input is not None:
        await password_input.press("Enter")
        return "login:enter"
    if email_input is not None:
        await email_input.press("Enter")
        return "login:enter"
    return ""


async def click_account_choice(page, email: str) -> str:
    if not email:
        return ""
    controls = page.locator('button, a, [role="button"], [role="link"]')
    count = min(await controls.count(), 40)
    target = email.strip().lower()
    for index in range(count):
        control = controls.nth(index)
        try:
            if not await control.is_visible() or not await control.is_enabled():
                continue
            label = (await element_label(control)).lower()
            if target not in label:
                continue
            await control.click(timeout=7000)
            return "account:selected"
        except Exception:
            continue
    return ""


def authorized(url: str, body: str) -> bool:
    path = (urlsplit(url).path or "").lower()
    text = body.lower()
    return path.endswith("/oauth2/device/done") or path.endswith("/device/done") or any(
        marker in text
        for marker in (
            "device authorized",
            "device is authorized",
            "you have authorized",
            "设备已授权",
            "授权成功",
        )
    )


def failure_marker(body: str) -> str:
    text = body.lower()
    for marker in (
        "access denied",
        "authorization denied",
        "device code expired",
        "code has expired",
        "invalid code",
        "访问被拒绝",
        "授权被拒绝",
        "验证码已过期",
    ):
        if marker in text:
            return marker
    return ""


async def save_screenshot(page, diagnostic_dir: str, label: str) -> str:
    if not diagnostic_dir:
        return ""
    try:
        directory = Path(diagnostic_dir).expanduser().resolve()
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(directory, 0o700)
        path = directory / f"oauth-{label}-{int(time.time())}.png"
        await page.screenshot(path=str(path), full_page=True)
        os.chmod(path, 0o600)
        return str(path)
    except Exception:
        return ""


async def approve(config: dict) -> dict:
    from playwright.async_api import async_playwright

    verification_url = validate_verification_url(
        str(config.get("verification_url") or "").strip()
    )
    sso = str(config.get("sso") or "").strip()
    email = str(config.get("email") or "").strip()
    password = str(config.get("password") or "")
    proxy = str(config.get("proxy") or "").strip()
    diagnostic_dir = str(config.get("diagnostic_dir") or "").strip()
    timeout = max(30.0, min(float(config.get("timeout_sec") or 150), 300.0))
    headless = bool(config.get("headless", True))
    capture_success = bool(config.get("capture_success", False))
    chrome = str(config.get("chrome") or "").strip() or find_chrome()
    if not sso:
        raise ValueError("missing SSO session")
    if not chrome:
        raise RuntimeError("CloakBrowser/Chromium executable not found")

    launch: dict = {
        "executable_path": chrome,
        "headless": headless,
        "args": [
            "--no-sandbox",
            "--disable-blink-features=AutomationControlled",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-infobars",
            "--disable-dev-shm-usage",
            "--window-size=1280,900",
        ],
    }
    if proxy:
        launch["proxy"] = playwright_proxy(proxy)

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(**launch)
        page = None
        try:
            context = await browser.new_context(
                viewport={"width": 1280, "height": 900},
                locale="en-US",
                ignore_https_errors=True,
            )
            await context.add_init_script(
                'Object.defineProperty(navigator,"webdriver",{get:()=>undefined})'
            )
            await context.add_cookies(
                [
                    {
                        "name": "sso",
                        "value": sso,
                        "domain": ".x.ai",
                        "path": "/",
                        "secure": True,
                        "httpOnly": True,
                        "sameSite": "Lax",
                    }
                ]
            )
            page = await context.new_page()
            await page.goto(
                verification_url,
                timeout=min(60000, int(timeout * 1000)),
                wait_until="domcontentloaded",
            )

            deadline = time.monotonic() + timeout
            actions: list[str] = []
            while time.monotonic() < deadline:
                await page.wait_for_timeout(800)
                body = ""
                try:
                    body = await page.locator("body").inner_text(timeout=3000)
                except Exception:
                    pass
                marker = failure_marker(body)
                if marker:
                    raise RuntimeError("browser_authorization_rejected:" + marker)
                if authorized(page.url, body):
                    # Keep the authorized browser session alive long enough for
                    # the terminal's concurrent RFC 8628 token poll to observe it.
                    await page.wait_for_timeout(5000)
                    screenshot = ""
                    if capture_success:
                        screenshot = await save_screenshot(
                            page, diagnostic_dir, "authorized"
                        )
                    return {
                        "ok": True,
                        "stage": "authorized",
                        "url": safe_url(page.url),
                        "actions": actions[-6:],
                        "screenshot": screenshot,
                    }

                action = await handle_login(page, email, password)
                if not action:
                    action = await click_account_choice(page, email)
                if not action:
                    action = await click_positive_action(page)
                    if action:
                        action = "approve:" + action
                if action:
                    actions.append(action)
                    await page.wait_for_timeout(1200)
                    continue

                # Cloudflare/Next navigation can sit without actionable controls
                # while JS finishes. Keep waiting, but report a bounded diagnosis.
                await page.wait_for_timeout(700)

            screenshot = await save_screenshot(page, diagnostic_dir, "failure")
            title = ""
            try:
                title = (await page.title())[:100]
            except Exception:
                pass
            return {
                "ok": False,
                "stage": "timeout",
                "url": safe_url(page.url),
                "title": title,
                "actions": actions[-6:],
                "screenshot": screenshot,
            }
        except Exception as exc:
            screenshot = ""
            current_url = ""
            if page is not None:
                current_url = safe_url(page.url)
                screenshot = await save_screenshot(page, diagnostic_dir, "failure")
            return {
                "ok": False,
                "stage": "browser_error",
                "url": current_url,
                "error": re.sub(r"\s+", " ", str(exc))[:180],
                "screenshot": screenshot,
            }
        finally:
            await browser.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stdin-json", action="store_true", required=True)
    args = parser.parse_args()
    _ = args
    try:
        raw = sys.stdin.buffer.read(1 << 20)
        config = json.loads(raw.decode("utf-8"))
        result = asyncio.run(approve(config))
    except Exception as exc:
        result = {
            "ok": False,
            "stage": "bootstrap_error",
            "error": re.sub(r"\s+", " ", str(exc))[:180],
        }
    sys.stdout.write(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
