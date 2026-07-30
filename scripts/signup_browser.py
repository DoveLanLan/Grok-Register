#!/usr/bin/env python3
"""Register an x.ai account through the real accounts.x.ai Web UI.

This path lets Castle + Turnstile run inside CloakBrowser so signup is not
flagged as machine registration (empty castleRequestToken over raw HTTP).

Configuration is one JSON document on stdin. Credentials never appear in argv.
Stdout is exactly one compact JSON result and never echoes the password.
"""
from __future__ import annotations

import argparse
import asyncio
import glob
import json
import os
import random
import re
import sys
import time
from pathlib import Path
from urllib.parse import unquote, urlsplit, urlunsplit


POSITIVE_WORDS = (
    "sign up",
    "continue",
    "create account",
    "create",
    "confirm email",
    "confirm",
    "next",
    "submit",
    "done",
    "finish",
    "注册",
    "继续",
    "创建",
    "确认",
    "下一步",
)
NEGATIVE_WORDS = ("deny", "cancel", "reject", "go back", "back", "禁止", "拒绝", "取消", "返回")


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


def looks_like_jwt(value: str) -> bool:
    value = (value or "").strip()
    if not value.startswith("eyJ") or value.count(".") != 2:
        return False
    # Hop-config JWTs are short-ish and carry success_url; real session JWTs are longer.
    return len(value) > 80


async def first_visible(page, selectors: tuple[str, ...]):
    for selector in selectors:
        locator = page.locator(selector)
        count = min(await locator.count(), 8)
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
            if value and str(value).strip():
                return re.sub(r"\s+", " ", str(value).strip())
        except Exception:
            continue
    return ""


async def click_positive_action(page, extra_words: tuple[str, ...] = ()) -> str:
    words = tuple(extra_words) + POSITIVE_WORDS
    controls = page.locator(
        'button, input[type="submit"], input[type="button"], [role="button"]'
    )
    count = min(await controls.count(), 50)
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
        for priority, word in enumerate(words):
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
        await page.mouse.move(max(0, x - 18), max(0, y - 4))
        await page.mouse.move(x, y, steps=7)
        await page.mouse.click(x, y, delay=70)
    return label


async def accept_cookies(page) -> str:
    for name in (
        "Accept All Cookies",
        "Allow All",
        "Accept All",
        "Accept",
        "Agree",
        "允许全部",
        "接受全部",
    ):
        button = page.get_by_role("button", name=re.compile(rf"^{re.escape(name)}$", re.I))
        if await button.count() == 0:
            button = page.get_by_role("button", name=re.compile(name, re.I))
        if await button.count() == 0:
            continue
        try:
            await button.first.click(timeout=2500)
            await page.wait_for_timeout(700)
            return name
        except Exception:
            continue
    return ""


async def human_type(locator, value: str, delay: int = 35) -> None:
    """Focus and type. Falls back to fill() when click/type is flaky."""
    focused = False
    for timeout_ms in (3500, 6000):
        try:
            await locator.scroll_into_view_if_needed(timeout=timeout_ms)
        except Exception:
            pass
        try:
            await locator.click(timeout=timeout_ms)
            focused = True
            break
        except Exception:
            continue
    if not focused:
        # Last resort: focus via JS / force fill without a successful click.
        try:
            await locator.evaluate("el => { el.focus(); el.click(); }")
            focused = True
        except Exception:
            pass
    try:
        await locator.fill("")
    except Exception:
        try:
            await locator.evaluate("el => { el.value = ''; el.dispatchEvent(new Event('input', {bubbles:true})); }")
        except Exception:
            pass
    try:
        await locator.type(value, delay=delay)
    except Exception:
        # type() can fail if the field remounts; hard-fill keeps the flow alive.
        await locator.fill(value, timeout=5000)


async def read_input_value(locator) -> str:
    try:
        return str(await locator.input_value(timeout=2000) or "")
    except Exception:
        try:
            return str(await locator.evaluate("el => el.value || ''") or "")
        except Exception:
            return ""


async def fill_and_confirm(
    page,
    locator,
    value: str,
    delay: int = 32,
    label: str = "field",
    *,
    case_insensitive: bool = False,
    allow_unread: bool = False,
    normalize=None,
) -> str:
    """Type a value and verify the DOM actually kept the full string.

    React-controlled inputs can drop characters when typed too fast or when the
    page re-renders mid-type. We re-type / hard-fill until the visible value
    matches, then Tab out so onChange/blur commits the state before submit.

    allow_unread: for password fields some engines hide the value; if every
    read-back is empty after a successful fill, accept rather than hang.
    normalize: optional callable applied to both expected/current before compare
    (e.g. strip dashes from OTP codes).
    """
    expected = (value or "").strip()
    if not expected:
        raise RuntimeError(f"{label}_empty")

    def _match(current: str) -> bool:
        left = current
        right = expected
        if normalize is not None:
            try:
                left = normalize(left)
                right = normalize(right)
            except Exception:
                pass
        if case_insensitive or "@" in expected:
            return left.lower() == right.lower()
        return left == right

    last_current = ""
    for attempt in range(4):
        if attempt == 0:
            await human_type(locator, expected, delay=delay)
        elif attempt == 1:
            await human_type(locator, expected, delay=max(delay, 45))
        else:
            try:
                await locator.click(timeout=3000)
                await locator.fill(expected, timeout=5000)
            except Exception:
                await human_type(locator, expected, delay=delay)

        try:
            await locator.press("Tab")
        except Exception:
            try:
                await page.keyboard.press("Tab")
            except Exception:
                pass
        await page.wait_for_timeout(250 + attempt * 120)

        last_current = (await read_input_value(locator)).strip()
        if _match(last_current):
            return f"fill:{label}"
        # Password / sensitive inputs may always report empty; don't loop forever.
        if allow_unread and last_current == "":
            return f"fill:{label}:unread"

    if allow_unread and last_current == "":
        return f"fill:{label}:unread"
    raise RuntimeError(
        f"{label}_incomplete: want={expected[:48]!r} got={last_current[:48]!r}"
    )


async def wait_for_code(code_file: str, timeout_sec: float) -> str:
    path = Path(code_file)
    deadline = time.monotonic() + max(15.0, timeout_sec)
    while time.monotonic() < deadline:
        try:
            if path.is_file():
                text = path.read_text(encoding="utf-8", errors="ignore").strip().upper()
                text = re.sub(r"\s+", "", text)
                if re.fullmatch(r"[A-Z0-9]{3}-[A-Z0-9]{3}", text) or re.fullmatch(
                    r"[A-Z0-9]{6}", text
                ):
                    return text
        except Exception:
            pass
        await asyncio.sleep(0.8)
    return ""


async def read_sso_cookie(context) -> str:
    try:
        cookies = await context.cookies()
    except Exception:
        return ""
    best = ""
    for cookie in cookies:
        if cookie.get("name") != "sso":
            continue
        value = str(cookie.get("value") or "")
        if looks_like_jwt(value) and len(value) > len(best):
            best = value
    return best


# Public Turnstile sitekey used by accounts.x.ai sign-up (also documented in README).
# Used only as a last-resort inject when the page embeds the challenge but no
# interactive/managed widget is visible yet.
DEFAULT_TURNSTILE_SITEKEY = "0x4AAAAAAAhr9JGVDZbrZOo0"


class _CamoufoxRuntime:
    """Small adapter that exposes Camoufox through Playwright's launch shape.

    Keeping the browser boundary compatible lets both engines execute the exact
    same signup/OAuth flow; only the engine and fingerprint construction differ.
    """

    def __init__(self, config: dict, headless: bool, proxy: str):
        self._config = config
        self._headless = headless
        self._proxy = proxy
        self._manager = None
        self.chromium = self

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self._manager is not None:
            manager, self._manager = self._manager, None
            await manager.__aexit__(exc_type, exc, tb)

    async def launch(self, **_ignored):
        try:
            from camoufox.async_api import AsyncCamoufox
        except Exception as exc:
            raise RuntimeError(
                "Camoufox is not installed; pip install 'camoufox[geoip]>=0.5.4' "
                "and run: camoufox fetch"
            ) from exc

        egress = self._config.get("egress") or {}
        locale = str(egress.get("locale") or "en-US").strip()
        timezone = str(egress.get("timezone") or "").strip()
        latitude = float(egress.get("latitude") or 0)
        longitude = float(egress.get("longitude") or 0)
        exit_ip = str(egress.get("ip") or "").strip()
        camou_config = {}
        # Prefer Camoufox's GeoIP pipeline whenever the preflight resolved an
        # exit IP. It configures the full fingerprint coherently and avoids the
        # manual-geolocation leak warning. Manual values are only a fallback.
        if not exit_ip:
            if timezone:
                camou_config["timezone"] = timezone
            if latitude or longitude:
                camou_config["geolocation:latitude"] = latitude
                camou_config["geolocation:longitude"] = longitude

        options = {
            "headless": self._headless,
            "humanize": True,
            "block_webrtc": True,
            "locale": locale,
            "config": camou_config,
            "i_know_what_im_doing": True,
        }
        if self._proxy:
            options["proxy"] = playwright_proxy(self._proxy)
        if exit_ip:
            options["geoip"] = exit_ip

        self._manager = AsyncCamoufox(**options)
        return await self._manager.__aenter__()


async def maybe_click_turnstile(page) -> str:
    # Best-effort: real widget is in an iframe; CloakBrowser often auto-passes.
    frames = list(page.frames)
    for frame in frames:
        url = (frame.url or "").lower()
        if "challenges.cloudflare.com" not in url and "turnstile" not in url:
            continue
        for selector in (
            "input[type=checkbox]",
            "#challenge-stage",
            ".ctp-checkbox-label",
            "label",
            "body",
        ):
            try:
                loc = frame.locator(selector)
                if await loc.count() == 0:
                    continue
                box = await loc.first.bounding_box()
                if not box or box.get("width", 0) < 4 or box.get("height", 0) < 4:
                    continue
                x = box["x"] + min(max(box["width"] * 0.15, 12), max(box["width"] - 4, 12))
                y = box["y"] + box["height"] / 2
                await page.mouse.move(max(0, x - 10), max(0, y - 4))
                await page.mouse.move(x, y, steps=6)
                await page.mouse.click(x, y, delay=60)
                return "turnstile:clicked"
            except Exception:
                continue

    # Also try the host-page widget container center (managed mode).
    try:
        box = await page.evaluate(
            """() => {
                const e = document.querySelector(
                    '.cf-turnstile, [data-sitekey], iframe[src*="challenges.cloudflare.com"]'
                );
                if (!e) return null;
                const r = e.getBoundingClientRect();
                if (r.width < 4 || r.height < 4) return null;
                return {x: r.left + Math.min(Math.max(r.width * 0.2, 16), r.width - 4),
                        y: r.top + r.height / 2};
            }"""
        )
        if box:
            x, y = float(box["x"]), float(box["y"])
            await page.mouse.move(max(0, x - 12), max(0, y - 5))
            await page.mouse.move(x, y, steps=7)
            await page.mouse.click(x, y, delay=70)
            return "turnstile:clicked_host"
    except Exception:
        pass
    return ""


async def turnstile_token_present(page) -> bool:
    try:
        return bool(
            await page.evaluate(
                '''() => {
                const selectors = [
                    'input[name="cf-turnstile-response"]',
                    'input[name="turnstileToken"]',
                    'input[name="cf_turnstile_response"]',
                    'textarea[name="cf-turnstile-response"]',
                    '[data-turnstile-response]',
                    'input[id*="cf-chl-widget"]',
                    'input[name*="turnstile" i]',
                    'textarea[name*="turnstile" i]',
                ];
                for (const sel of selectors) {
                    const nodes = document.querySelectorAll(sel);
                    for (const input of nodes) {
                        const val = (input.value
                            || input.getAttribute("data-turnstile-response")
                            || input.textContent
                            || "").trim();
                        if (val.length >= 80) return true;
                    }
                }
                for (const w of document.querySelectorAll("[data-sitekey], .cf-turnstile")) {
                    const resp = w.querySelector('input[type="hidden"], textarea');
                    if (resp && (resp.value || "").trim().length >= 80) return true;
                    const attr = w.getAttribute("data-turnstile-response") || "";
                    if (attr.length >= 80) return true;
                }
                if (window.turnstile && typeof window.turnstile.getResponse === "function") {
                    try {
                        const response = String(window.turnstile.getResponse() || "").trim();
                        if (response.length >= 80) return true;
                    } catch (_) {}
                }
                return false;
            }'''
            )
        )
    except Exception:
        raise


async def turnstile_visual_success(page) -> bool:
    """Detect managed Turnstile Success! UI even when host token is opaque."""
    try:
        return bool(
            await page.evaluate(
                '''() => {
                const body = (document.body && document.body.innerText || "");
                if (/\bSuccess!\b/i.test(body) && /cloudflare/i.test(body)) return true;
                if (/\bSuccess!\b/i.test(body) && document.querySelector(
                    'iframe[src*="challenges.cloudflare.com"], .cf-turnstile, [data-sitekey]'
                )) return true;
                const nodes = document.querySelectorAll(
                    '[aria-label*="success" i], [data-state="success"], .success'
                );
                for (const n of nodes) {
                    const t = (n.textContent || n.getAttribute("aria-label") || "").toLowerCase();
                    if (t.includes("success")) return true;
                }
                return false;
            }'''
            )
        )
    except Exception:
        return False


async def detect_turnstile_sitekey(page) -> str:
    try:
        key = await page.evaluate(
            '''() => {
                const nodes = document.querySelectorAll(
                    "[data-sitekey], .cf-turnstile, iframe[src*='challenges.cloudflare.com']"
                );
                for (const n of nodes) {
                    const k = n.getAttribute("data-sitekey");
                    if (k && k.startsWith("0x")) return k;
                    const src = n.getAttribute("src") || "";
                    const m = src.match(/[?&]k=(0x[0-9A-Za-z_-]+)/);
                    if (m) return m[1];
                }
                // Next.js / React may stash the key in script text.
                for (const s of document.scripts) {
                    const t = s.textContent || "";
                    const m = t.match(/0x4AAAAAAA[0-9A-Za-z_-]+/);
                    if (m) return m[0];
                }
                return "";
            }'''
        )
        return str(key or "").strip()
    except Exception:
        return ""


async def inject_turnstile_widget(page, site_key: str = "") -> str:
    """Force-render a Turnstile widget when the page challenge never surfaces.

    Mirrors scripts/turnstile_mint.py so CloakBrowser can mint a real token on
    the credentials step even when the managed widget stays invisible / stuck.
    """
    key = (site_key or "").strip() or await detect_turnstile_sitekey(page)
    if not key:
        key = DEFAULT_TURNSTILE_SITEKEY
    # Escape for single-quoted JS string literals.
    key_js = key.replace("\\", "\\\\").replace("'", "\\'")
    inject = (
        "(function(sitekey){"
        "if(window.__grokTurnstileInjected){return 'already';}"
        "window.__grokTurnstileInjected=true;"
        "var d=document.createElement('div');"
        "d.className='cf-turnstile';"
        "d.setAttribute('data-sitekey',sitekey);"
        "d.setAttribute('data-theme','light');"
        "d.style.cssText='position:fixed;top:12px;left:12px;z-index:2147483646;"
        "background:#fff;padding:10px;border:1px solid #ddd;border-radius:6px;"
        "width:320px;min-height:70px;box-shadow:0 2px 12px rgba(0,0,0,.12)';"
        "document.body.appendChild(d);"
        "function __bind(t){"
        "var names=['cf-turnstile-response','turnstileToken','cf_turnstile_response'];"
        "for(var n=0;n<names.length;n++){"
        "var i=document.querySelector('input[name=\"'+names[n]+'\"],textarea[name=\"'+names[n]+'\"]');"
        "if(!i){i=document.createElement('input');i.type='hidden';i.name=names[n];"
        "document.body.appendChild(i);}"
        "i.value=t;"
        "try{i.dispatchEvent(new Event('input',{bubbles:true}));"
        "i.dispatchEvent(new Event('change',{bubbles:true}));}catch(e){}"
        "}"
        "var nodes=document.querySelectorAll('[data-sitekey],.cf-turnstile');"
        "for(var j=0;j<nodes.length;j++){"
        "try{nodes[j].setAttribute('data-turnstile-response',t);}catch(e){}"
        "}"
        "window.__grokTurnstileToken=t;"
        "}"
        "function __r(){"
        "try{"
        "if(window.turnstile&&window.turnstile.render){"
        "window.turnstile.render(d,{sitekey:sitekey,callback:__bind,"
        "'error-callback':function(){},'expired-callback':function(){}});"
        "return 'rendered';"
        "}"
        "}catch(e){return 'render_err';}"
        "return 'no_api';"
        "}"
        "if(window.turnstile){return __r();}"
        "var s=document.createElement('script');"
        "s.src='https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';"
        "s.async=true;"
        "s.onload=function(){setTimeout(__r,600);};"
        "document.head.appendChild(s);"
        "return 'script_loading';"
        "})('" + key_js + "')"
    )
    try:
        status = await page.evaluate(inject)
        return f"turnstile:inject:{status or 'ok'}"
    except Exception as exc:
        return "turnstile:inject_error:" + re.sub(r"\s+", " ", str(exc))[:60]


async def wait_for_turnstile(
    page,
    actions: list[str],
    timeout_sec: float = 45,
    *,
    allow_inject: bool = False,
    inject_after_sec: float = 35.0,
) -> bool:
    """Wait for Turnstile to complete before submitting the form.

    Strategy (in order, looped until timeout):
    1. Detect an already-minted cf-turnstile / turnstileToken value.
    2. Observe iframe success / checkmark state, but require the host token.
    3. Click interactive checkbox if present.
    4. Optionally inject an explicit widget only after a long native grace
       period. Injection is disabled by default because a standalone token can
       miss application-specific action/state binding.
    """
    clicked_once = False
    injected = False
    deadline = time.monotonic() + max(8.0, timeout_sec)
    started = time.monotonic()
    last_retry_click = 0.0
    while time.monotonic() < deadline:
        try:
            if await turnstile_token_present(page):
                if injected and not clicked_once:
                    actions.append("turnstile:injected_passed")
                elif not clicked_once:
                    actions.append("turnstile:auto_passed")
                else:
                    actions.append("turnstile:passed")
                return True
            if await turnstile_visual_success(page):
                if "turnstile:visual_success_pending_token" not in actions[-4:]:
                    actions.append("turnstile:visual_success_pending_token")
        except Exception as exc:
            actions.append("turnstile:token_check_error:" + type(exc).__name__)
            return False

        # Check iframe success state.
        for frame in page.frames:
            frame_url = (frame.url or "").lower()
            if "challenges.cloudflare.com" not in frame_url and "turnstile" not in frame_url:
                continue
            try:
                success = await frame.evaluate(
                    '''() => {
                    const check = document.querySelector(
                        '[data-action="succeeded"], .success, #success, [aria-label*="success" i]'
                    );
                    if (check) return true;
                    const container = document.querySelector('#challenge-stage, .challenge-container');
                    if (container && container.offsetHeight < 5) return true;
                    // Solved widgets often collapse / show a green check SVG.
                    if (document.querySelector('svg, #success-i, .cb-i')) {
                        const bodyText = (document.body && document.body.innerText || '').toLowerCase();
                        if (bodyText.includes('success') || bodyText.includes('verified')) return true;
                    }
                    return false;
                }'''
                )
                if success:
                    # Give the host page a beat to copy the token into the form.
                    await page.wait_for_timeout(600)
                    try:
                        if await turnstile_token_present(page):
                            actions.append("turnstile:iframe_success")
                            return True
                    except Exception as exc:
                        actions.append(
                            "turnstile:iframe_token_error:" + type(exc).__name__
                        )
                        continue
                    if "turnstile:iframe_success_pending" not in actions[-4:]:
                        actions.append("turnstile:iframe_success_pending")
            except Exception:
                pass

        # Try clicking the checkbox if not yet clicked.
        if not clicked_once:
            ts = await maybe_click_turnstile(page)
            if ts:
                actions.append(ts)
                clicked_once = True
                await page.wait_for_timeout(random.randint(1800, 3200))
                continue

        # Explicit injection is opt-in and delayed so the page's managed widget
        # always gets the primary opportunity to mint its bound response.
        elapsed = time.monotonic() - started
        if allow_inject and not injected and elapsed >= max(10.0, inject_after_sec):
            status = await inject_turnstile_widget(page)
            actions.append(status)
            injected = True
            await page.wait_for_timeout(random.randint(1200, 2200))
            # Immediately try a click on the freshly rendered widget.
            ts = await maybe_click_turnstile(page)
            if ts:
                actions.append(ts)
                clicked_once = True
            continue

        # Periodically re-click after inject (widget may need a second nudge).
        # Use wall-clock throttle instead of int(elapsed)%9 which could spam.
        if injected and (elapsed - last_retry_click) >= 8.0:
            ts = await maybe_click_turnstile(page)
            if ts:
                actions.append(ts + ":retry")
                last_retry_click = elapsed

        await page.wait_for_timeout(random.randint(700, 1400))

    # Timeout; final token / visual check.
    try:
        if await turnstile_token_present(page):
            actions.append("turnstile:passed_late")
            return True
        if await turnstile_visual_success(page):
            actions.append("turnstile:visual_success_late_without_token")
    except Exception as exc:
        actions.append("turnstile:late_check_error:" + type(exc).__name__)
        return False
    actions.append("turnstile:timeout")
    return False


async def credentials_form_ready(page) -> bool:
    """True when the Complete-your-sign-up name/password step is on screen."""
    try:
        return bool(
            await page.evaluate(
                '''() => {
                const body = (document.body && document.body.innerText || '').toLowerCase();
                const hasCredCopy = (
                    body.includes('complete your sign up')
                    || body.includes('create your account')
                    || body.includes('finish signing up')
                    || body.includes('create a password')
                    || body.includes('choose a password')
                    || body.includes('完成注册')
                    || body.includes('创建账户')
                    || body.includes('创建账号')
                );
                const textInputs = Array.from(document.querySelectorAll(
                    'input:not([type="hidden"]):not([type="checkbox"]):not([type="radio"]):not([type="submit"]):not([type="button"])'
                )).filter(el => {
                    const t = (el.type || 'text').toLowerCase();
                    if (t === 'password') return false;
                    if (t === 'email') return false;
                    const r = el.getBoundingClientRect();
                    return r.width > 10 && r.height > 8 && el.offsetParent !== null;
                });
                const pw = Array.from(document.querySelectorAll('input[type="password"]'))
                    .filter(el => {
                        const r = el.getBoundingClientRect();
                        return r.width > 10 && r.height > 8 && el.offsetParent !== null;
                    });
                // Ready when password is visible and at least one name-like field,
                // or page copy says this is the credentials step with a password.
                if (pw.length >= 1 && textInputs.length >= 1) return true;
                if (hasCredCopy && pw.length >= 1) return true;
                return false;
            }'''
            )
        )
    except Exception:
        return False


async def find_by_label(page, patterns: tuple[str, ...]):
    """Resolve an input via accessible name / associated label text."""
    for pattern in patterns:
        try:
            loc = page.get_by_label(re.compile(pattern, re.I))
            count = min(await loc.count(), 4)
            for index in range(count):
                item = loc.nth(index)
                try:
                    if await item.is_visible():
                        return item
                except Exception:
                    continue
        except Exception:
            continue
        try:
            label = page.locator("label").filter(has_text=re.compile(pattern, re.I))
            count = min(await label.count(), 4)
            for index in range(count):
                lab = label.nth(index)
                try:
                    if not await lab.is_visible():
                        continue
                except Exception:
                    continue
                try:
                    for_id = await lab.get_attribute("for")
                except Exception:
                    for_id = None
                if for_id:
                    item = page.locator(f"#{for_id}").first
                    try:
                        if await item.count() and await item.is_visible():
                            return item
                    except Exception:
                        pass
                try:
                    nested = lab.locator("input").first
                    if await nested.count() and await nested.is_visible():
                        return nested
                except Exception:
                    pass
                try:
                    sib = lab.locator(
                        "xpath=following::input[not(@type)='hidden'][1]"
                    )
                    # simpler following input
                    sib = lab.locator("xpath=following::input[1]")
                    if await sib.count() and await sib.first.is_visible():
                        return sib.first
                except Exception:
                    pass
        except Exception:
            continue
    return None


async def find_credentials_inputs(page):
    """Locate given/family/password fields on Complete-your-sign-up.

    Real x.ai pages label fields as "First name" / "Last name" / "Password"
    with generic inputs (often no name=/autocomplete=). Prefer labels, then
    attribute selectors, then visible text-input order.
    """
    given_input = await find_by_label(
        page, (r"first\s*name", r"given\s*name", r"^名$")
    )
    family_input = await find_by_label(
        page, (r"last\s*name", r"family\s*name", r"^姓$")
    )
    if given_input is None:
        given_input = await first_visible(
            page,
            (
                'input[name="givenName"]',
                'input[name="given_name"]',
                'input[autocomplete="given-name"]',
                'input[name="firstName"]',
                'input[name="first_name"]',
                'input[id*="given" i]',
                'input[id*="first" i]',
                'input[placeholder*="First" i]',
                'input[placeholder*="Given" i]',
                'input[aria-label*="First" i]',
                'input[aria-label*="Given" i]',
            ),
        )
    if family_input is None:
        family_input = await first_visible(
            page,
            (
                'input[name="familyName"]',
                'input[name="family_name"]',
                'input[autocomplete="family-name"]',
                'input[name="lastName"]',
                'input[name="last_name"]',
                'input[id*="family" i]',
                'input[id*="last" i]',
                'input[placeholder*="Last" i]',
                'input[placeholder*="Family" i]',
                'input[aria-label*="Last" i]',
                'input[aria-label*="Family" i]',
            ),
        )

    if given_input is None or family_input is None:
        text_inputs = page.locator(
            'input:not([type="hidden"]):not([type="password"]):not([type="email"]):not([type="checkbox"]):not([type="radio"]):not([type="submit"]):not([type="button"])'
        )
        try:
            n = await text_inputs.count()
        except Exception:
            n = 0
        visible_text = []
        for index in range(min(n, 8)):
            item = text_inputs.nth(index)
            try:
                if await item.is_visible():
                    box = await item.bounding_box()
                    if box and box.get("width", 0) >= 8 and box.get("height", 0) >= 8:
                        visible_text.append(item)
            except Exception:
                continue
        if given_input is None and visible_text:
            given_input = visible_text[0]
        if family_input is None and len(visible_text) > 1:
            family_input = visible_text[1]

    password_inputs = []
    pw_by_label = await find_by_label(page, (r"^password$", r"password", r"密码"))
    if pw_by_label is not None:
        password_inputs.append(pw_by_label)
    loc = page.locator('input[type="password"]')
    try:
        count = await loc.count()
    except Exception:
        count = 0
    for index in range(min(count, 3)):
        item = loc.nth(index)
        try:
            if await item.is_visible():
                password_inputs.append(item)
        except Exception:
            continue
    password_inputs = password_inputs[:2]
    return given_input, family_input, password_inputs


async def js_force_fill(page, given: str, family: str, password: str) -> list[str]:
    """Last-resort React-friendly value set on visible credentials inputs."""
    try:
        result = await page.evaluate(
            """({given, family, password}) => {
                function visible(el) {
                    if (!el) return false;
                    const r = el.getBoundingClientRect();
                    const s = window.getComputedStyle(el);
                    return r.width > 8 && r.height > 8
                        && s.visibility !== 'hidden'
                        && s.display !== 'none'
                        && Number(s.opacity || '1') > 0.05;
                }
                function setVal(el, val) {
                    if (!el) return false;
                    try { el.focus(); } catch (e) {}
                    const proto = window.HTMLInputElement
                        && window.HTMLInputElement.prototype;
                    const desc = proto && Object.getOwnPropertyDescriptor(proto, 'value');
                    if (desc && desc.set) desc.set.call(el, val);
                    else el.value = val;
                    el.dispatchEvent(new Event('input', {bubbles: true}));
                    el.dispatchEvent(new Event('change', {bubbles: true}));
                    el.dispatchEvent(new KeyboardEvent('keyup', {bubbles: true}));
                    return true;
                }
                const all = Array.from(document.querySelectorAll('input')).filter(visible);
                const texts = all.filter(el => {
                    const t = (el.type || 'text').toLowerCase();
                    return t === 'text' || t === '' || t === 'search' || t === 'tel';
                });
                const pws = all.filter(el => (el.type || '').toLowerCase() === 'password');
                const out = [];
                if (texts[0] && given && setVal(texts[0], given)) out.push('givenName');
                if (texts[1] && family && setVal(texts[1], family)) out.push('familyName');
                if (pws[0] && password && setVal(pws[0], password)) out.push('password');
                if (pws[1] && password && setVal(pws[1], password)) out.push('password2');
                return out;
            }""",
            {"given": given, "family": family, "password": password},
        )
    except Exception as exc:
        return ["fill:js_error:" + re.sub(r"\s+", " ", str(exc))[:40]]
    return [f"fill:{name}:js" for name in (result or [])]


async def fill_credentials(page, given: str, family: str, password: str) -> list[str]:
    """Fill the Complete-your-sign-up name + password form.

    Returns fill actions. Empty list => form not ready / fill failed; caller retries.
    """
    actions: list[str] = []
    if not await credentials_form_ready(page):
        return actions

    # x.ai uses label text ("First name") with generic inputs; Playwright attribute
    # selectors often miss them. Force-fill via DOM first, then fall back.
    js_first = await js_force_fill(page, given, family, password)
    if js_first:
        actions.extend(js_first)
        labels = {a.split(":")[1] for a in js_first if a.startswith("fill:")}
        if ("password" in labels or "password2" in labels) and (
            "givenName" in labels or "familyName" in labels
        ):
            try:
                ok = await page.evaluate(
                    "() => Array.from(document.querySelectorAll('input[type=password]'))"
                    ".some(el => (el.value||'').length >= 6)"
                )
            except Exception:
                ok = True
            if ok:
                actions.append("fill:credentials:js_ok")
                return actions

    given_input, family_input, password_inputs = await find_credentials_inputs(page)

    async def _safe_fill(locator, value: str, label: str, allow_unread: bool = False) -> None:
        nonlocal actions
        if locator is None or not value:
            return
        try:
            actions.append(
                await fill_and_confirm(
                    page,
                    locator,
                    value,
                    delay=random.randint(24, 48),
                    label=label,
                    allow_unread=allow_unread,
                )
            )
            return
        except Exception as exc:
            try:
                await locator.fill(value, timeout=4000)
                actions.append(f"fill:{label}:hard")
                return
            except Exception:
                try:
                    await locator.evaluate(
                        """(el, val) => {
                            const proto = window.HTMLInputElement
                                && window.HTMLInputElement.prototype;
                            const desc = proto && Object.getOwnPropertyDescriptor(proto, 'value');
                            if (desc && desc.set) desc.set.call(el, val);
                            else el.value = val;
                            el.dispatchEvent(new Event('input', {bubbles:true}));
                            el.dispatchEvent(new Event('change', {bubbles:true}));
                            return true;
                        }""",
                        value,
                    )
                    actions.append(f"fill:{label}:js_one")
                    return
                except Exception as exc2:
                    actions.append(
                        "fill:%s:error:%s"
                        % (label, re.sub(r"\s+", " ", str(exc2) or str(exc))[:40])
                    )

    if given_input is None and family_input is None and not password_inputs:
        js_actions = await js_force_fill(page, given, family, password)
        if any("password" in a for a in js_actions):
            actions.extend(js_actions)
            return actions
        return actions

    if given_input is not None and given:
        await _safe_fill(given_input, given, "givenName")
        await asyncio.sleep(random.uniform(0.2, 0.5))
    if family_input is not None and family:
        await _safe_fill(family_input, family, "familyName")
        await asyncio.sleep(random.uniform(0.2, 0.5))
    for index, item in enumerate(password_inputs[:2]):
        label = "password" if index == 0 else f"password{index + 1}"
        await _safe_fill(item, password, label, allow_unread=True)
        await asyncio.sleep(random.uniform(0.15, 0.35))

    filled_labels = set()
    for a in actions:
        if a.startswith("fill:"):
            parts = a.split(":")
            if len(parts) >= 2:
                filled_labels.add(parts[1])

    need_js = (
        "password" not in filled_labels and "password1" not in filled_labels
    ) or (
        (given_input is not None or family_input is not None)
        and "givenName" not in filled_labels
        and "familyName" not in filled_labels
    )
    if need_js:
        js_actions = await js_force_fill(page, given, family, password)
        actions.extend(js_actions)
        for a in js_actions:
            if a.startswith("fill:"):
                parts = a.split(":")
                if len(parts) >= 2:
                    filled_labels.add(parts[1])

    if "password" not in filled_labels and "password1" not in filled_labels:
        return []
    if (given_input is not None or family_input is not None) and not (
        "givenName" in filled_labels or "familyName" in filled_labels
    ):
        return []
    return actions



def oauth_authorized(url: str, body: str) -> bool:
    path = (urlsplit(url).path or "").lower()
    text = (body or "").lower()
    return (
        path.endswith("/oauth2/device/done")
        or path.endswith("/device/done")
        or "device authorized" in text
        or "device is authorized" in text
        or "you have authorized" in text
        or "设备已授权" in text
        or "授权成功" in text
    )


def success_markers(url: str, body: str) -> bool:
    path = (urlsplit(url).path or "").lower()
    text = (body or "").lower()
    if any(
        token in path
        for token in (
            "/home",
            "/account",
            "/welcome",
            "/onboarding",
            "/chat",
            "/sign-in",  # sometimes lands briefly; cookie is authoritative
        )
    ):
        # path alone is weak; combined with body below
        pass
    return any(
        marker in text
        for marker in (
            "you're all set",
            "you are all set",
            "welcome to",
            "account created",
            "finish setting up",
            "get started",
            "注册成功",
            "创建成功",
        )
    )


async def export_cookies(context) -> list[dict]:
    out = []
    try:
        cookies = await context.cookies()
    except Exception:
        return out
    for cookie in cookies:
        name = str(cookie.get("name") or "")
        value = str(cookie.get("value") or "")
        if not name or not value:
            continue
        item = {
            "name": name,
            "value": value,
            "domain": str(cookie.get("domain") or ".x.ai"),
            "path": str(cookie.get("path") or "/"),
        }
        if cookie.get("secure") is not None:
            item["secure"] = bool(cookie.get("secure"))
        if cookie.get("httpOnly") is not None:
            item["httpOnly"] = bool(cookie.get("httpOnly"))
        if cookie.get("sameSite"):
            item["sameSite"] = str(cookie.get("sameSite"))
        out.append(item)
    return out


def is_sign_in_url(url: str) -> bool:
    try:
        path = (urlsplit(url).path or "").lower()
    except ValueError:
        path = (url or "").lower()
    return "/sign-in" in path or path.endswith("/login") or "/sign_in" in path


async def handle_login(page, email: str, password: str) -> str:
    """Fill email/password if the OAuth device page bounced to sign-in."""
    email_input = await first_visible(
        page,
        (
            'input[type="email"]',
            'input[name="email"]',
            'input[autocomplete="username"]',
            'input[name="username"]',
            'input[autocomplete="email"]',
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
            current = (await read_input_value(email_input)).strip()
        except Exception:
            current = ""
        if current.lower() != email.strip().lower():
            await email_input.fill(email, timeout=5000)
            try:
                await email_input.press("Tab")
            except Exception:
                pass
            await page.wait_for_timeout(300)
            # Some sign-in flows are multi-step: email first, then password.
            if password_input is None:
                action = await click_positive_action(
                    page, ("continue", "next", "sign in", "log in", "下一步", "继续", "登录")
                )
                if action:
                    await page.wait_for_timeout(900)
                    password_input = await first_visible(
                        page,
                        (
                            'input[type="password"]',
                            'input[name="password"]',
                            'input[autocomplete="current-password"]',
                        ),
                    )

    if password_input is not None:
        await password_input.fill(password, timeout=5000)

    action = await click_positive_action(
        page,
        ("sign in", "log in", "continue", "next", "登录", "继续", "下一步"),
    )
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


async def approve_device_in_session(
    page,
    verification_url: str,
    actions: list[str],
    timeout_sec: float = 90.0,
    email: str = "",
    password: str = "",
) -> bool:
    """Approve Device Flow in the same browser session used for signup.

    Brand-new SSO cookies sometimes bounce /oauth2/device → /sign-in. When that
    happens we re-authenticate with the just-created credentials (or rely on the
    existing session cookie after a short wait) and continue the consent flow.
    """
    if not verification_url:
        return False

    async def open_verification(reason: str) -> None:
        await page.goto(
            verification_url,
            timeout=min(60000, int(timeout_sec * 1000)),
            wait_until="domcontentloaded",
        )
        actions.append(reason)

    await open_verification("oauth:open")
    deadline = time.monotonic() + max(25.0, timeout_sec)
    signin_retries = 0
    last_login_at = 0.0

    while time.monotonic() < deadline:
        await page.wait_for_timeout(700)
        body = ""
        try:
            body = await page.locator("body").inner_text(timeout=2500)
        except Exception:
            pass

        if oauth_authorized(page.url, body):
            actions.append("oauth:authorized")
            # Keep session alive briefly so concurrent token poll can observe it.
            await page.wait_for_timeout(5000)
            return True

        # Dropped to sign-in: either SSO not yet sticky, or session was ignored.
        # Only treat as a bounce when the URL is /sign-in OR a real login form is
        # present. Consent pages often contain a footer "Sign in" link — matching
        # body text alone would incorrectly re-login and stall the flow.
        on_signin_url = is_sign_in_url(page.url)
        login_form = None
        if on_signin_url or "/oauth2/device" not in (page.url or ""):
            login_form = await first_visible(
                page,
                (
                    'input[type="password"]',
                    'input[type="email"]',
                    'input[name="email"]',
                    'input[autocomplete="username"]',
                ),
            )
        if on_signin_url or login_form is not None:
            now = time.monotonic()
            if email and password and (now - last_login_at) > 4.0:
                try:
                    login_action = await handle_login(page, email, password)
                except Exception as exc:
                    login_action = ""
                    actions.append(
                        "oauth:login_error:" + re.sub(r"\s+", " ", str(exc))[:60]
                    )
                if login_action:
                    actions.append("oauth:" + login_action)
                    last_login_at = now
                    await page.wait_for_timeout(1500)
                    # After login, force back to the device URL if still not there.
                    if is_sign_in_url(page.url) or "/oauth2/device" not in (
                        page.url or ""
                    ):
                        signin_retries += 1
                        if signin_retries <= 3:
                            await page.wait_for_timeout(1200 * signin_retries)
                            await open_verification(
                                f"oauth:reopen_after_login:{signin_retries}"
                            )
                    continue

            # Login UI not ready / credentials missing — wait + reopen device URL.
            if on_signin_url:
                signin_retries += 1
                actions.append(f"oauth:signin_bounce:{signin_retries}")
                if signin_retries > 4:
                    actions.append("oauth:signin_stuck")
                    return False
                await page.wait_for_timeout(1500 * signin_retries)
                await open_verification(f"oauth:reopen:{signin_retries}")
                continue

        # Account picker / multi-session chooser.
        account_action = await click_account_choice(page, email)
        if account_action:
            actions.append("oauth:" + account_action)
            await page.wait_for_timeout(1000)
            continue

        action = await click_positive_action(
            page,
            (
                "continue",
                "allow",
                "approve",
                "authorize",
                "confirm",
                "同意",
                "允许",
                "授权",
                "继续",
            ),
        )
        if action:
            actions.append("oauth:" + action)
            await page.wait_for_timeout(1200)
            continue

        await page.wait_for_timeout(600)

    actions.append("oauth:timeout")
    return False


async def write_progress(diagnostic_dir: str, stage: str, actions: list[str], url: str = "") -> None:
    if not diagnostic_dir:
        return
    try:
        directory = Path(diagnostic_dir).expanduser().resolve()
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        path = directory / "progress.txt"
        with path.open("a", encoding="utf-8") as fh:
            fh.write(
                f"{int(time.time())}\t{stage}\t{safe_url(url)}\t"
                + " | ".join(actions[-8:])
                + "\n"
            )
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass
    except Exception:
        return


async def save_screenshot(page, diagnostic_dir: str, label: str) -> str:
    if not diagnostic_dir:
        return ""
    try:
        directory = Path(diagnostic_dir).expanduser().resolve()
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(directory, 0o700)
        path = directory / f"signup-{label}-{int(time.time())}.png"
        await page.screenshot(path=str(path), full_page=True)
        os.chmod(path, 0o600)
        return str(path)
    except Exception:
        return ""


def is_grok_handoff_url(raw: str) -> bool:
    """True when the tab landed on the grok.com app accounts.x.ai hands off to."""
    try:
        host = (urlsplit(raw or "").hostname or "").lower()
    except ValueError:
        return False
    return host == "grok.com" or host.endswith(".grok.com")


async def wait_for_grok_handoff(page, actions: list[str], timeout_sec: float = 60.0) -> None:
    """Block until the post-signup redirect to grok.com has landed.

    x.ai finishes provisioning the account on that hop: accounts.x.ai issues the
    session and grok.com exchanges it for its own cookies. Opening the device
    consent page mid-handoff yields invalid_grant on the token poll, so wait for
    the landing page the way a human would before authorizing.
    """
    deadline = time.monotonic() + max(5.0, timeout_sec)
    while time.monotonic() < deadline:
        if is_grok_handoff_url(page.url):
            # Let grok.com commit its session cookies before navigating away.
            await page.wait_for_timeout(3000)
            actions.append("handoff:grok_loaded")
            return
        await page.wait_for_timeout(700)
    # The account exists and SSO is live; a missed redirect should degrade to a
    # best-effort OAuth attempt rather than discarding a good registration.
    actions.append("handoff:timeout")


async def finish_with_oauth(
    page,
    context,
    sso: str,
    actions: list[str],
    email: str,
    password: str,
    given: str,
    family: str,
    verification_url: str,
    oauth_timeout: float,
) -> dict:
    """Wait for the grok.com handoff, export cookies, then approve Device Flow."""
    # Brand-new SSO can bounce device verify to /sign-in for a short window.
    await page.wait_for_timeout(2000)
    # accounts.x.ai hands the session to grok.com to finish provisioning the
    # account. Export and consent both happen after that lands, so the cookie
    # jar handed to the standalone fallback matches what the browser really has.
    try:
        await wait_for_grok_handoff(page, actions)
    except Exception as handoff_exc:
        actions.append("handoff:error:" + re.sub(r"\s+", " ", str(handoff_exc))[:60])
    cookies = await export_cookies(context)
    oauth_ok = False
    if verification_url:
        try:
            oauth_ok = await approve_device_in_session(
                page,
                verification_url,
                actions,
                oauth_timeout,
                email=email,
                password=password,
            )
        except Exception as oauth_exc:
            actions.append(
                "oauth:error:" + re.sub(r"\s+", " ", str(oauth_exc))[:80]
            )
    return {
        "ok": True,
        "stage": "registered_oauth" if oauth_ok else "registered",
        "sso": sso,
        "oauth_authorized": oauth_ok,
        "cookies": cookies,
        "url": safe_url(page.url),
        "actions": actions[-14:],
        "email": email,
        "given_name": given,
        "family_name": family,
    }


async def register(config: dict) -> dict:
    from playwright.async_api import async_playwright

    email = str(config.get("email") or "").strip()
    password = str(config.get("password") or "")
    given = str(config.get("given_name") or config.get("givenName") or "").strip()
    family = str(config.get("family_name") or config.get("familyName") or "").strip()
    proxy = str(config.get("proxy") or "").strip()
    diagnostic_dir = str(config.get("diagnostic_dir") or "").strip()
    code_file = str(config.get("code_file") or "").strip()
    inline_code = str(config.get("code") or "").strip().upper()
    timeout = max(45.0, min(float(config.get("timeout_sec") or 180), 420.0))
    code_timeout = max(20.0, min(float(config.get("code_timeout_sec") or 100), 180.0))
    headless = bool(config.get("headless", True))
    engine = str(config.get("engine") or "chromium").strip().lower()
    if engine not in ("chromium", "camoufox"):
        raise ValueError(f"unsupported browser engine: {engine}")
    egress = config.get("egress") if isinstance(config.get("egress"), dict) else {}
    locale = str(egress.get("locale") or "en-US").strip()
    timezone_id = str(egress.get("timezone") or "").strip()
    latitude = float(egress.get("latitude") or 0)
    longitude = float(egress.get("longitude") or 0)
    allow_turnstile_inject = bool(config.get("turnstile_inject_fallback", False))
    turnstile_inject_after = max(
        10.0, float(config.get("turnstile_inject_after_sec") or 35.0)
    )
    chrome = str(config.get("chrome") or "").strip() or find_chrome()
    page_url = str(config.get("url") or "https://accounts.x.ai/sign-up?redirect=grok-com").strip()
    verification_url = str(config.get("verification_url") or "").strip()
    oauth_timeout = max(30.0, min(float(config.get("oauth_timeout_sec") or 90), 180.0))

    if not email or not password:
        raise ValueError("email and password are required")
    if not given:
        given = random.choice(
            ["James", "Emma", "Olivia", "Liam", "Noah", "Ava", "Mia", "Lucas"]
        )
    if not family:
        family = random.choice(
            ["Smith", "Johnson", "Brown", "Taylor", "Wilson", "Moore", "Clark"]
        )
    if engine == "chromium" and not chrome:
        raise RuntimeError("CloakBrowser/Chromium executable not found")
    if not code_file and not inline_code:
        raise ValueError("code_file or code is required")

    launch: dict = {
        "executable_path": chrome,
        "headless": headless,
        "args": [
            "--no-sandbox",
            "--disable-blink-features=AutomationControlled",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-networking",
            "--disable-component-update",
            "--disable-default-apps",
            "--disable-sync",
            "--disable-infobars",
            "--disable-dev-shm-usage",
            "--window-size=1280,900",
            "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
            "--webrtc-ip-handling-policy=disable_non_proxied_udp",
            "--enforce-webrtc-ip-permission-check",
        ],
    }
    if proxy:
        launch["proxy"] = playwright_proxy(proxy)

    actions: list[str] = []
    runtime = (
        _CamoufoxRuntime(config, headless, proxy)
        if engine == "camoufox"
        else async_playwright()
    )
    async with runtime as playwright:
        browser = await playwright.chromium.launch(**launch)
        page = None
        try:
            context_options = {
                "locale": locale,
                "ignore_https_errors": True,
            }
            if engine == "chromium":
                context_options["viewport"] = {"width": 1280, "height": 900}
            if timezone_id:
                context_options["timezone_id"] = timezone_id
            if latitude or longitude:
                context_options["geolocation"] = {
                    "latitude": latitude,
                    "longitude": longitude,
                }
                context_options["permissions"] = ["geolocation"]
            context = await browser.new_context(**context_options)
            if engine == "chromium":
                await context.add_init_script(
                    'Object.defineProperty(navigator,"webdriver",{get:()=>undefined})'
                )
            page = await context.new_page()
            actions.append(
                f"browser:{engine}:locale={locale}:tz={timezone_id or 'unknown'}"
            )

            last_err = None
            for attempt in range(4):
                try:
                    await page.goto(
                        page_url,
                        timeout=min(90000, int(timeout * 1000)),
                        wait_until="domcontentloaded",
                    )
                    last_err = None
                    break
                except Exception as exc:
                    last_err = exc
                    await page.wait_for_timeout(1500 + attempt * 800)
            if last_err is not None:
                raise RuntimeError(f"navigate_failed:{last_err}")

            await page.wait_for_timeout(1200 + random.randint(200, 900))
            cookie_action = await accept_cookies(page)
            if cookie_action:
                actions.append("cookies:" + cookie_action)

            # Landing → email method
            email_method = page.get_by_role(
                "button", name=re.compile(r"Sign up with email|邮箱", re.I)
            )
            if await email_method.count():
                await email_method.first.click(timeout=10000)
                actions.append("method:email")
                await write_progress(diagnostic_dir, "method_email", actions, page.url)
                await page.wait_for_timeout(800)

            email_input = None
            for _ in range(20):
                email_input = await first_visible(
                    page,
                    (
                        'input[name="email"]',
                        'input[type="email"]',
                        'input[autocomplete="email"]',
                    ),
                )
                if email_input is not None:
                    break
                # Cookie banner can reappear and block the form.
                cookie_action = await accept_cookies(page)
                if cookie_action:
                    actions.append("cookies:" + cookie_action)
                await page.wait_for_timeout(500)
            if email_input is None:
                raise RuntimeError("email_input_missing")

            # Type + verify the full email before submit. Incomplete values used
            # to advance the UI into a code step that can never succeed.
            actions.append(
                await fill_and_confirm(
                    page, email_input, email, delay=34, label="email"
                )
            )
            await page.wait_for_timeout(350)

            # Final guard: refuse to submit unless the visible input still holds
            # the complete address (React re-render can clear mid-flight).
            visible_email = (await read_input_value(email_input)).strip()
            if visible_email.lower() != email.lower():
                actions.append("fill:email:retry_mismatch")
                actions.append(
                    await fill_and_confirm(
                        page, email_input, email, delay=50, label="email"
                    )
                )
                visible_email = (await read_input_value(email_input)).strip()
            if visible_email.lower() != email.lower() or "@" not in visible_email:
                raise RuntimeError(
                    f"email_incomplete_before_submit: got={visible_email[:64]!r}"
                )
            if not re.search(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", visible_email):
                raise RuntimeError(
                    f"email_invalid_before_submit: got={visible_email[:64]!r}"
                )

            clicked = await click_positive_action(page, ("sign up", "continue", "next"))
            if not clicked:
                submit = page.locator('button[type="submit"]').first
                await submit.click(timeout=8000)
                clicked = "submit"
            actions.append("submit:email:" + clicked)
            await write_progress(diagnostic_dir, "email_submitted", actions, page.url)
            # Castle createRequestToken + send code happens here inside the page.

            # Wait for verification code field. If the email field is STILL
            # visible with a partial/invalid value, re-fill and resubmit once.
            code_input = None
            deadline = time.monotonic() + 50
            email_resubmit_done = False
            while time.monotonic() < deadline:
                code_input = await first_visible(
                    page,
                    (
                        'input[name="code"]',
                        'input[autocomplete="one-time-code"]',
                        'input[inputmode="numeric"]',
                        'input[placeholder*="code" i]',
                        'input[placeholder*="验证码" i]',
                    ),
                )
                if code_input is not None:
                    # Avoid treating a hidden/disabled mount as ready.
                    try:
                        enabled = await code_input.is_enabled()
                    except Exception:
                        enabled = True
                    if enabled:
                        try:
                            box = await code_input.bounding_box()
                        except Exception:
                            box = {"width": 20, "height": 20}
                        if box and box.get("width", 0) >= 8 and box.get("height", 0) >= 8:
                            break
                    code_input = None

                body = ""
                try:
                    body = await page.locator("body").inner_text(timeout=1500)
                except Exception:
                    pass
                if re.search(r"rate limit|try again|too many", body, re.I):
                    raise RuntimeError("email_code_rate_limited")
                if re.search(
                    r"invalid email|enter a valid email|邮箱.*无效|请输入有效",
                    body,
                    re.I,
                ):
                    raise RuntimeError("email_rejected_by_page")

                # Still on email step? Ensure full address is present and resubmit.
                if not email_resubmit_done:
                    still_email = await first_visible(
                        page,
                        (
                            'input[name="email"]',
                            'input[type="email"]',
                            'input[autocomplete="email"]',
                        ),
                    )
                    if still_email is not None:
                        current = (await read_input_value(still_email)).strip()
                        if current.lower() != email.lower():
                            actions.append("fill:email:resubmit")
                            await fill_and_confirm(
                                page, still_email, email, delay=48, label="email"
                            )
                            retry_click = await click_positive_action(
                                page, ("sign up", "continue", "next")
                            )
                            if not retry_click:
                                try:
                                    await page.locator(
                                        'button[type="submit"]'
                                    ).first.click(timeout=5000)
                                    retry_click = "submit"
                                except Exception:
                                    retry_click = ""
                            if retry_click:
                                actions.append("submit:email:retry:" + retry_click)
                            email_resubmit_done = True

                await page.wait_for_timeout(800)
            if code_input is None:
                screenshot = await save_screenshot(page, diagnostic_dir, "no-code-field")
                return {
                    "ok": False,
                    "stage": "awaiting_code_field",
                    "url": safe_url(page.url),
                    "actions": actions[-10:],
                    "screenshot": screenshot,
                    "error": "verification code field did not appear",
                }

            # External poller (Go) drops the mailbox code into code_file.
            code = inline_code
            if not code:
                # Signal readiness via tiny marker file sibling if possible.
                try:
                    Path(code_file + ".ready").write_text("1", encoding="utf-8")
                except Exception:
                    pass
                code = await wait_for_code(code_file, code_timeout)
            if not code:
                screenshot = await save_screenshot(page, diagnostic_dir, "code-timeout")
                return {
                    "ok": False,
                    "stage": "code_timeout",
                    "url": safe_url(page.url),
                    "actions": actions[-8:],
                    "screenshot": screenshot,
                    "error": "verification code not provided in time",
                }

            # Codes are short; still confirm the field actually accepted every char.
            # UIs may strip/insert the dash, so compare on alnum only.
            # The code field can remount right after appearing — retry a few times
            # instead of crashing the whole browser session on a single click timeout.
            code_filled = False
            last_code_err = ""
            for code_attempt in range(4):
                # Re-resolve in case React remounted the input.
                live_code = await first_visible(
                    page,
                    (
                        'input[name="code"]',
                        'input[autocomplete="one-time-code"]',
                        'input[inputmode="numeric"]',
                        'input[placeholder*="code" i]',
                        'input[placeholder*="验证码" i]',
                    ),
                )
                if live_code is None:
                    live_code = code_input
                try:
                    actions.append(
                        await fill_and_confirm(
                            page,
                            live_code,
                            code,
                            delay=45,
                            label="code",
                            case_insensitive=True,
                            normalize=lambda s: re.sub(r"[^A-Za-z0-9]", "", s or ""),
                        )
                    )
                    code_filled = True
                    break
                except Exception as exc:
                    last_code_err = re.sub(r"\s+", " ", str(exc))[:100]
                    actions.append(f"fill:code:retry:{code_attempt+1}")
                    await page.wait_for_timeout(700 + code_attempt * 400)
            if not code_filled:
                raise RuntimeError(f"code_fill_failed:{last_code_err}")
            await page.wait_for_timeout(350)
            confirm = await click_positive_action(
                page, ("confirm email", "confirm", "continue", "verify", "确认")
            )
            if not confirm:
                await page.locator('button[type="submit"]').first.click(timeout=8000)
                confirm = "submit"
            actions.append("submit:code:" + confirm)
            await page.wait_for_timeout(2500)

            # Credentials step: names + password (+ turnstile)
            # Important: do NOT re-run a full 40s Turnstile wait every loop iteration.
            # Overnight logs showed ~16× turnstile:timeout per attempt until Go killed
            # the process (~8 min), which surfaces as signup_browser_timeout.
            filled = False
            credentials_wait_rounds = 0
            turnstile_rounds = 0
            submit_rounds = 0
            max_turnstile_rounds = 2  # two full waits max, then fail fast
            cred_deadline = time.monotonic() + min(150.0, max(70.0, timeout * 0.55))
            for _ in range(48):
                if time.monotonic() > cred_deadline:
                    actions.append("credentials:deadline")
                    break

                sso = await read_sso_cookie(context)
                if sso:
                    actions.append("sso:present")
                    await page.wait_for_timeout(1200)
                    return await finish_with_oauth(
                        page,
                        context,
                        sso,
                        actions,
                        email,
                        password,
                        given,
                        family,
                        verification_url,
                        oauth_timeout,
                    )

                body = ""
                try:
                    body = await page.locator("body").inner_text(timeout=2000)
                except Exception:
                    pass
                if re.search(
                    r"invalid code|incorrect code|expired|验证码无效|验证码错误",
                    body,
                    re.I,
                ):
                    raise RuntimeError("invalid_or_expired_code")

                # Already past credentials form?
                if success_markers(page.url, body) and filled:
                    for _wait in range(12):
                        sso = await read_sso_cookie(context)
                        if sso:
                            return await finish_with_oauth(
                                page,
                                context,
                                sso,
                                actions,
                                email,
                                password,
                                given,
                                family,
                                verification_url,
                                oauth_timeout,
                            )
                        await page.wait_for_timeout(500)

                # Wait until Complete-your-sign-up is actually mounted.
                if not filled and not await credentials_form_ready(page):
                    credentials_wait_rounds += 1
                    if credentials_wait_rounds in (1, 5, 12, 20):
                        actions.append(
                            f"credentials:waiting_form:{credentials_wait_rounds}"
                        )
                        cookie_action = await accept_cookies(page)
                        if cookie_action:
                            actions.append("cookies:" + cookie_action)
                    if credentials_wait_rounds >= 28:
                        actions.append("credentials:form_never_ready")
                        break
                    await page.wait_for_timeout(900)
                    continue

                if not filled:
                    cred_actions = await fill_credentials(page, given, family, password)
                    if not cred_actions and await credentials_form_ready(page):
                        actions.append("credentials:fill_miss")
                        await write_progress(
                            diagnostic_dir, "credentials_fill_miss", actions, page.url
                        )
                        cred_actions = await js_force_fill(page, given, family, password)
                        if cred_actions:
                            await write_progress(
                                diagnostic_dir, "credentials_js_retry", actions, page.url
                            )
                    if not cred_actions:
                        await page.wait_for_timeout(1000)
                        continue

                    actions.extend(cred_actions)
                    filled = True
                    await write_progress(
                        diagnostic_dir, "credentials_filled", actions, page.url
                    )

                    # Re-check values before Turnstile/submit — React can wipe
                    # fields after a late re-render of the credentials step.
                    given_input, family_input, password_inputs = (
                        await find_credentials_inputs(page)
                    )
                    if given_input is not None:
                        cur = (await read_input_value(given_input)).strip()
                        if cur.lower() != given.lower():
                            actions.append("fill:givenName:recheck")
                            actions.append(
                                await fill_and_confirm(
                                    page,
                                    given_input,
                                    given,
                                    delay=40,
                                    label="givenName",
                                )
                            )
                    if family_input is not None:
                        cur = (await read_input_value(family_input)).strip()
                        if cur.lower() != family.lower():
                            actions.append("fill:familyName:recheck")
                            actions.append(
                                await fill_and_confirm(
                                    page,
                                    family_input,
                                    family,
                                    delay=40,
                                    label="familyName",
                                )
                            )
                    if password_inputs:
                        try:
                            await password_inputs[0].fill(password, timeout=4000)
                            actions.append("fill:password:recheck")
                        except Exception:
                            pass

                # Turnstile: at most max_turnstile_rounds full waits after fill.
                # First wait longer (managed + inject); second is a short salvage.
                if turnstile_rounds < max_turnstile_rounds:
                    wait_sec = 55 if turnstile_rounds == 0 else 28
                    turnstile_ok = await wait_for_turnstile(
                        page,
                        actions,
                        timeout_sec=wait_sec,
                        allow_inject=allow_turnstile_inject,
                        inject_after_sec=turnstile_inject_after,
                    )
                    turnstile_rounds += 1
                    if not turnstile_ok:
                        if await turnstile_visual_success(page):
                            actions.append("turnstile:visual_success_without_token")
                        actions.append(f"turnstile:timeout_no_submit:{turnstile_rounds}")

                    if not turnstile_ok:
                        # Never treat a visual checkmark as a bound response. A
                        # later round may still expose the host token.
                        continue

                    await page.wait_for_timeout(random.randint(500, 1100))
                    clicked = await click_positive_action(
                        page,
                        (
                            "complete sign up",
                            "create account",
                            "create",
                            "continue",
                            "sign up",
                            "submit",
                            "finish",
                            "创建账户",
                            "创建账号",
                            "完成注册",
                        ),
                    )
                    if not clicked:
                        try:
                            await page.locator('button[type="submit"]').first.click(
                                timeout=6000
                            )
                            clicked = "submit"
                        except Exception:
                            clicked = ""
                    if clicked:
                        submit_rounds += 1
                        actions.append(
                            f"submit:credentials:{clicked}:r{submit_rounds}"
                        )
                        try:
                            await page.wait_for_timeout(4500)
                        except Exception:
                            pass
                        # If submit navigated away / SSO landed, next loop catches it.
                        continue

                # After exhausting turnstile rounds, fail fast instead of burning
                # another ~40s×N until the Go process-group kill.
                if turnstile_rounds >= max_turnstile_rounds:
                    still_cred = await credentials_form_ready(page)
                    sso = await read_sso_cookie(context)
                    if sso:
                        continue
                    if still_cred or not success_markers(page.url, body):
                        screenshot = await save_screenshot(
                            page, diagnostic_dir, "turnstile-stuck"
                        )
                        await write_progress(
                            diagnostic_dir, "turnstile_stuck", actions, page.url
                        )
                        return {
                            "ok": False,
                            "stage": "turnstile_stuck",
                            "url": safe_url(page.url),
                            "actions": actions[-18:],
                            "screenshot": screenshot,
                            "error": "turnstile_not_passed_after_retries",
                        }

                await page.wait_for_timeout(900)

            sso = await read_sso_cookie(context)
            if sso:
                return await finish_with_oauth(
                    page,
                    context,
                    sso,
                    actions,
                    email,
                    password,
                    given,
                    family,
                    verification_url,
                    oauth_timeout,
                )

            screenshot = await save_screenshot(page, diagnostic_dir, "timeout")
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
                "actions": actions[-10:],
                "screenshot": screenshot,
                "error": "signup did not produce SSO session",
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
                "actions": actions[-10:],
                "screenshot": screenshot,
            }
        finally:
            if engine != "camoufox":
                await browser.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stdin-json", action="store_true", required=True)
    args = parser.parse_args()
    _ = args
    try:
        raw = sys.stdin.buffer.read(1 << 20)
        config = json.loads(raw.decode("utf-8"))
        result = asyncio.run(register(config))
    except Exception as exc:
        result = {
            "ok": False,
            "stage": "bootstrap_error",
            "error": re.sub(r"\s+", " ", str(exc))[:180],
        }
    # Never echo password; sso is intentionally returned for the Go caller.
    sys.stdout.write(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
