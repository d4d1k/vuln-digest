from __future__ import annotations

import argparse
import json
import logging
import os
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

BASE_DIR = Path(__file__).resolve().parent
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
LOG = logging.getLogger("vuln-digest")


class DigestError(RuntimeError):
    pass


@dataclass(frozen=True)
class Settings:
    nvd_api_key: str
    openrouter_api_key: str
    openrouter_model: str
    telegram_bot_token: str
    telegram_chat_id: str
    top_n: int
    lookback_hours: int
    interval_hours: int
    db_path: Path

    @classmethod
    def from_env(cls) -> "Settings":
        top_n = positive_int("DIGEST_TOP_N", 10)
        lookback_hours = positive_int("DIGEST_LOOKBACK_HOURS", 24)
        interval_hours = positive_int("DIGEST_INTERVAL_HOURS", 24)
        db_path = Path(os.getenv("DIGEST_DB_PATH", "data/state.sqlite3")).expanduser()
        if not db_path.is_absolute():
            db_path = BASE_DIR / db_path
        return cls(
            nvd_api_key=os.getenv("NVD_API_KEY", "").strip(),
            openrouter_api_key=os.getenv("OPENROUTER_API_KEY", "").strip(),
            openrouter_model=os.getenv("OPENROUTER_MODEL", "openrouter/free").strip(),
            telegram_bot_token=os.getenv("TELEGRAM_BOT_TOKEN", "").strip(),
            telegram_chat_id=os.getenv("TELEGRAM_CHAT_ID", "").strip(),
            top_n=top_n,
            lookback_hours=lookback_hours,
            interval_hours=interval_hours,
            db_path=db_path,
        )


@dataclass
class DigestItem:
    cve_id: str
    categories: list[str]
    nvd: dict[str, Any] | None
    kev: dict[str, Any] | None


def positive_int(name: str, default: int) -> int:
    raw = os.getenv(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise DigestError(f"{name} must be an integer") from exc
    if value <= 0:
        raise DigestError(f"{name} must be greater than zero")
    return value


def load_env(path: Path) -> None:
    if not path.exists():
        return
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            raise DigestError(f"Invalid .env line {line_number}")
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        os.environ.setdefault(key, value)


def request_json(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    data: bytes | None = None,
    retries: int = 3,
) -> dict[str, Any]:
    request_headers = {"User-Agent": "vuln-digest/0.1", **(headers or {})}
    host = urlsplit(url).netloc
    for attempt in range(retries):
        request = Request(url, data=data, headers=request_headers)
        try:
            with urlopen(request, timeout=60) as response:
                return json.load(response)
        except HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")[:500]
            retryable = exc.code == 429 or exc.code >= 500
            if not retryable or attempt == retries - 1:
                raise DigestError(f"HTTP {exc.code} from {host}: {body}") from exc
        except (URLError, TimeoutError) as exc:
            if attempt == retries - 1:
                raise DigestError(f"Request to {host} failed: {exc.reason if hasattr(exc, 'reason') else exc}") from exc
        time.sleep(2**attempt)
    raise DigestError(f"Request to {host} failed")


def parse_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def nvd_date(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")


def nvd_headers(api_key: str) -> dict[str, str]:
    return {"apiKey": api_key} if api_key else {}


def fetch_nvd(since: datetime, until: datetime, api_key: str) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    start_index = 0
    while True:
        query = urlencode(
            {
                "pubStartDate": nvd_date(since),
                "pubEndDate": nvd_date(until),
                "resultsPerPage": 2000,
                "startIndex": start_index,
            }
        )
        payload = request_json(f"{NVD_URL}?{query}", headers=nvd_headers(api_key))
        batch = payload.get("vulnerabilities", [])
        results.extend(batch)
        total = int(payload.get("totalResults", len(results)))
        start_index += len(batch)
        if not batch or start_index >= total:
            break
        time.sleep(0.8 if api_key else 6)
    return results


def fetch_nvd_cve(cve_id: str, api_key: str) -> dict[str, Any] | None:
    payload = request_json(f"{NVD_URL}?{urlencode({'cveId': cve_id})}", headers=nvd_headers(api_key))
    vulnerabilities = payload.get("vulnerabilities", [])
    return vulnerabilities[0] if vulnerabilities else None


def fetch_kev() -> list[dict[str, Any]]:
    return request_json(KEV_URL).get("vulnerabilities", [])


def english_description(descriptions: list[dict[str, Any]]) -> str:
    for description in descriptions:
        if description.get("lang") == "en":
            return description.get("value", "")
    return descriptions[0].get("value", "") if descriptions else ""


def extract_cvss(cve: dict[str, Any]) -> dict[str, Any] | None:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        values = metrics.get(key, [])
        if not values:
            continue
        metric = next((item for item in values if item.get("type") == "Primary"), values[0])
        data = metric.get("cvssData", {})
        return {
            "score": data.get("baseScore"),
            "severity": data.get("baseSeverity") or metric.get("baseSeverity"),
            "vector": data.get("vectorString"),
            "version": data.get("version"),
        }
    return None


def extract_affected(cve: dict[str, Any]) -> list[str]:
    affected: list[str] = []
    for configuration in cve.get("configurations", []):
        for node in configuration.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable", False):
                    continue
                parts = match.get("criteria", "").split(":")
                if len(parts) > 5:
                    product = f"{parts[3]} {parts[4]}".replace("_", " ")
                    version = parts[5]
                else:
                    product = match.get("criteria", "Unknown product")
                    version = ""
                constraints = []
                for key, label in (
                    ("versionStartIncluding", ">="),
                    ("versionStartExcluding", ">"),
                    ("versionEndIncluding", "<="),
                    ("versionEndExcluding", "<"),
                ):
                    if match.get(key):
                        constraints.append(f"{label} {match[key]}")
                detail = product
                if version and version != "*":
                    detail += f" {version}"
                if constraints:
                    detail += f" ({', '.join(constraints)})"
                if detail not in affected:
                    affected.append(detail)
    return affected[:20]


def normalize_nvd(wrapper: dict[str, Any]) -> dict[str, Any]:
    cve = wrapper.get("cve", {})
    weaknesses = []
    for weakness in cve.get("weaknesses", []):
        for description in weakness.get("description", []):
            value = description.get("value")
            if value and value not in weaknesses and not value.startswith("NVD-CWE"):
                weaknesses.append(value)
    references = [
        {"url": reference.get("url"), "tags": reference.get("tags", [])}
        for reference in cve.get("references", [])[:15]
    ]
    return {
        "id": cve.get("id", ""),
        "published": cve.get("published", ""),
        "last_modified": cve.get("lastModified", ""),
        "status": cve.get("vulnStatus", ""),
        "description": english_description(cve.get("descriptions", [])),
        "cvss": extract_cvss(cve),
        "affected": extract_affected(cve),
        "cwe": weaknesses,
        "references": references,
        "source": f"https://nvd.nist.gov/vuln/detail/{cve.get('id', '')}",
    }


def normalize_kev(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": record.get("cveID", ""),
        "name": record.get("vulnerabilityName", ""),
        "vendor": record.get("vendorProject", ""),
        "product": record.get("product", ""),
        "date_added": record.get("dateAdded", ""),
        "due_date": record.get("dueDate", ""),
        "description": record.get("shortDescription", ""),
        "required_action": record.get("requiredAction", ""),
        "ransomware": record.get("knownRansomwareCampaignUse", "Unknown"),
        "notes": record.get("notes", ""),
        "cwe": record.get("cwes", []),
        "source": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    }


class State:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.execute(
            "CREATE TABLE IF NOT EXISTS sent_items ("
            "cve_id TEXT NOT NULL, category TEXT NOT NULL, sent_at TEXT NOT NULL, "
            "PRIMARY KEY (cve_id, category))"
        )
        self.connection.commit()

    def is_sent(self, cve_id: str, category: str) -> bool:
        row = self.connection.execute(
            "SELECT 1 FROM sent_items WHERE cve_id = ? AND category = ?", (cve_id, category)
        ).fetchone()
        return row is not None

    def mark_sent(self, items: list[DigestItem], sent_at: datetime) -> None:
        rows = [
            (item.cve_id, category, sent_at.isoformat())
            for item in items
            for category in item.categories
        ]
        self.connection.executemany(
            "INSERT OR IGNORE INTO sent_items (cve_id, category, sent_at) VALUES (?, ?, ?)", rows
        )
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()


def collect_items(settings: Settings, state: State, now: datetime) -> tuple[list[DigestItem], datetime]:
    since = now - timedelta(hours=settings.lookback_hours)
    raw_nvd = fetch_nvd(since, now, settings.nvd_api_key)
    normalized_nvd = [normalize_nvd(item) for item in raw_nvd]
    critical = []
    for item in normalized_nvd:
        score = (item.get("cvss") or {}).get("score")
        if not item["id"] or item["status"] == "Rejected" or score is None or score < 9:
            continue
        if parse_datetime(item["published"]) < since or state.is_sent(item["id"], "critical"):
            continue
        critical.append(item)
    critical.sort(key=lambda item: (item["cvss"]["score"], parse_datetime(item["published"])), reverse=True)
    critical = critical[: settings.top_n]

    new_kev = []
    for raw_record in fetch_kev():
        record = normalize_kev(raw_record)
        try:
            added = datetime.fromisoformat(record["date_added"]).date()
        except ValueError:
            continue
        if since.date() <= added <= now.date() and not state.is_sent(record["id"], "kev"):
            new_kev.append(record)
    new_kev.sort(key=lambda item: item["date_added"], reverse=True)
    new_kev = new_kev[: settings.top_n]

    critical_by_id = {item["id"]: item for item in critical}
    kev_by_id = {item["id"]: item for item in new_kev}
    nvd_by_id = critical_by_id.copy()
    for cve_id in kev_by_id.keys() - nvd_by_id.keys():
        try:
            raw_cve = fetch_nvd_cve(cve_id, settings.nvd_api_key)
            if raw_cve:
                nvd_by_id[cve_id] = normalize_nvd(raw_cve)
        except DigestError as exc:
            LOG.warning("Could not enrich %s from NVD: %s", cve_id, exc)
        time.sleep(0.8 if settings.nvd_api_key else 6)

    items = []
    for cve_id in critical_by_id.keys() | kev_by_id.keys():
        categories = []
        if cve_id in critical_by_id:
            categories.append("critical")
        if cve_id in kev_by_id:
            categories.append("kev")
        items.append(DigestItem(cve_id, categories, nvd_by_id.get(cve_id), kev_by_id.get(cve_id)))
    items.sort(
        key=lambda item: (
            "kev" not in item.categories,
            -((item.nvd or {}).get("cvss") or {}).get("score", -1),
            item.cve_id,
        )
    )
    LOG.info(
        "Selected %d items: %d critical, %d KEV (NVD returned %d)",
        len(items),
        len(critical_by_id),
        len(kev_by_id),
        len(raw_nvd),
    )
    return items, since


def report_payload(items: list[DigestItem], since: datetime, until: datetime) -> dict[str, Any]:
    return {
        "period_utc": {"from": since.isoformat(), "to": until.isoformat()},
        "items": [
            {
                "cve_id": item.cve_id,
                "categories": item.categories,
                "nvd": item.nvd,
                "cisa_kev": item.kev,
            }
            for item in items
        ],
    }


def generate_llm_report(settings: Settings, items: list[DigestItem], since: datetime, now: datetime) -> str:
    system_prompt = (
        "Ты составляешь краткую русскоязычную сводку кибербезопасности. Используй только факты "
        "из переданного JSON, ничего не додумывай. Если сведений нет, напиши «Нет данных». "
        "Для каждой CVE укажи: категорию (новая критичная и/или CISA KEV), дату публикации, "
        "затронутые продукты, суть и условия уязвимости, высокоуровневый способ эксплуатации, "
        "подтверждение эксплуатации через KEV, сведения о патче только из ссылок и requiredAction, "
        "защитные и компенсирующие меры, ссылки на источники. Не называй дату публикации датой "
        "обнаружения. CVSS без значения не считай критичным. Не добавляй exploit-код. Сначала "
        "дай общий заголовок и количество уязвимостей, затем карточки. Пиши простым текстом."
    )
    body = json.dumps(
        {
            "model": settings.openrouter_model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": json.dumps(report_payload(items, since, now), ensure_ascii=False)},
            ],
            "temperature": 0.1,
        },
        ensure_ascii=False,
    ).encode("utf-8")
    payload = request_json(
        OPENROUTER_URL,
        headers={
            "Authorization": f"Bearer {settings.openrouter_api_key}",
            "Content-Type": "application/json",
        },
        data=body,
    )
    content = payload["choices"][0]["message"]["content"]
    if not isinstance(content, str) or not content.strip():
        raise DigestError("OpenRouter returned an empty report")
    return content.strip()


def fallback_report(items: list[DigestItem], since: datetime, now: datetime) -> str:
    lines = [
        "Сводка новых уязвимостей",
        f"Период UTC: {since:%Y-%m-%d %H:%M} — {now:%Y-%m-%d %H:%M}",
        f"Всего: {len(items)}",
    ]
    if not items:
        lines.append("Новых критичных CVE и новых записей CISA KEV за период не найдено.")
        return "\n".join(lines)
    for item in items:
        labels = {"critical": "Новая критичная", "kev": "CISA KEV"}
        lines.extend(["", "=" * 48, f"{item.cve_id} — {', '.join(labels[c] for c in item.categories)}"])
        nvd = item.nvd
        kev = item.kev
        if kev:
            lines.extend(
                [
                    f"Название: {kev['name']}",
                    f"Продукт: {kev['vendor']} {kev['product']}",
                    f"Добавлена в KEV: {kev['date_added']}",
                    f"Подтверждённая эксплуатация: да, по каталогу CISA KEV",
                    f"Использование в ransomware: {kev['ransomware']}",
                    f"Требуемое действие: {kev['required_action']}",
                ]
            )
        if nvd:
            cvss = nvd.get("cvss") or {}
            lines.extend(
                [
                    f"Опубликована: {nvd['published']}",
                    f"CVSS: {cvss.get('score', 'Нет данных')} {cvss.get('severity') or ''} "
                    f"{cvss.get('vector') or ''}".strip(),
                    f"Описание: {nvd['description'] or 'Нет данных'}",
                    f"CWE: {', '.join(nvd['cwe']) or 'Нет данных'}",
                    "Затронутые продукты: " + ("; ".join(nvd["affected"]) or "Нет данных"),
                ]
            )
        elif kev:
            lines.append(f"Описание: {kev['description']}")
        lines.append(
            "Патч и компенсирующие меры: выполнить requiredAction CISA и проверить ссылки "
            "производителя; конкретная версия исправления требует подтверждения из advisory."
            if kev
            else "Патч и компенсирующие меры: проверить ссылки производителя; данных для точного вывода недостаточно."
        )
        sources = []
        if nvd:
            sources.append(nvd["source"])
            sources.extend(ref["url"] for ref in nvd["references"][:5] if ref.get("url"))
        if kev:
            sources.append(kev["source"])
        lines.append("Источники: " + "\n".join(dict.fromkeys(sources)))
    return "\n".join(lines)


def render_report(settings: Settings, items: list[DigestItem], since: datetime, now: datetime) -> str:
    if items and settings.openrouter_api_key:
        try:
            return generate_llm_report(settings, items, since, now)
        except (DigestError, KeyError, IndexError, TypeError) as exc:
            LOG.warning("LLM report failed, using factual fallback: %s", exc)
    elif items:
        LOG.info("OPENROUTER_API_KEY is not set; using factual fallback")
    return fallback_report(items, since, now)


def split_message(text: str, limit: int = 4000) -> list[str]:
    chunks = []
    remaining = text.strip()
    while len(remaining) > limit:
        split_at = remaining.rfind("\n", 0, limit + 1)
        if split_at < limit // 2:
            split_at = limit
        chunks.append(remaining[:split_at].strip())
        remaining = remaining[split_at:].strip()
    if remaining:
        chunks.append(remaining)
    return chunks


def send_telegram(settings: Settings, text: str) -> None:
    if not settings.telegram_bot_token or not settings.telegram_chat_id:
        raise DigestError("TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID are required for sending")
    url = f"https://api.telegram.org/bot{settings.telegram_bot_token}/sendMessage"
    chunks = split_message(text)
    for index, chunk in enumerate(chunks):
        data = urlencode(
            {
                "chat_id": settings.telegram_chat_id,
                "text": chunk,
                "disable_web_page_preview": "true",
            }
        ).encode("utf-8")
        response = request_json(url, data=data)
        if not response.get("ok"):
            raise DigestError("Telegram API returned an unsuccessful response")
        if index < len(chunks) - 1:
            time.sleep(0.5)


def run_once(settings: Settings, dry_run: bool = False) -> None:
    now = datetime.now(timezone.utc)
    state = State(settings.db_path)
    try:
        items, since = collect_items(settings, state, now)
        report = render_report(settings, items, since, now)
        if dry_run:
            print(report)
            LOG.info("Dry run: nothing sent and no items marked as processed")
            return
        send_telegram(settings, report)
        state.mark_sent(items, now)
        LOG.info("Digest sent successfully")
    finally:
        state.close()


def run_daemon(settings: Settings) -> None:
    LOG.info("Starting daemon with a %d-hour interval", settings.interval_hours)
    while True:
        try:
            run_once(settings)
        except Exception:
            LOG.exception("Digest run failed")
        time.sleep(settings.interval_hours * 3600)


def main() -> None:
    parser = argparse.ArgumentParser(description="Critical CVE and CISA KEV digest for Telegram")
    parser.add_argument("--env-file", type=Path, default=BASE_DIR / ".env")
    parser.add_argument("--verbose", action="store_true")
    subparsers = parser.add_subparsers(dest="command", required=True)
    run_parser = subparsers.add_parser("run", help="collect and send one digest")
    run_parser.add_argument("--dry-run", action="store_true", help="print without sending or saving state")
    subparsers.add_parser("daemon", help="run continuously at DIGEST_INTERVAL_HOURS")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    try:
        load_env(args.env_file.resolve())
        settings = Settings.from_env()
        if args.command == "run":
            run_once(settings, dry_run=args.dry_run)
        else:
            run_daemon(settings)
    except DigestError as exc:
        LOG.error("%s", exc)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
