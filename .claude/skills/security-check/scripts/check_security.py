#!/usr/bin/env python3
"""HTML/JS 파일을 4가지 보안 관점(하드코딩된 비밀번호·API 키 / innerHTML XSS /
console.log 민감정보 노출 / http:// 외부 요청)으로 점검하고 원시 진단 결과를
JSON으로 출력한다. 심각도 분류와 한국어 보고서 작성은 SKILL.md의 지침에 따라
이 스크립트를 호출한 모델이 수행한다.

정규식 기반 한 줄(라인) 단위 점검이라 여러 줄에 걸친 코드나 변수를 거쳐 전달되는
값은 놓칠 수 있다 — 스크립트 결과는 "후보"이며, 최종 판단과 오탐 제거는 모델이 한다.

사용법: python check_security.py <html_or_js_file>
"""
import json
import re
import sys
from pathlib import Path

# Windows 콘솔의 기본 코드페이지(cp949 등)로 인쇄되면 한글 스니펫이 깨지므로,
# 항상 UTF-8로 출력하도록 강제한다.
try:
    sys.stdout.reconfigure(encoding="utf-8")
except AttributeError:
    pass

SECRET_KEY_RE = re.compile(
    r"""(?ix)
    \b([\w-]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|
       access[_-]?key|private[_-]?key|auth[_-]?key|credential[s]?)[\w-]*)
    \s*[:=]\s*
    (['"])((?:(?!\2).){3,})\2
    """
)

PLACEHOLDER_HINTS = (
    "your", "xxxx", "example", "changeme", "replace", "todo", "<", "{{",
    "$env", "process.env", "import.meta", "insert_", "here", "***",
)

INNERHTML_RE = re.compile(r"""(?x)
    \.(innerHTML|outerHTML)\s*(\+?=)\s*(?P<expr>[^;]+);?
    |
    document\.write\s*\(\s*(?P<expr2>[^)]*)\)
""")

USER_INPUT_HINTS = (
    ".value", "target.value", "urlsearchparams", "location.search",
    "location.hash", "prompt(", "decodeuricomponent", ".get(",
    "document.cookie", "e.data", "event.data",
)

CONSOLE_RE = re.compile(r"console\.(log|debug|info|warn|error)\s*\((?P<args>.*)")

SENSITIVE_LOG_HINTS = (
    "password", "passwd", "pwd", "secret", "token", "apikey", "api_key",
    "api-key", "accesskey", "access_key", "privatekey", "private_key",
    "card", "cvv", "ssn", "credential",
)

HTTP_URL_RE = re.compile(r"(?<!s)\bhttp://[^\s'\"<>)]+")

CONTEXT_HINTS = (
    "fetch", "xmlhttprequest", "axios", "src=", "href=", "action=",
    ".open(", "websocket",
)


STATIC_STRING_RE = re.compile(r"""^(['"`])(?:\\.|(?!\1).)*\1$""", re.DOTALL)


def is_static_string_literal(expr):
    expr = expr.strip()
    if not STATIC_STRING_RE.match(expr):
        return False
    if expr[0] == "`" and "${" in expr:
        return False
    return True


def looks_like_placeholder(value):
    lowered = value.lower()
    return any(hint in lowered for hint in PLACEHOLDER_HINTS) or value.strip() == ""


def mask_secret(value):
    if len(value) <= 6:
        return "*" * len(value)
    return value[:2] + "*" * (len(value) - 4) + value[-2:]


def check_hardcoded_secrets(lines):
    findings = []
    for i, line in enumerate(lines, start=1):
        for m in SECRET_KEY_RE.finditer(line):
            key, _, value = m.group(1), m.group(2), m.group(3)
            findings.append({
                "line": i,
                "key": key,
                "value_masked": mask_secret(value),
                "looks_like_placeholder": looks_like_placeholder(value),
                "snippet": line.strip()[:200],
            })
    return findings


def check_innerhtml_xss(lines):
    findings = []
    context_window = 6
    for i, line in enumerate(lines, start=1):
        for m in INNERHTML_RE.finditer(line):
            expr = m.group("expr") or m.group("expr2") or ""
            if is_static_string_literal(expr):
                continue
            context = "\n".join(lines[max(0, i - 1 - context_window):i]).lower()
            likely_user_input = any(hint in context for hint in USER_INPUT_HINTS)
            findings.append({
                "line": i,
                "sink": "document.write" if m.group("expr2") is not None else m.group(1),
                "assigned_expr": expr.strip()[:200],
                "likely_user_input": likely_user_input,
                "snippet": line.strip()[:200],
            })
    return findings


def check_console_log_sensitive(lines):
    findings = []
    for i, line in enumerate(lines, start=1):
        m = CONSOLE_RE.search(line)
        if not m:
            continue
        args = m.group("args")
        lowered = args.lower()
        matched_keywords = [h for h in SENSITIVE_LOG_HINTS if h in lowered]
        if matched_keywords:
            findings.append({
                "line": i,
                "matched_keywords": matched_keywords,
                "snippet": line.strip()[:200],
            })
    return findings


def check_http_external(lines):
    findings = []
    for i, line in enumerate(lines, start=1):
        for m in HTTP_URL_RE.finditer(line):
            url = m.group(0)
            lowered_line = line.lower()
            context = [h for h in CONTEXT_HINTS if h in lowered_line]
            is_local = any(host in url for host in ("://localhost", "://127.0.0.1", "://0.0.0.0"))
            findings.append({
                "line": i,
                "url": url,
                "context_hints": context,
                "is_local": is_local,
                "snippet": line.strip()[:200],
            })
    return findings


def main():
    if len(sys.argv) != 2:
        print("사용법: python check_security.py <html_or_js_file>", file=sys.stderr)
        sys.exit(1)

    file_path = Path(sys.argv[1])
    if not file_path.exists():
        print(json.dumps({"error": f"파일을 찾을 수 없음: {file_path}"}, ensure_ascii=False))
        sys.exit(1)

    text = file_path.read_bytes().decode("utf-8", errors="replace")
    lines = text.splitlines()

    result = {
        "file": str(file_path),
        "hardcoded_secrets": check_hardcoded_secrets(lines),
        "innerhtml_xss": check_innerhtml_xss(lines),
        "console_log_sensitive": check_console_log_sensitive(lines),
        "http_external": check_http_external(lines),
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
