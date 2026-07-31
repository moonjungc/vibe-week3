#!/usr/bin/env python3
"""HTML 페이지를 5가지 관점(title / 내부 링크 / img alt / viewport / UTF-8 인코딩)으로
점검하고 원시 진단 결과를 JSON으로 출력한다. 심각도 분류와 한국어 보고서 작성은
SKILL.md의 지침에 따라 이 스크립트를 호출한 모델이 수행한다.

사용법: python check_page.py <html_file>
"""
import json
import re
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

EXTERNAL_SCHEMES = ("http://", "https://", "//", "mailto:", "tel:", "ftp:", "javascript:", "data:")


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title_text = None
        self._in_title = False
        self.meta_tags = []  # list of attr dicts
        self.images = []  # list of (attrs dict, has_alt bool)
        self.links = []  # list of href strings
        self.ids = set()  # id/name attribute values found anywhere in the doc

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        for key in ("id", "name"):
            if attrs_dict.get(key):
                self.ids.add(attrs_dict[key])

        if tag == "title":
            self._in_title = True
            self.title_text = ""
        elif tag == "meta":
            self.meta_tags.append(attrs_dict)
        elif tag == "img":
            self.images.append({"has_alt": "alt" in attrs_dict, "src": attrs_dict.get("src", "")})
        elif tag == "a" and attrs_dict.get("href") is not None:
            self.links.append(attrs_dict["href"])

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self.title_text += data


def check_title(parser):
    if parser.title_text is None:
        return {"present": False, "text": None, "empty": None}
    text = parser.title_text.strip()
    return {"present": True, "text": text, "empty": text == ""}


def check_viewport(parser):
    for meta in parser.meta_tags:
        name = (meta.get("name") or "").strip().lower()
        if name == "viewport":
            return {"present": True, "content": meta.get("content", "")}
    return {"present": False, "content": None}


def check_charset(file_path, parser, raw_bytes):
    declared = None
    for meta in parser.meta_tags:
        if meta.get("charset"):
            declared = meta["charset"].strip()
            break
        http_equiv = (meta.get("http-equiv") or "").strip().lower()
        if http_equiv == "content-type":
            content = meta.get("content", "")
            m = re.search(r"charset=([\w-]+)", content, re.IGNORECASE)
            if m:
                declared = m.group(1)
                break

    declared_is_utf8 = bool(declared) and declared.strip().lower().replace("-", "") == "utf8"

    decodes_as_utf8 = True
    try:
        raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        decodes_as_utf8 = False

    return {
        "declared_charset": declared,
        "declared_is_utf8": declared_is_utf8,
        "file_decodes_as_utf8": decodes_as_utf8,
    }


def check_images(parser):
    missing_alt = [img["src"] for img in parser.images if not img["has_alt"]]
    return {"total": len(parser.images), "missing_alt": missing_alt}


def check_links(parser, file_path):
    base_dir = file_path.resolve().parent
    broken = []
    checked = 0
    for href in parser.links:
        href = href.strip()
        if not href or href.lower().startswith(EXTERNAL_SCHEMES):
            continue
        checked += 1
        if href.startswith("#"):
            fragment = href[1:]
            if fragment and fragment not in parser.ids:
                broken.append({"href": href, "reason": f"페이지 안에 id/name=\"{fragment}\" 요소가 없음"})
            continue

        split = urlsplit(href)
        path_part = split.path
        if not path_part:
            continue
        target = (base_dir / path_part).resolve()
        if not target.exists():
            broken.append({"href": href, "reason": f"파일이 존재하지 않음: {target}"})
            continue
        if split.fragment and target.is_file():
            try:
                target_text = target.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                target_text = ""
            if f'id="{split.fragment}"' not in target_text and f"name=\"{split.fragment}\"" not in target_text:
                broken.append({"href": href, "reason": f"대상 파일에 id/name=\"{split.fragment}\" 요소가 없음"})

    return {"checked": checked, "broken": broken}


def main():
    if len(sys.argv) != 2:
        print("사용법: python check_page.py <html_file>", file=sys.stderr)
        sys.exit(1)

    file_path = Path(sys.argv[1])
    if not file_path.exists():
        print(json.dumps({"error": f"파일을 찾을 수 없음: {file_path}"}, ensure_ascii=False))
        sys.exit(1)

    raw_bytes = file_path.read_bytes()
    text = raw_bytes.decode("utf-8", errors="replace")

    parser = PageParser()
    parser.feed(text)

    result = {
        "file": str(file_path),
        "title": check_title(parser),
        "viewport": check_viewport(parser),
        "charset": check_charset(file_path, parser, raw_bytes),
        "images": check_images(parser),
        "links": check_links(parser, file_path),
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
