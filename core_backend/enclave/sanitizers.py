"""
Content sanitization pipeline. Runs inside the enclave worker process, so it must
not use relative imports or touch the filesystem or network.

Every handler returns sanitized bytes; the pipeline then re-scans its own output
and refuses to release it if anything dangerous remains.
"""

import csv
import html
import io
import re
import unicodedata
import xml.etree.ElementTree as ET
import zipfile
import zlib
from html.parser import HTMLParser
from posixpath import dirname, join as pjoin, normpath

MAX_INPUT_BYTES = 10 * 1024 * 1024
MAX_ZIP_ENTRIES = 2000
MAX_ZIP_TOTAL_BYTES = 100 * 1024 * 1024
MAX_ZIP_RATIO = 100
MAX_PDF_INFLATED_BYTES = 100 * 1024 * 1024
MAX_ANCHORS_REPORTED = 1000
MAX_LOCATIONS_PER_THREAT = 50

# Split so this source file itself never contains the contiguous test signature.
EICAR_SIGNATURE = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

DANGEROUS_EXTENSIONS = {
    "exe", "dll", "scr", "com", "pif", "cpl", "msi", "msp", "bat", "cmd", "ps1", "psm1", "vbs", "vbe",
    "js", "jse", "wsf", "wsh", "hta", "jar", "lnk", "reg", "sh", "apk", "app", "iso", "img", "vhd", "sys", "drv",
}

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
MACHO_MAGICS = {b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"}


class Rejected(Exception):
    def __init__(self, code: str, message: str, detected_type: str = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.detected_type = detected_type


class Report:
    def __init__(self):
        self.threats = {}
        self.anchors = []
        self.anchor_count = 0
        self.notes = []

    def threat(self, code, severity, description, location=None):
        entry = self.threats.setdefault(code, {"code": code, "severity": severity, "description": description, "count": 0, "locations": []})
        entry["count"] += 1
        if location is not None and len(entry["locations"]) < MAX_LOCATIONS_PER_THREAT:
            entry["locations"].append(str(location))

    def note(self, text):
        if text not in self.notes:
            self.notes.append(text)

    def has_findings(self):
        return bool(self.threats) or self.anchor_count > 0


# --------------------------------------------------------------------------- #
# Character anchor mapping
# --------------------------------------------------------------------------- #

BIDI_CONTROLS = {0x061C, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069}
ZERO_WIDTH = {0x200B, 0x2060, 0xFEFF, 0x180E}
JOINERS = {0x200C, 0x200D}

CONFUSABLES = {
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ӏ": "l",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X", "І": "I", "Ј": "J", "Ѕ": "S",
    # Greek
    "ο": "o", "α": "a", "ν": "v", "ι": "i", "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M",
    "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
}

ANCHOR_THREATS = {
    "bidi_control": ("high", "Bidirectional control characters that can reorder displayed text (Trojan Source)"),
    "zero_width": ("medium", "Invisible zero-width characters used to hide or split content"),
    "control": ("low", "Non-printing control characters"),
    "homoglyph": ("medium", "Lookalike characters from another script mixed into a Latin word (homograph spoofing)"),
}

_WORD = re.compile(r"[^\W\d_]+")


def _char_name(ch):
    return unicodedata.name(ch, "CONTROL CHARACTER" if unicodedata.category(ch) == "Cc" else "UNNAMED")


def map_character_anchors(text: str, report: Report) -> str:
    """Neutralize deceptive characters and record each one as a positional anchor."""
    homoglyph_positions = set()
    for m in _WORD.finditer(text):
        word = m.group()
        if any(ch in CONFUSABLES for ch in word) and any(ch.isascii() for ch in word):
            homoglyph_positions.update(m.start() + i for i, ch in enumerate(word) if ch in CONFUSABLES)

    out = []
    line, column = 1, 0
    last = len(text) - 1
    for i, ch in enumerate(text):
        cp = ord(ch)
        category = action = replacement = None
        if cp in BIDI_CONTROLS:
            category, action = "bidi_control", "removed"
        elif cp in JOINERS:
            prev_ascii = i > 0 and text[i - 1].isascii() and text[i - 1].isalnum()
            next_ascii = i < last and text[i + 1].isascii() and text[i + 1].isalnum()
            if prev_ascii or next_ascii:
                category, action = "zero_width", "removed"
        elif cp in ZERO_WIDTH:
            category, action = "zero_width", "removed"
        elif (cp < 32 and ch not in "\t\n\r") or cp == 0x7F or 0x80 <= cp <= 0x9F:
            category, action = "control", "removed"
        elif i in homoglyph_positions:
            category, action, replacement = "homoglyph", "replaced", CONFUSABLES[ch]

        column += 1
        if category:
            report.anchor_count += 1
            severity, description = ANCHOR_THREATS[category]
            report.threat(category, severity, description, f"line {line}, column {column}")
            if len(report.anchors) < MAX_ANCHORS_REPORTED:
                anchor = {"offset": i, "line": line, "column": column, "codepoint": f"U+{cp:04X}", "name": _char_name(ch), "category": category, "action": action}
                if replacement is not None:
                    anchor["replacement"] = replacement
                report.anchors.append(anchor)
            if replacement is not None:
                out.append(replacement)
        else:
            out.append(ch)
        if ch == "\n":
            line, column = line + 1, 0
    return "".join(out)


# --------------------------------------------------------------------------- #
# Type detection
# --------------------------------------------------------------------------- #

def _extension(name: str) -> str:
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    return base.rsplit(".", 1)[-1].lower() if "." in base else ""


def decode_text(data: bytes):
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8"), "utf-8-bom"
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16"), "utf-16"
    if b"\x00" in data:
        raise Rejected("unsupported_type", "Binary content of an unsupported type")
    try:
        return data.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        raise Rejected("unsupported_encoding", "Text files must be UTF-8 or UTF-16 encoded")


def encode_text(text: str, encoding: str) -> bytes:
    if encoding == "utf-8-bom":
        return b"\xef\xbb\xbf" + text.encode("utf-8")
    if encoding == "utf-16":
        return text.encode("utf-16")
    return text.encode("utf-8")


def detect_type(data: bytes, name: str) -> str:
    ext = _extension(name)
    if data[:2] == b"MZ" or data[:4] == b"\x7fELF" or data[:4] in MACHO_MAGICS:
        raise Rejected("executable", "Executable programs are not accepted", "executable")
    if ext in DANGEROUS_EXTENSIONS:
        raise Rejected("dangerous_extension", f"Files of type .{ext} are not accepted", "blocked")
    if data.startswith(b"#!"):
        raise Rejected("script", "Shell scripts are not accepted", "script")
    if data.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                names = set(zf.namelist())
        except zipfile.BadZipFile:
            raise Rejected("corrupt_archive", "The archive is corrupt", "zip")
        if "[Content_Types].xml" in names:
            return "ooxml"
        raise Rejected("archive_unsupported", "Generic archives are not accepted; upload the files individually", "zip")
    if data.startswith(OLE_MAGIC):
        raise Rejected("legacy_office", "Legacy Office formats (.doc/.xls/.ppt) can't be sanitized safely; save as .docx/.xlsx/.pptx", "ole")
    if b"%PDF-" in data[:1024]:
        return "pdf"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "gif"

    text, _ = decode_text(data)
    head = text.lstrip()[:2000].lower()
    if ext in ("html", "htm", "xhtml") or head.startswith(("<!doctype html", "<html")):
        return "html"
    if ext == "svg" or head.startswith("<svg") or (head.startswith("<?xml") and "<svg" in head):
        return "svg"
    if ext in ("csv", "tsv"):
        return "csv"
    return "text"


# --------------------------------------------------------------------------- #
# Office Open XML (docx/docm/xlsx/xlsm/pptx/pptm)
# --------------------------------------------------------------------------- #

REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
CT_NS = "http://schemas.openxmlformats.org/package/2006/content-types"

VBA_PART = re.compile(r"(^|/)(vbaProject\.bin|vbaData\.xml|vbaProjectSignature\w*\.bin)$", re.I)
ACTIVE_DIRS = re.compile(r"^(word|xl|ppt)/(activeX|embeddings|macrosheets|dialogsheets)/", re.I)
DDE_INSTR = re.compile(rb"(<w:instrText\b[^>]*>)([^<]*)(</w:instrText>)")
DDE_SIMPLE = re.compile(rb'(<w:fldSimple\b[^>]*\bw:instr=")([^"]*)(")')
DDE_WORD = re.compile(rb"\bDDE(AUTO)?\b", re.I)
DDE_FORMULA = re.compile(rb"<f\b[^>]*>[^<]*\|[^<]*![^<]*</f>")

MACRO_CONTENT_TYPES = {
    "application/vnd.ms-word.document.macroEnabled.main+xml": "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
    "application/vnd.ms-word.template.macroEnabledTemplate.main+xml": "application/vnd.openxmlformats-officedocument.wordprocessingml.template.main+xml",
    "application/vnd.ms-excel.sheet.macroEnabled.main+xml": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
    "application/vnd.ms-excel.template.macroEnabled.main+xml": "application/vnd.openxmlformats-officedocument.spreadsheetml.template.main+xml",
    "application/vnd.ms-excel.addin.macroEnabled.main+xml": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
    "application/vnd.ms-powerpoint.presentation.macroEnabled.main+xml": "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml",
    "application/vnd.ms-powerpoint.slideshow.macroEnabled.main+xml": "application/vnd.openxmlformats-officedocument.presentationml.slideshow.main+xml",
    "application/vnd.ms-powerpoint.template.macroEnabled.main+xml": "application/vnd.openxmlformats-officedocument.presentationml.template.main+xml",
    "application/vnd.ms-powerpoint.addin.macroEnabled.main+xml": "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml",
}

MACRO_EXTENSIONS = {"docm": "docx", "dotm": "dotx", "xlsm": "xlsx", "xltm": "xltx", "xlam": "xlsx", "pptm": "pptx", "potm": "potx", "ppsm": "ppsx", "ppam": "pptx"}


def _read_zip(data: bytes):
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise Rejected("corrupt_archive", "The document archive is corrupt", "ooxml")
    with zf:
        infos = zf.infolist()
        if len(infos) > MAX_ZIP_ENTRIES:
            raise Rejected("zip_bomb", f"Too many archive entries ({len(infos)})", "ooxml")
        seen, parts, total = set(), [], 0
        for info in infos:
            name = info.filename
            if name.startswith("/") or "\\" in name or ".." in name.split("/"):
                raise Rejected("path_traversal", f"Unsafe path inside document: {name}", "ooxml")
            if name.lower() in seen:
                raise Rejected("duplicate_entry", f"Duplicate entry inside document: {name}", "ooxml")
            seen.add(name.lower())
            if info.flag_bits & 0x1:
                raise Rejected("encrypted_document", "Password-protected documents can't be inspected", "ooxml")
            with zf.open(info) as fh:
                content = fh.read(MAX_ZIP_TOTAL_BYTES - total + 1)
            total += len(content)
            if total > MAX_ZIP_TOTAL_BYTES:
                raise Rejected("zip_bomb", "Document expands beyond the size limit (possible zip bomb)", "ooxml")
            if info.compress_size and len(content) > 1_000_000 and len(content) / info.compress_size > MAX_ZIP_RATIO:
                raise Rejected("zip_bomb", f"Suspicious compression ratio in {name} (possible zip bomb)", "ooxml")
            if EICAR_SIGNATURE in content:
                raise Rejected("malware_signature", f"Malware test signature found inside {name}", "ooxml")
            parts.append((info, content))
    return parts


def _xml_root(content: bytes, name: str):
    if b"<!DOCTYPE" in content or b"<!ENTITY" in content:
        raise Rejected("xml_dtd", f"DTD declarations are not allowed in {name}", "ooxml")
    try:
        return ET.fromstring(content)
    except ET.ParseError:
        raise Rejected("malformed_document", f"Malformed XML in {name}", "ooxml")


def _rels_base(rels_name: str) -> str:
    return dirname(dirname(rels_name))


def sanitize_ooxml(data: bytes, name: str, report: Report):
    parts = _read_zip(data)
    removed = set()
    for info, _ in parts:
        n = info.filename
        if VBA_PART.search(n):
            report.threat("vba_macro", "high", "VBA macro project removed", n)
            removed.add(n.lower())
        elif ACTIVE_DIRS.match(n):
            folder = ACTIVE_DIRS.match(n).group(2).lower()
            if folder in ("macrosheets", "dialogsheets"):
                report.threat("xlm_macro", "high", "Excel 4.0 (XLM) macro sheet removed", n)
            elif folder == "activex":
                report.threat("activex_control", "high", "ActiveX control removed", n)
            else:
                report.threat("embedded_object", "medium", "Embedded OLE object removed", n)
            removed.add(n.lower())

    out_parts = []
    for info, content in parts:
        n = info.filename
        if n.lower() in removed:
            continue
        lower = n.lower()
        if lower.endswith(".rels"):
            content = _clean_rels(content, n, removed, report)
        elif lower == "[content_types].xml":
            content = _clean_content_types(content, removed, report)
        elif lower.endswith(".xml"):
            if b"<!DOCTYPE" in content or b"<!ENTITY" in content:
                raise Rejected("xml_dtd", f"DTD declarations are not allowed in {n}", "ooxml")
            content = _strip_dde(content, n, report)
        out_parts.append((info, content))

    if not any(i.filename == "[Content_Types].xml" for i, _ in out_parts):
        raise Rejected("malformed_document", "Missing [Content_Types].xml", "ooxml")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zo:
        for info, content in sorted(out_parts, key=lambda p: p[0].filename != "[Content_Types].xml"):
            zi = zipfile.ZipInfo(info.filename, date_time=info.date_time)
            zi.compress_type = zipfile.ZIP_DEFLATED
            zo.writestr(zi, content)

    ext = _extension(name)
    out_name = name
    if ext in MACRO_EXTENSIONS:
        out_name = name[: -len(ext)] + MACRO_EXTENSIONS[ext]
        report.note(f"Saved as .{MACRO_EXTENSIONS[ext]} because the document no longer contains macros")
    return buf.getvalue(), out_name


def _clean_rels(content: bytes, rels_name: str, removed: set, report: Report) -> bytes:
    root = _xml_root(content, rels_name)
    base = _rels_base(rels_name)
    changed = False
    for rel in list(root):
        target = rel.get("Target", "")
        rel_type = rel.get("Type", "")
        if rel.get("TargetMode") == "External":
            if rel_type.endswith("/hyperlink"):
                continue
            report.threat("external_reference", "high", "External reference removed (e.g. remote template or linked object)", target[:200])
            root.remove(rel)
            changed = True
            continue
        resolved = target.lstrip("/") if target.startswith("/") else normpath(pjoin(base, target))
        if resolved.lower() in removed or "vbaproject" in rel_type.lower():
            root.remove(rel)
            changed = True
    if not changed:
        return content
    ET.register_namespace("", REL_NS)
    return ET.tostring(root, encoding="UTF-8", xml_declaration=True)


def _clean_content_types(content: bytes, removed: set, report: Report) -> bytes:
    root = _xml_root(content, "[Content_Types].xml")
    changed = False
    for el in list(root):
        tag = el.tag.rsplit("}", 1)[-1]
        ctype = el.get("ContentType", "")
        if tag == "Override" and el.get("PartName", "").lstrip("/").lower() in removed:
            root.remove(el)
            changed = True
            continue
        if tag == "Default" and "vba" in ctype.lower():
            root.remove(el)
            changed = True
            continue
        if ctype in MACRO_CONTENT_TYPES:
            el.set("ContentType", MACRO_CONTENT_TYPES[ctype])
            changed = True
    if not changed:
        return content
    ET.register_namespace("", CT_NS)
    return ET.tostring(root, encoding="UTF-8", xml_declaration=True)


def _strip_dde(content: bytes, part: str, report: Report) -> bytes:
    def instr(m):
        if DDE_WORD.search(m.group(2)):
            report.threat("dde_field", "high", "DDE field (command execution) removed", part)
            return m.group(1) + m.group(3)
        return m.group(0)

    content = DDE_INSTR.sub(instr, content)
    content = DDE_SIMPLE.sub(instr, content)

    def formula(m):
        report.threat("dde_formula", "high", "DDE formula (command execution) removed", part)
        return b""

    return DDE_FORMULA.sub(formula, content)


# --------------------------------------------------------------------------- #
# PDF
# --------------------------------------------------------------------------- #

PDF_DELIM = rb"(?=[\s/<>\[\]()%{}]|$)"
PDF_ACTIVE = {
    b"JavaScript": ("pdf_javascript", "high", "Embedded JavaScript neutralized"),
    b"JS": ("pdf_javascript", "high", "Embedded JavaScript neutralized"),
    b"OpenAction": ("pdf_auto_action", "high", "Automatic open action neutralized"),
    b"AA": ("pdf_auto_action", "high", "Additional (event-triggered) actions neutralized"),
    b"Launch": ("pdf_launch", "high", "Launch action (runs external programs) neutralized"),
    b"EmbeddedFiles": ("pdf_embedded_file", "medium", "Embedded file attachment neutralized"),
    b"EmbeddedFile": ("pdf_embedded_file", "medium", "Embedded file attachment neutralized"),
    b"RichMedia": ("pdf_rich_media", "medium", "Rich media (Flash/video) content neutralized"),
    b"SubmitForm": ("pdf_form_action", "medium", "Form submission action neutralized"),
    b"ImportData": ("pdf_form_action", "medium", "Data import action neutralized"),
    b"GoToR": ("pdf_remote_goto", "medium", "Remote document jump neutralized"),
    b"GoToE": ("pdf_remote_goto", "medium", "Embedded document jump neutralized"),
    b"XFA": ("pdf_xfa", "medium", "XFA form (scriptable) neutralized"),
}
PDF_NAME_RE = re.compile(rb"/(" + b"|".join(sorted(PDF_ACTIVE, key=len, reverse=True)) + rb")" + PDF_DELIM)
PDF_ESCAPED_NAME = re.compile(rb"/[^\s/<>\[\]()%{}]*#[0-9A-Fa-f]{2}[^\s/<>\[\]()%{}]*")
PDF_JS_URI = re.compile(rb"javascript:", re.I)
PDF_ENCRYPT = re.compile(rb"/Encrypt" + PDF_DELIM)
PDF_STREAM = re.compile(rb"stream\r?\n")


def _pdf_scan_streams(data: bytes):
    inflated_total = 0
    pos = 0
    while True:
        m = PDF_STREAM.search(data, pos)
        if not m:
            return
        end = data.find(b"endstream", m.end())
        if end < 0:
            return
        pos = end + 9
        d = zlib.decompressobj()
        try:
            inflated = d.decompress(data[m.end():end], MAX_PDF_INFLATED_BYTES - inflated_total)
        except zlib.error:
            continue
        inflated_total += len(inflated)
        if inflated_total >= MAX_PDF_INFLATED_BYTES:
            raise Rejected("zip_bomb", "Compressed PDF streams expand beyond the size limit", "pdf")
        if EICAR_SIGNATURE in inflated:
            raise Rejected("malware_signature", "Malware test signature found inside a PDF stream", "pdf")
        if PDF_NAME_RE.search(inflated) or PDF_JS_URI.search(inflated):
            raise Rejected("pdf_compressed_active_content", "Active content is hidden inside a compressed object stream and can't be neutralized safely", "pdf")


def sanitize_pdf(data: bytes, name: str, report: Report):
    if PDF_ENCRYPT.search(data):
        raise Rejected("pdf_encrypted", "Encrypted PDFs can't be inspected", "pdf")
    for m in PDF_ESCAPED_NAME.finditer(data):
        decoded = re.sub(rb"#([0-9A-Fa-f]{2})", lambda h: bytes([int(h.group(1), 16)]), m.group()[1:])
        if decoded in PDF_ACTIVE:
            raise Rejected("pdf_obfuscation", f"Obfuscated PDF keyword /{decoded.decode('latin-1')} (hex-escaped name)", "pdf")
    _pdf_scan_streams(data)

    def neutralize(m):
        key = m.group(1)
        code, severity, description = PDF_ACTIVE[key]
        report.threat(code, severity, description, f"byte offset {m.start()}")
        return b"/" + b"X" * len(key)  # same length keeps the xref table valid

    out = PDF_NAME_RE.sub(neutralize, data)

    def js_uri(m):
        report.threat("pdf_javascript_uri", "high", "javascript: link neutralized", f"byte offset {m.start()}")
        return b"blocked-js:"

    out = PDF_JS_URI.sub(js_uri, out)
    if out != data:
        report.note("Active PDF keys were renamed in place so byte offsets (and the document structure) stay valid")
    return out, name


# --------------------------------------------------------------------------- #
# HTML
# --------------------------------------------------------------------------- #

HTML_ALLOWED = {
    "html", "head", "body", "title", "p", "div", "span", "h1", "h2", "h3", "h4", "h5", "h6", "ul", "ol", "li", "a", "b", "strong", "i", "em", "u",
    "br", "hr", "table", "thead", "tbody", "tfoot", "tr", "th", "td", "caption", "colgroup", "col", "img", "blockquote", "pre", "code", "section",
    "article", "header", "footer", "nav", "main", "aside", "small", "sub", "sup", "dl", "dt", "dd", "figure", "figcaption", "label", "mark", "s",
}
HTML_VOID = {"br", "hr", "img", "col", "meta", "link", "base", "embed", "input", "area", "source", "wbr", "param", "track"}
HTML_DROP = {
    "script": ("html_script", "high", "Script element removed"),
    "style": ("html_style", "low", "Style element removed"),
    "iframe": ("html_embedded_content", "medium", "Embedded frame removed"),
    "frame": ("html_embedded_content", "medium", "Embedded frame removed"),
    "frameset": ("html_embedded_content", "medium", "Embedded frame removed"),
    "object": ("html_embedded_content", "medium", "Embedded object removed"),
    "embed": ("html_embedded_content", "medium", "Embedded object removed"),
    "applet": ("html_embedded_content", "medium", "Embedded applet removed"),
    "template": ("html_template", "low", "Template element removed"),
    "noscript": ("html_template", "low", "Noscript element removed"),
    "svg": ("html_inline_svg", "medium", "Inline SVG removed"),
    "math": ("html_inline_svg", "low", "Inline MathML removed"),
    "link": ("html_external_resource", "low", "External resource link removed"),
    "base": ("html_base_override", "medium", "Base URL override removed"),
    "meta": (None, None, None),
    "canvas": ("html_embedded_content", "low", "Canvas element removed"),
}
HTML_FORM_TAGS = {"form", "input", "button", "select", "textarea", "option", "fieldset", "legend"}
HTML_ATTRS = {
    "*": {"title", "class", "id", "lang", "dir"},
    "a": {"href", "name", "target", "rel"},
    "img": {"src", "alt", "width", "height"},
    "td": {"colspan", "rowspan"},
    "th": {"colspan", "rowspan", "scope"},
    "ol": {"start", "type"},
    "col": {"span"},
    "colgroup": {"span"},
}
SAFE_URL_SCHEMES = {"http", "https", "mailto", "tel"}
SAFE_DATA_IMAGE = re.compile(r"^data:image/(png|jpeg|jpg|gif|webp);", re.I)


def url_is_safe(value: str, allow_data_image: bool = False) -> bool:
    compact = "".join(ch for ch in value if ch > " " and ord(ch) != 0x7F).strip()
    lowered = compact.lower()
    scheme_end = min((lowered.find(c) for c in ":/?#" if lowered.find(c) >= 0), default=-1)
    if scheme_end < 0 or lowered[scheme_end] != ":":
        return True
    scheme = lowered[:scheme_end]
    if scheme in SAFE_URL_SCHEMES:
        return True
    return allow_data_image and bool(SAFE_DATA_IMAGE.match(lowered))


class _HtmlSanitizer(HTMLParser):
    def __init__(self, report: Report):
        super().__init__(convert_charrefs=True)
        self.report = report
        self.out = []
        self.skip_tag = None
        self.skip_depth = 0

    def handle_decl(self, decl):
        if decl.lower().startswith("doctype html") and not self.skip_tag:
            self.out.append("<!DOCTYPE html>")

    def _attrs(self, tag, attrs):
        allowed = HTML_ATTRS["*"] | HTML_ATTRS.get(tag, set())
        kept = []
        for key, value in attrs:
            key = key.lower()
            value = value or ""
            if key.startswith("on"):
                self.report.threat("html_event_handler", "high", "Inline event handler removed", f"<{tag} {key}>")
                continue
            if key == "style":
                self.report.threat("html_style", "low", "Inline style removed", f"<{tag} style>")
                continue
            if key not in allowed:
                continue
            if key in ("href", "src") and not url_is_safe(value, allow_data_image=(tag == "img" and key == "src")):
                self.report.threat("html_script_url", "high", "Dangerous URL scheme removed (javascript:, data:, vbscript:)", f"<{tag} {key}>")
                continue
            kept.append((key, value))
        if tag == "a" and any(k == "target" for k, _ in kept):
            kept = [(k, v) for k, v in kept if k != "rel"] + [("rel", "noopener noreferrer")]
        return "".join(f' {k}="{html.escape(v, quote=True)}"' for k, v in kept)

    def handle_starttag(self, tag, attrs, self_closing=False):
        tag = tag.lower()
        if self.skip_tag:
            if tag == self.skip_tag and tag not in HTML_VOID:
                self.skip_depth += 1
            return
        if tag in HTML_DROP:
            code, severity, description = HTML_DROP[tag]
            if tag == "meta":
                if any(k.lower() == "http-equiv" and (v or "").lower() == "refresh" for k, v in attrs):
                    self.report.threat("html_meta_refresh", "medium", "Meta refresh redirect removed", "<meta http-equiv=refresh>")
            else:
                self.report.threat(code, severity, description, f"<{tag}>")
            if tag not in HTML_VOID and not self_closing:
                self.skip_tag, self.skip_depth = tag, 1
            return
        if tag in HTML_FORM_TAGS:
            self.report.threat("html_form_control", "low", "Form control removed (prevents credential phishing)", f"<{tag}>")
            return
        if tag not in HTML_ALLOWED:
            return
        self.out.append(f"<{tag}{self._attrs(tag, attrs)}>")

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs, self_closing=True)

    def handle_endtag(self, tag):
        tag = tag.lower()
        if self.skip_tag:
            if tag == self.skip_tag:
                self.skip_depth -= 1
                if self.skip_depth == 0:
                    self.skip_tag = None
            return
        if tag in HTML_ALLOWED and tag not in HTML_VOID:
            self.out.append(f"</{tag}>")

    def handle_data(self, data):
        if not self.skip_tag:
            self.out.append(html.escape(data, quote=False))

    def handle_comment(self, data):
        if "[if" in data.lower():
            self.report.threat("html_conditional_comment", "low", "Conditional comment removed", "<!--[if ...]-->")


def sanitize_html(data: bytes, name: str, report: Report):
    text, encoding = decode_text(data)
    text = map_character_anchors(text, report)
    parser = _HtmlSanitizer(report)
    parser.feed(text)
    parser.close()
    return encode_text("".join(parser.out), encoding), name


# --------------------------------------------------------------------------- #
# SVG
# --------------------------------------------------------------------------- #

SVG_NS = "http://www.w3.org/2000/svg"
XLINK_NS = "http://www.w3.org/1999/xlink"
SVG_REMOVE = {"script", "foreignObject", "iframe", "embed", "object", "handler", "listener"}
SVG_ANIMATION = {"set", "animate", "animateTransform", "animateMotion"}
SAFE_SVG_DATA = re.compile(r"^data:image/(png|jpeg|jpg|gif|webp);", re.I)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def sanitize_svg(data: bytes, name: str, report: Report):
    text, encoding = decode_text(data)
    if re.search(r"<!DOCTYPE|<!ENTITY", text, re.I):
        raise Rejected("xml_dtd", "DTD/entity declarations are not allowed in SVG (XXE / billion-laughs risk)", "svg")
    text = map_character_anchors(text, report)
    ET.register_namespace("", SVG_NS)
    ET.register_namespace("xlink", XLINK_NS)
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        raise Rejected("malformed_svg", "The SVG is not well-formed XML", "svg")
    if _local(root.tag) != "svg":
        raise Rejected("malformed_svg", "The root element is not <svg>", "svg")

    for parent in list(root.iter()):
        for child in list(parent):
            local = _local(child.tag)
            if local in SVG_REMOVE:
                code = "svg_script" if local == "script" else "svg_embedded_content"
                report.threat(code, "high" if local == "script" else "medium", f"<{local}> element removed", f"<{local}>")
                parent.remove(child)
            elif local in SVG_ANIMATION and _local(child.get("attributeName", "")).lower() in ("href",):
                report.threat("svg_animated_link", "high", "Animation that rewrites a link target removed", f"<{local}>")
                parent.remove(child)

    for el in root.iter():
        for key in list(el.attrib):
            local = _local(key).lower()
            value = el.attrib[key]
            if local.startswith("on"):
                report.threat("svg_event_handler", "high", "Inline event handler removed", f"<{_local(el.tag)} {local}>")
                del el.attrib[key]
            elif local == "href" and not value.strip().startswith("#") and not (url_is_safe(value) and not value.strip().lower().startswith("data:")) and not SAFE_SVG_DATA.match(value.strip()):
                report.threat("svg_script_url", "high", "Dangerous link target removed", f"<{_local(el.tag)} href>")
                del el.attrib[key]
            elif local == "style" and re.search(r"javascript:|expression\s*\(|@import", value, re.I):
                report.threat("svg_style", "medium", "Style with script or external import removed", f"<{_local(el.tag)} style>")
                del el.attrib[key]

    out = '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode")
    return encode_text(out, encoding), name


# --------------------------------------------------------------------------- #
# CSV and plain text
# --------------------------------------------------------------------------- #

NUMBER = re.compile(r"^[+-]?(\d+([.,]\d+)*|\d*[.,]\d+)([eE][+-]?\d+)?$")
FORMULA_PREFIX = ("=", "+", "-", "@", "\t", "\r")


def sanitize_csv(data: bytes, name: str, report: Report):
    text, encoding = decode_text(data)
    cleaned = map_character_anchors(text, report)
    newline = "\r\n" if "\r\n" in cleaned else "\n"
    try:
        dialect = csv.Sniffer().sniff(cleaned[:8192], delimiters=",;\t|")
        delimiter = dialect.delimiter
    except csv.Error:
        delimiter = "\t" if _extension(name) == "tsv" else ","
    rows = list(csv.reader(io.StringIO(cleaned, newline=""), delimiter=delimiter))
    formula_found = False
    for r, row in enumerate(rows):
        for c, cell in enumerate(row):
            if cell.startswith(FORMULA_PREFIX) and not NUMBER.match(cell.strip()):
                row[c] = "'" + cell
                formula_found = True
                report.threat("csv_formula_injection", "high", "Spreadsheet formula neutralized (CSV/formula injection)", f"row {r + 1}, column {c + 1}")
    if not formula_found:
        return (data if cleaned == text else encode_text(cleaned, encoding)), name
    buf = io.StringIO()
    csv.writer(buf, delimiter=delimiter, lineterminator=newline).writerows(rows)
    out = buf.getvalue()
    if not cleaned.endswith(("\n", "\r")) and out.endswith(newline):
        out = out[: -len(newline)]
    return encode_text(out, encoding), name


def sanitize_text(data: bytes, name: str, report: Report):
    text, encoding = decode_text(data)
    cleaned = map_character_anchors(text, report)
    return (data if cleaned == text else encode_text(cleaned, encoding)), name


# --------------------------------------------------------------------------- #
# Images
# --------------------------------------------------------------------------- #

def _trailing_payload(trailing: bytes, report: Report, fmt: str):
    if not trailing.strip(b"\x00"):
        return
    head = trailing.lstrip(b"\x00")[:8]
    severity = "high" if head.startswith((b"PK", b"MZ", b"%PDF", b"<scr", b"<?ph", b"<htm", b"#!")) else "medium"
    report.threat("appended_payload", severity, f"Data hidden after the end of the {fmt} image removed (polyglot file)", f"{len(trailing)} bytes")


def sanitize_png(data: bytes, name: str, report: Report):
    pos = 8
    while pos + 12 <= len(data):
        length = int.from_bytes(data[pos:pos + 4], "big")
        chunk_type = data[pos + 4:pos + 8]
        end = pos + 12 + length
        if end > len(data):
            break
        if chunk_type == b"IEND":
            _trailing_payload(data[end:], report, "PNG")
            return data[:end], name
        pos = end
    raise Rejected("corrupt_image", "The PNG image is truncated or corrupt", "png")


def sanitize_jpeg(data: bytes, name: str, report: Report):
    end = data.rfind(b"\xff\xd9")
    if end < 0:
        raise Rejected("corrupt_image", "The JPEG image is truncated or corrupt", "jpeg")
    _trailing_payload(data[end + 2:], report, "JPEG")
    return data[:end + 2], name


def sanitize_gif(data: bytes, name: str, report: Report):
    report.note("GIF images are passed through unchanged after signature checks")
    return data, name


HANDLERS = {
    "ooxml": sanitize_ooxml,
    "pdf": sanitize_pdf,
    "html": sanitize_html,
    "svg": sanitize_svg,
    "csv": sanitize_csv,
    "text": sanitize_text,
    "png": sanitize_png,
    "jpeg": sanitize_jpeg,
    "gif": sanitize_gif,
}


def _run(data: bytes, name: str, report: Report):
    if len(data) > MAX_INPUT_BYTES:
        raise Rejected("too_large", f"Files larger than {MAX_INPUT_BYTES // (1024 * 1024)} MB are not accepted")
    if not data:
        raise Rejected("empty_file", "The file is empty")
    if EICAR_SIGNATURE in data:
        raise Rejected("malware_signature", "Matches the EICAR anti-malware test signature")
    kind = detect_type(data, name)
    output, out_name = HANDLERS[kind](data, name, report)
    return kind, output, out_name


def sanitize(data: bytes, name: str) -> dict:
    """Sanitize one file. Raises Rejected if the file must not be released at all."""
    report = Report()
    kind, output, out_name = _run(data, name, report)

    # Independent second pass over the output: it must come back completely clean.
    recheck = Report()
    try:
        kind2, output2, _ = _run(output, out_name, recheck)
    except Rejected as e:
        raise Rejected("verification_failed", f"Sanitized output failed re-inspection: {e.message}", kind)
    residual = [t["code"] for t in recheck.threats.values()]
    if residual or kind2 != kind:
        raise Rejected("verification_failed", f"Sanitized output still contains: {', '.join(residual) or 'a different file type'}", kind)

    return {
        "detected_type": kind,
        "verdict": "sanitized" if report.has_findings() else "clean",
        "output": output,
        "output_name": out_name,
        "threats": sorted(report.threats.values(), key=lambda t: ("high", "medium", "low").index(t["severity"])),
        "anchors": report.anchors,
        "anchor_count": report.anchor_count,
        "notes": report.notes,
        "verification": {"method": "independent re-scan of sanitized output", "passed": True, "residual_findings": []},
    }
