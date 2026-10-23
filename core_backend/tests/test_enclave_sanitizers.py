import io
import zipfile

import pytest

from ..enclave import sanitizers as s
from . import corpus


def codes(result):
    return {t["code"] for t in result["threats"]}


def rejected(data, name):
    with pytest.raises(s.Rejected) as e:
        s.sanitize(data, name)
    return e.value


class TestOfficeMacros:
    def test_docm_macros_removed_and_renamed(self):
        r = s.sanitize(corpus.docm(), "invoice.docm")
        assert r["verdict"] == "sanitized"
        assert r["output_name"] == "invoice.docx"
        assert {"vba_macro", "external_reference", "dde_field"} <= codes(r)
        z = zipfile.ZipFile(io.BytesIO(r["output"]))
        names = z.namelist()
        assert not any("vba" in n.lower() for n in names)
        ct = z.read("[Content_Types].xml").decode()
        assert "macroEnabled" not in ct and "vbaProject" not in ct and "vbaData" not in ct
        assert "wordprocessingml.document.main+xml" in ct
        rels = z.read("word/_rels/document.xml.rels").decode()
        assert "vbaProject" not in rels and "evil.example" not in rels
        assert "https://example.com/" in rels, "benign hyperlinks must be kept"
        doc = z.read("word/document.xml")
        assert b"DDEAUTO" not in doc and b"Quarterly report" in doc

    def test_xlsm_macrosheet_and_dde_formula(self):
        r = s.sanitize(corpus.xlsm(), "budget.xlsm")
        assert {"xlm_macro", "dde_formula"} <= codes(r)
        z = zipfile.ZipFile(io.BytesIO(r["output"]))
        assert not any("macrosheets" in n for n in z.namelist())
        sheet = z.read("xl/worksheets/sheet1.xml")
        assert b"cmd|" not in sheet and b"SUM(1,2)" in sheet
        assert r["output_name"] == "budget.xlsx"

    def test_clean_docx_is_clean(self):
        r = s.sanitize(corpus.docx_clean(), "clean.docx")
        assert r["verdict"] == "clean" and r["threats"] == []

    def test_zip_bomb_rejected(self):
        assert rejected(corpus.zip_bomb_docx(), "bomb.docx").code == "zip_bomb"

    def test_legacy_office_rejected(self):
        assert rejected(corpus.legacy_doc(), "report.doc").code == "legacy_office"

    def test_generic_zip_rejected(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("a.txt", "x")
        assert rejected(buf.getvalue(), "files.zip").code == "archive_unsupported"


class TestPdf:
    def test_active_content_neutralized_in_place(self):
        data = corpus.pdf_javascript()
        r = s.sanitize(data, "statement.pdf")
        assert {"pdf_javascript", "pdf_auto_action", "pdf_launch", "pdf_javascript_uri"} <= codes(r)
        out = r["output"]
        assert len(out) == len(data), "same-length rewrite keeps xref offsets valid"
        for token in (b"/JavaScript", b"/JS ", b"/OpenAction", b"/AA ", b"/Launch", b"javascript:"):
            assert token not in out
        assert out.index(b"xref") == data.index(b"xref")

    def test_clean_pdf(self):
        r = s.sanitize(corpus.pdf_clean(), "clean.pdf")
        assert r["verdict"] == "clean" and r["output"] == corpus.pdf_clean()

    def test_obfuscated_names_rejected(self):
        assert rejected(corpus.pdf_obfuscated(), "x.pdf").code == "pdf_obfuscation"

    def test_compressed_javascript_rejected(self):
        assert rejected(corpus.pdf_compressed_js(), "x.pdf").code == "pdf_compressed_active_content"


class TestMarkup:
    def test_html_scripts_and_handlers_removed(self):
        r = s.sanitize(corpus.HTML_ATTACK, "invoice.html")
        out = r["output"].decode()
        low = out.lower()
        for bad in ("<script", "steal(", "onload", "onerror", "javascript", "<iframe", "inside iframe", "<style", "http-equiv", "<form", "<input", "password"):
            assert bad not in low, bad
        assert "<h1>Invoice #42</h1>" in out and "&lt;not a tag&gt;" in out
        assert '<img src="x.png" alt="logo">' in out
        assert 'href="https://example.com/pay"' in out and 'rel="noopener noreferrer"' in out
        assert {"html_script", "html_event_handler", "html_script_url", "html_meta_refresh", "html_embedded_content", "html_form_control"} <= codes(r)

    def test_svg_scripts_removed(self):
        r = s.sanitize(corpus.SVG_ATTACK, "logo.svg")
        out = r["output"].decode().lower()
        assert "<script" not in out and "onload" not in out and "onclick" not in out and "javascript" not in out and "foreignobject" not in out
        assert "<rect" in out and 'href="#ok"' in out
        assert {"svg_script", "svg_event_handler", "svg_script_url", "svg_embedded_content"} <= codes(r)

    def test_svg_xxe_rejected(self):
        assert rejected(corpus.SVG_XXE, "x.svg").code == "xml_dtd"


class TestCsvAndText:
    def test_csv_formula_injection(self):
        r = s.sanitize(corpus.CSV_INJECTION, "contacts.csv")
        out = r["output"].decode()
        assert "Alice,-120,refund" in out, "negative numbers must not be altered"
        assert "'=HYPERLINK" in out and "'@SUM" in out and "'+cmd" in out
        threat = next(t for t in r["threats"] if t["code"] == "csv_formula_injection")
        assert threat["count"] == 3 and "row 3, column 2" in threat["locations"]

    def test_trojan_source_anchor_map(self):
        r = s.sanitize(corpus.TROJAN_SOURCE, "trojan_source.txt")
        out = r["output"].decode()
        assert "‮" not in out and "⁦" not in out and "⁩" not in out and "​" not in out
        assert "paypal.com" in out, "Cyrillic lookalike in a Latin word is mapped to ASCII"
        assert "Привіт, світ" in out, "genuine Cyrillic text is untouched"
        assert "\U0001F468‍\U0001F469‍\U0001F467" in out, "emoji joiners are kept"
        cats = {a["category"] for a in r["anchors"]}
        assert cats == {"bidi_control", "zero_width", "homoglyph"}
        rlo = next(a for a in r["anchors"] if a["codepoint"] == "U+202E")
        assert (rlo["line"], rlo["action"], rlo["name"]) == (2, "removed", "RIGHT-TO-LEFT OVERRIDE")
        homoglyph = next(a for a in r["anchors"] if a["category"] == "homoglyph")
        assert homoglyph["replacement"] == "a" and homoglyph["codepoint"] == "U+0430" and homoglyph["line"] == 4
        source = corpus.TROJAN_SOURCE.decode()
        for a in r["anchors"]:
            assert f"U+{ord(source[a['offset']]):04X}" == a["codepoint"], "anchor offsets point at the original character"

    def test_plain_text_clean_is_untouched(self):
        data = "Line one\nПривіт\n".encode()
        r = s.sanitize(data, "notes.txt")
        assert r["verdict"] == "clean" and r["output"] == data


class TestBinaryAndSignatures:
    def test_png_polyglot_trailer_stripped(self):
        r = s.sanitize(corpus.png_polyglot(), "photo.png")
        assert r["output"].endswith(b"IEND\xaeB`\x82") and len(r["output"]) == corpus.png_clean_length()
        t = next(t for t in r["threats"] if t["code"] == "appended_payload")
        assert t["severity"] == "high"

    def test_eicar_rejected(self):
        assert rejected(corpus.eicar_txt(), "eicar.txt").code == "malware_signature"

    def test_executable_disguised_as_pdf_rejected(self):
        assert rejected(corpus.executable(), "setup.exe.pdf").code == "executable"

    def test_dangerous_extension_rejected(self):
        assert rejected(b"WScript.Echo 1", "run.vbs").code == "dangerous_extension"

    def test_eicar_inside_office_document_rejected(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("[Content_Types].xml", "<Types/>")
            z.writestr("word/media/x.txt", corpus.EICAR)
        assert rejected(buf.getvalue(), "x.docx").code == "malware_signature"


class TestVerification:
    @pytest.mark.parametrize("name", ["invoice.docm", "budget.xlsm", "statement.pdf", "invoice.html", "logo.svg", "contacts.csv", "trojan_source.txt", "photo.png"])
    def test_output_passes_independent_rescan(self, name):
        r = s.sanitize(corpus.SAMPLES[name](), name)
        assert r["verification"]["passed"] is True
        again = s.sanitize(r["output"], r["output_name"])
        assert again["verdict"] == "clean" and again["threats"] == []
