"""Seed inputs for the parser fuzzer (crates/kokino-fuzz/seeds/).

Small, valid examples of the formats that have no small fixture in
tests/fixtures: documents (ZIP, Office Open XML, OpenDocument, GZIP, PDF),
thumbnail-size pictures, browser history databases and LZXPRESS buffers.
All content is invented. Needs Pillow for the pictures.

    python scripts/make_fuzz_seeds.py
"""
import gzip
import io
import os
import sqlite3
import struct
import zipfile
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(ROOT, "tests", "fixtures")
OUT = os.path.join(ROOT, "crates", "kokino-fuzz", "seeds")


def put(sub, name, data):
    d = os.path.join(OUT, sub)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name), "wb") as f:
        f.write(data)


def zipped(files, method=zipfile.ZIP_DEFLATED):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", method) as z:
        for n, d in files:
            z.writestr(n, d)
    return b.getvalue()


def docs():
    put("doc", "plain.zip", zipped([("notes.txt", "meeting at the lab, invoice 4471\n" * 3)]))
    put("doc", "stored.zip", zipped([("a.txt", "stored entry text")], zipfile.ZIP_STORED))
    inner = zipped([("deep.txt", "nested archive text")])
    put("doc", "nested.zip", zipped([("inner.zip", inner), ("top.txt", "top level")]))
    ct = '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>'
    put("doc", "min.docx", zipped([
        ("[Content_Types].xml", ct),
        ("word/document.xml", '<w:document xmlns:w="w"><w:body><w:p><w:r><w:t>Quarterly report draft</w:t></w:r></w:p>'
                              '<w:p><w:r><w:t xml:space="preserve">second &amp; third</w:t></w:r></w:p></w:body></w:document>'),
        ("docProps/core.xml", '<cp:coreProperties xmlns:cp="c" xmlns:dc="d"><dc:creator>alice</dc:creator><dc:title>Draft</dc:title></cp:coreProperties>'),
    ]))
    put("doc", "min.xlsx", zipped([
        ("[Content_Types].xml", ct),
        ("xl/sharedStrings.xml", '<sst xmlns="x"><si><t>Account</t></si><si><t>Balance 1200</t></si></sst>'),
        ("xl/worksheets/sheet1.xml", '<worksheet><sheetData><row><c t="s"><v>0</v></c><c t="s"><v>1</v></c></row></sheetData></worksheet>'),
    ]))
    put("doc", "min.pptx", zipped([
        ("[Content_Types].xml", ct),
        ("ppt/slides/slide1.xml", '<p:sld xmlns:p="p" xmlns:a="a"><a:t>Slide title</a:t><a:t>bullet one</a:t></p:sld>'),
    ]))
    put("doc", "min.odt", zipped([
        ("mimetype", "application/vnd.oasis.opendocument.text"),
        ("content.xml", '<office:document-content xmlns:office="o" xmlns:text="t"><office:body><office:text>'
                        '<text:p>OpenDocument paragraph</text:p><text:h>Heading</text:h></office:text></office:body></office:document-content>'),
        ("meta.xml", '<office:document-meta xmlns:office="o" xmlns:meta="m"><meta:initial-creator>bob</meta:initial-creator></office:document-meta>'),
    ], zipfile.ZIP_STORED))
    put("doc", "text.gz", gzip.compress(b"compressed log line 10.0.0.1\n" * 20))
    put("doc", "tar-like.gz", gzip.compress(zipped([("x.txt", "zip in gzip")])))

    def pdf(objs):
        out = b"%PDF-1.4\n"
        offs = []
        for i, o in enumerate(objs, 1):
            offs.append(len(out))
            out += b"%d 0 obj\n" % i + o + b"\nendobj\n"
        x = len(out)
        out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
        for o in offs:
            out += b"%010d 00000 n \n" % o
        out += b"trailer\n<< /Size %d /Root 1 0 R /Info 5 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, x)
        return out

    content = b"BT /F1 12 Tf 72 720 Td (Invoice total 1200 EUR) Tj T* [(Kern)-120(ed)] TJ ET"
    flate = zlib.compress(content)
    tounicode = zlib.compress(b"/CIDInit /ProcSet findresource begin 1 begincmap 1 beginbfchar <01> <0041> endbfchar endcmap end")
    put("doc", "text.pdf", pdf([
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /Contents 4 0 R /Resources << /Font << /F1 6 0 R >> >> >>",
        b"<< /Length %d /Filter /FlateDecode >>\nstream\n" % len(flate) + flate + b"\nendstream",
        b"<< /Title (Test document) /Author (alice) /Producer (fuzz seed) >>",
        b"<< /Type /Font /Subtype /Type0 /ToUnicode 7 0 R >>",
        b"<< /Length %d /Filter /FlateDecode >>\nstream\n" % len(tounicode) + tounicode + b"\nendstream",
    ]))
    put("doc", "plain.pdf", pdf([
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>",
        b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream",
        b"<< /Title (Plain) >>",
    ]))


def photos():
    from PIL import Image
    src = Image.open(os.path.join(FIX, "photo", "camera.jpg"))
    exif = src.info.get("exif", b"")
    small = src.resize((48, 32))
    b = io.BytesIO()
    small.save(b, "JPEG", quality=80, exif=exif)
    put("photo", "camera-small.jpg", b.getvalue())
    put("photo", "appended.jpg", b.getvalue() + zipped([("hidden.txt", "payload")]))
    b = io.BytesIO()
    small.save(b, "JPEG", quality=60, progressive=True)
    put("photo", "progressive.jpg", b.getvalue())
    b = io.BytesIO()
    small.convert("L").save(b, "JPEG", quality=90)
    put("photo", "gray.jpg", b.getvalue())
    b = io.BytesIO()
    small.save(b, "JPEG", quality=85, subsampling=0)
    put("photo", "444.jpg", b.getvalue())
    for mode, name in [("RGB", "rgb.png"), ("RGBA", "rgba.png"), ("L", "gray.png"), ("P", "pal.png")]:
        b = io.BytesIO()
        small.convert(mode).save(b, "PNG")
        put("photo", name, b.getvalue())
    for mode, name in [("RGB", "rgb.bmp"), ("L", "gray.bmp")]:
        b = io.BytesIO()
        small.convert(mode).save(b, "BMP")
        put("photo", name, b.getvalue())


def db(build):
    p = os.path.join(OUT, "tmp.sqlite")
    if os.path.exists(p):
        os.remove(p)
    c = sqlite3.connect(p)
    build(c)
    c.commit()
    c.close()
    data = open(p, "rb").read()
    os.remove(p)
    return data


def browsers():
    def chrome(c):
        c.executescript("""
        CREATE TABLE urls(id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR, visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER, hidden INTEGER);
        CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, from_visit INTEGER, transition INTEGER, visit_duration INTEGER);
        CREATE TABLE downloads(id INTEGER PRIMARY KEY, guid VARCHAR, current_path LONGVARCHAR, target_path LONGVARCHAR, start_time INTEGER, received_bytes INTEGER, total_bytes INTEGER, state INTEGER, danger_type INTEGER, interrupt_reason INTEGER, end_time INTEGER, opened INTEGER, referrer VARCHAR, tab_url VARCHAR, mime_type VARCHAR);
        CREATE TABLE downloads_url_chains(id INTEGER, chain_index INTEGER, url LONGVARCHAR);
        CREATE TABLE keyword_search_terms(keyword_id INTEGER, url_id INTEGER, term LONGVARCHAR, normalized_term LONGVARCHAR);
        INSERT INTO urls VALUES(1,'https://search.example.test/search?q=wipe+disk','wipe disk - Search',2,1,13350000000000000,0);
        INSERT INTO urls VALUES(2,'https://files.example.test/tool.zip','Download',1,0,13350000100000000,0);
        INSERT INTO visits VALUES(1,1,13350000000000000,0,805306369,0);
        INSERT INTO visits VALUES(2,2,13350000100000000,1,805306368,5000000);
        INSERT INTO downloads VALUES(1,'g-1','C:\\Users\\alice\\Downloads\\tool.zip','C:\\Users\\alice\\Downloads\\tool.zip',13350000100000000,1000,1000,1,0,0,13350000200000000,0,'','','application/zip');
        INSERT INTO downloads_url_chains VALUES(1,0,'https://files.example.test/tool.zip');
        INSERT INTO keyword_search_terms VALUES(2,1,'wipe disk','wipe disk');
        """)

    def firefox(c):
        c.executescript("""
        CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR, visit_count INTEGER, typed INTEGER, last_visit_date INTEGER, hidden INTEGER, frecency INTEGER);
        CREATE TABLE moz_historyvisits(id INTEGER PRIMARY KEY, from_visit INTEGER, place_id INTEGER, visit_date INTEGER, visit_type INTEGER, session INTEGER);
        CREATE TABLE moz_anno_attributes(id INTEGER PRIMARY KEY, name VARCHAR(32));
        CREATE TABLE moz_annos(id INTEGER PRIMARY KEY, place_id INTEGER, anno_attribute_id INTEGER, content LONGVARCHAR, flags INTEGER, expiration INTEGER, type INTEGER, dateAdded INTEGER, lastModified INTEGER);
        INSERT INTO moz_places VALUES(1,'https://www.example.test/?q=sdelete','sdelete',1,1,1700000000000000,0,100);
        INSERT INTO moz_places VALUES(2,'https://dl.example.test/sdelete.zip',NULL,1,0,1700000100000000,0,100);
        INSERT INTO moz_historyvisits VALUES(1,0,1,1700000000000000,2,0);
        INSERT INTO moz_historyvisits VALUES(2,1,2,1700000100000000,7,0);
        INSERT INTO moz_anno_attributes VALUES(1,'downloads/destinationFileURI');
        INSERT INTO moz_annos VALUES(1,2,1,'file:///C:/Users/alice/Downloads/sdelete.zip',0,4,3,1700000100000000,1700000100000000);
        """)

    put("browser", "chrome-History", db(chrome))
    put("browser", "firefox-places.sqlite", db(firefox))


def xpress():
    for n in ["text", "random", "long"]:
        raw = open(os.path.join(FIX, "win", "xpress-%s.raw" % n), "rb").read()
        comp = open(os.path.join(FIX, "win", "xpress-%s.xph" % n), "rb").read()
        put("xpress", n + ".bin", struct.pack("<I", len(raw)) + comp)


if __name__ == "__main__":
    docs()
    photos()
    browsers()
    xpress()
    for sub in sorted(os.listdir(OUT)):
        files = os.listdir(os.path.join(OUT, sub))
        print("%-8s %2d files, %d bytes" % (sub, len(files), sum(os.path.getsize(os.path.join(OUT, sub, f)) for f in files)))
