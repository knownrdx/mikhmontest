import io
from xhtml2pdf import pisa


def html_to_pdf_bytes(html: str) -> io.BytesIO:
    pdf_io = io.BytesIO()
    pisa.CreatePDF(io.BytesIO(html.encode('UTF-8')), dest=pdf_io)
    pdf_io.seek(0)
    return pdf_io
