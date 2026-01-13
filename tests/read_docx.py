"""Read and print DOCX content."""
import sys
from docx import Document

def read_docx(path):
    doc = Document(path)
    for para in doc.paragraphs:
        if para.text.strip():
            print(para.text)
            print()

if __name__ == '__main__':
    read_docx(sys.argv[1])
