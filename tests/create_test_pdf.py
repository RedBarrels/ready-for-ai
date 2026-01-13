"""Create a test PDF document with various PII for testing."""

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch


def create_test_pdf():
    c = canvas.Canvas('test_document.pdf', pagesize=letter)
    width, height = letter

    # Title
    c.setFont("Helvetica-Bold", 16)
    c.drawString(1 * inch, height - 1 * inch, "Project Phoenix Status Report")

    # Content
    c.setFont("Helvetica", 11)
    y = height - 1.5 * inch

    lines = [
        "From: John Smith (john.smith@acmecorp.com)",
        "To: Sarah Johnson (sarah.j@globex.io)",
        "CC: @mike_wilson, @jennifer_lee",
        "Date: January 10, 2024",
        "",
        "Executive Summary",
        "This report summarizes the progress of Project Phoenix for Acme Corporation.",
        "Our team lead, Michael Chen, has been coordinating with the client",
        "representative Jennifer Williams at GlobalTech Industries.",
        "",
        "Team Members:",
        "- John Smith - Project Manager (555-123-4567)",
        "- Sarah Johnson - Lead Developer",
        "- Mike Wilson - Backend Engineer (@mike_wilson)",
        "- Jennifer Lee - QA Lead (jennifer.lee@acmecorp.com)",
        "- Robert Brown - DevOps (robert.b@acmecorp.com)",
        "",
        "Client Information:",
        "Client: GlobalTech Industries",
        "Contact: Jennifer Williams",
        "Email: j.williams@globaltech.com",
        "Phone: 555-987-6543",
        "Address: 123 Main Street, San Francisco, CA 94102",
        "",
        "Technical Details:",
        "Production server IP: 192.168.1.100",
        "API documentation: https://api.acmecorp.com/docs",
        "Support: support@acmecorp.com or 1-800-555-0199",
        "",
        "Confidential Notes:",
        "Employee SSN for payroll: 123-45-6789 (John Smith)",
        "Corporate card: 4111-1111-1111-1234",
        "Internal Slack: #project-phoenix-team",
        "",
        "Best regards,",
        "John Smith",
        "Project Manager, Engineering Team",
        "Acme Corporation",
    ]

    for line in lines:
        c.drawString(1 * inch, y, line)
        y -= 0.25 * inch
        if y < 1 * inch:
            c.showPage()
            c.setFont("Helvetica", 11)
            y = height - 1 * inch

    c.save()
    print('Created test_document.pdf')


if __name__ == '__main__':
    create_test_pdf()
