import os

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    PageBreak
)

from reportlab.lib.styles import (
    getSampleStyleSheet
)

class PDFReportGenerator:

    def generate(
        self,
        findings,
        target,
        output_dir
    ):

        file_path = os.path.join(
            output_dir,
            "report.pdf"
        )

        doc = SimpleDocTemplate(
            file_path
        )

        styles = (
            getSampleStyleSheet()
        )

        elements = []

        elements.append(
            Paragraph(
                "Security Misconfiguration Report",
                styles["Title"]
            )
        )

        elements.append(
            Paragraph(
                f"Target: {target}",
                styles["Normal"]
            )
        )

        elements.append(
            Spacer(1, 20)
        )

        for finding in findings:

            elements.append(
                Paragraph(
                    finding["title"],
                    styles["Heading2"]
                )
            )

            elements.append(
                Paragraph(
                    f"Severity: "
                    f"{finding['severity']}",
                    styles["Normal"]
                )
            )

            elements.append(
                Paragraph(
                    f"Affected URL: "
                    f"{finding['affected_url']}",
                    styles["Normal"]
                )
            )

            elements.append(
                Paragraph(
                    f"Description: "
                    f"{finding['description']}",
                    styles["Normal"]
                )
            )

            elements.append(
                Paragraph(
                    f"Impact: "
                    f"{finding['impact']}",
                    styles["Normal"]
                )
            )

            elements.append(
                Paragraph(
                    f"Recommendation: "
                    f"{finding['recommendation']}",
                    styles["Normal"]
                )
            )

            elements.append(
                Paragraph(
                    f"Evidence: "
                    f"{finding['evidence']}",
                    styles["Normal"]
                )
            )

            elements.append(
                Spacer(1, 15)
            )

        doc.build(elements)

        return file_path
