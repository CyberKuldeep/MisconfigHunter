import json
import os

class JSONReportGenerator:

    def generate(
        self,
        findings,
        target,
        output_dir
    ):

        report = {
            "target": target,
            "total_findings": len(findings),
            "findings": findings
        }

        file_path = os.path.join(
            output_dir,
            "findings.json"
        )

        with open(
            file_path,
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                report,
                f,
                indent=4
            )

        return file_path
