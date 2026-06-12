import os
from collections import Counter

class HTMLReportGenerator:

    def generate(self, findings, target, output_dir):

        severity_count = Counter(
            [f["severity"] for f in findings]
        )

        html = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">

<title>MisconfigHunter Report</title>

<style>

body {{
    font-family: Arial;
    margin: 40px;
}}

h1 {{
    color: #2c3e50;
}}

table {{
    width: 100%;
    border-collapse: collapse;
}}

th, td {{
    border: 1px solid #ddd;
    padding: 10px;
}}

th {{
    background: #f4f4f4;
}}

.finding {{
    margin-top: 20px;
    border: 1px solid #ddd;
    padding: 15px;
}}

</style>

</head>

<body>

<h1>Security Misconfiguration Report</h1>

<h3>Target: {target}</h3>

<h2>Executive Summary</h2>

<table>

<tr>
<th>Severity</th>
<th>Count</th>
</tr>

<tr>
<td>Critical</td>
<td>{severity_count.get("Critical",0)}</td>
</tr>

<tr>
<td>High</td>
<td>{severity_count.get("High",0)}</td>
</tr>

<tr>
<td>Medium</td>
<td>{severity_count.get("Medium",0)}</td>
</tr>

<tr>
<td>Low</td>
<td>{severity_count.get("Low",0)}</td>
</tr>

<tr>
<td>Info</td>
<td>{severity_count.get("Info",0)}</td>
</tr>

</table>

<h2>Findings</h2>
"""

        for finding in findings:

            html += f"""
<div class="finding">

<h3>{finding['title']}</h3>

<p><b>Severity:</b> {finding['severity']}</p>

<p><b>Affected URL:</b>
{finding['affected_url']}</p>

<p><b>Description:</b>
{finding['description']}</p>

<p><b>Impact:</b>
{finding['impact']}</p>

<p><b>Recommendation:</b>
{finding['recommendation']}</p>

<p><b>Evidence:</b>
{finding['evidence']}</p>

</div>
"""

        html += """
</body>
</html>
"""

        file_path = os.path.join(
            output_dir,
            "report.html"
        )

        with open(
            file_path,
            "w",
            encoding="utf-8"
        ) as f:

            f.write(html)

        return file_path
