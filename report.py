from pprint import pprint

def generate_report(cis_check, level, compliant, current_configuration):
    current_check = {'CIS Check':cis_check, 'Level':level, 'Compliant':compliant, 'Current Configuration':current_configuration}
    return current_check

def report_cli_output(report_output):
    pprint(report_output)

def report_html_output(report_output):
    html_report = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>ONYX: Cisco Another Automated Assessment Tool Report</title>
        </head>
        <body>
            <h1>CIS Report</h1>
            <table border="1">
                <tr>
                    <th>CIS Check</th>
                    <th>Level</th>
                    <th>Compliant</th>
                    <th>Current Configuration</th>
                </tr>
    """
    for output in report_output:
        html_report += f"""
            <tr>
                <td>{output['CIS Check']}</td>
                <td>{output['Level']}</td>
                <td>{output['Compliant']}</td>
                <td>{output['Current Configuration']}</td>
            </tr>
        """
    html_report += """
            </table>
        </body>
        </html>
    """
    with open('cis_checks_report.html', 'w') as f:
        f.write(html_report)