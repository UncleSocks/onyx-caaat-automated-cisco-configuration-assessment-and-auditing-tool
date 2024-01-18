from pprint import pprint

def generate_report(cis_check, level, compliant, current_configuration):
    current_check = {'CIS Check':cis_check, 'Level':level, 'Compliant':compliant, 'Current Configuration':current_configuration}
    return current_check

def report_cli_output(report_output):
    for report in report_output:
        print(report)

