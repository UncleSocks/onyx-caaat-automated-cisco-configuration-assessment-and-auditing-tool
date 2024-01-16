

def generate_report(cis_check, level, compliant, current_configuration):
    current_check = {'CIS Check':cis_check, 'Level':level, 'Compliant':compliant, 'Current Configuration':current_configuration}
    return current_check

def get_report(report_output):
    for output in report_output:
        print(output)