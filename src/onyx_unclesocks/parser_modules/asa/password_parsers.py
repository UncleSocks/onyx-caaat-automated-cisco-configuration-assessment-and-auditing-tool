import re
from ssh import ssh_send
from report_modules.main_report import generate_report

def compliance_check_password_policy(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)

    current_configuration = {'Lifetime':None, 'Minimum Changes':None, 'Minimum Uppercase':None,
                             'Minimum Lowercase':None, 'Minimum Numeric':None, 'Minimum Special':None,
                             'Minimum Length':None}

    if not command_output:
        compliant = False
        current_configuration = None
    else:
        non_compliant_password_policy_counter = 0
        password_lifetime_search = re.search(r'password-policy\s+lifetime\s+(?P<lifetime>\d+)(?=\n|$)', command_output)
        if not password_lifetime_search:
            non_compliant_password_policy_counter += 1
        else:
            lifetime = int(password_lifetime_search.group('lifetime'))
            if lifetime > 365:
                non_compliant_password_policy_counter += 1
                current_configuration['Lifetime'] = lifetime
            else:
                current_configuration['Lifetime'] = lifetime

        password_changes_search = re.search(r'password-policy\s+minimum-changes\s+(?P<changes>\d+)(?=\n|$)', command_output)
        if not password_changes_search:
            non_compliant_password_policy_counter += 1
        else:
            minimum_changes = int(password_changes_search.group('changes'))
            if minimum_changes < 14:
                non_compliant_password_policy_counter += 1
                current_configuration['Minimum Changes'] = minimum_changes
            else:
                current_configuration['Minimum Changes'] = minimum_changes

        password_uppercase_search = re.search(r'password-policy\s+minimum-uppercase\s+(?P<uppercase>\d+)(?=\n|$)', command_output)
        if not password_uppercase_search:
            non_compliant_password_policy_counter += 1
        else:
            uppercase = int(password_uppercase_search.group('uppercase'))
            if uppercase < 1:
                non_compliant_password_policy_counter += 1
                current_configuration['Minimum Uppercase'] = uppercase
            else:
                current_configuration['Minimum Uppercase'] = uppercase

        password_lowercase_search = re.search(r'password-policy\s+minimum-lowercase\s+(?P<lowercase>\d+)(?=\n|$)', command_output)
        if not password_lowercase_search:
            non_compliant_password_policy_counter += 1
        else:
            lowercase = int(password_lowercase_search.group('lowercase'))
            if lowercase < 1:
                non_compliant_password_policy_counter += 1
                current_configuration['Minimum Lowercase'] = lowercase
            else:
                current_configuration['Minimum Lowercase'] = lowercase

        password_numeric_search = re.search(r'password-policy\s+minimum-numeric\s+(?P<numeric>\d+)(?=\n|$)', command_output)
        if not password_numeric_search:
            non_compliant_password_policy_counter += 1
        else:
            numeric = int(password_numeric_search.group('numeric'))
            if numeric < 1:
                non_compliant_password_policy_counter += 1
                current_configuration['Minimum Numeric'] = numeric
            else:
                current_configuration['Minimum Numeric'] = numeric

        password_special_search = re.search(r'password-policy\s+minimum-special\s+(?P<special>\d+)(?=\n|$)', command_output)
        if not password_special_search:
            non_compliant_password_policy_counter += 1
        else:
            special = int(password_special_search.group('special'))
            if special < 1:
                non_compliant_password_policy_counter += 1
                current_configuration['Minimum Special'] = special
            else:
                current_configuration['Minimum Special'] = special

        password_length_search = re.search(r'password-policy\s+minimum-length\s+(?P<length>\d+)(?=\n|$)', command_output)
        if not password_length_search:
            non_compliant_password_policy_counter += 1
        else:
            length = int(password_length_search.group('length'))
            if length < 1:
                non_compliant_password_policy_counter += 1
                current_configuration['Minimum Length'] = length
            else:
                current_configuration['Minimum Length'] = length

        compliant = non_compliant_password_policy_counter == 0

    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


           
