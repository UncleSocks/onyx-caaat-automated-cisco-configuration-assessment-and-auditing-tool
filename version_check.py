import re
from ssh_module import ssh_send


def ios_version_check(connection):
    command = "show running-config | include version"
    command_output = ssh_send(connection, command)

    regex_pattern_ios_version_search = re.search(r'version\s+(?P<version>15|17)\S*(?=\n|\Z)', command_output)

    if regex_pattern_ios_version_search:
        version = regex_pattern_ios_version_search.group('version')
        if version == "15":
            ios_version = 15
        else:
            ios_version = 17
    
    return ios_version
    