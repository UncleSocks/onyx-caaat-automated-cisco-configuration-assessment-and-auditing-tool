

def score_compute(parsed_report_output):

    compliance_score_dict = {'Passed Management Plane Checks':0, 'Failed Management Plane Checks':0,
                               'NA Management Plane Checks':0, 'Passed Control Plane Checks':0,
                               'Failed Control Plane Checks':0, 'NA Control Plane Checks':0,
                               'Passed Data Plane Checks':0, 'Failed Data Plane Checks':0, 'NA Data Plane Checks':0, 
                               'Total Passed Checks':0, 'Total Failed Checks':0, 'Total NA Checks':0,
                               'Total Checks':0}

    for management_plane_check in parsed_report_output['Management Plane Checks']:

        if management_plane_check['Compliant'] == True:
            compliance_score_dict['Passed Management Plane Checks'] += 1
        elif management_plane_check['Compliant'] == False:
            compliance_score_dict['Failed Management Plane Checks'] += 1
        else:
            compliance_score_dict['NA Management Plane Checks'] += 1

    for control_plane_check in parsed_report_output['Control Plane Checks']:

        if control_plane_check['Compliant'] == True:
            compliance_score_dict['Passed Control Plane Checks'] += 1
        elif control_plane_check['Compliant'] == False:
            compliance_score_dict['Failed Control Plane Checks'] += 1
        else:
            compliance_score_dict['NA Control Plane Checks'] += 1

    for data_plane_check in parsed_report_output['Data Plane Checks']:

        if data_plane_check['Compliant'] == True:
            compliance_score_dict['Passed Data Plane Checks'] += 1
        elif data_plane_check['Compliant'] == False:
            compliance_score_dict['Failed Data Plane Checks'] += 1
        else:
            compliance_score_dict['NA Data Plane Checks'] += 1
    
    compliance_score_dict['Total Passed Checks'] = compliance_score_dict['Passed Management Plane Checks'] + compliance_score_dict['Passed Control Plane Checks'] + compliance_score_dict['Passed Data Plane Checks']
    compliance_score_dict['Total Failed Checks'] = compliance_score_dict['Failed Management Plane Checks'] + compliance_score_dict['Failed Control Plane Checks'] + compliance_score_dict['Failed Data Plane Checks']
    compliance_score_dict['Total NA Checks'] = compliance_score_dict['NA Management Plane Checks'] + compliance_score_dict['NA Control Plane Checks'] + compliance_score_dict['NA Data Plane Checks']

    compliance_score_dict['Total Checks'] = compliance_score_dict['Total Passed Checks'] + compliance_score_dict['Total Failed Checks']

    return compliance_score_dict