

def score_compute_ios15(report_output):

    management_plane_checks = report_output[0:31]
    control_plane_checks = report_output[31:60]
    data_plane_checks = report_output[60:80]

    compliant_score_counter = {'Passed Management Plane Checks':0, 'Failed Management Plane Checks':0,
                               'NA Management Plane Checks':0, 'Passed Control Plane Checks':0,
                               'Failed Control Plane Checks':0, 'NA Control Plane Checks':0,
                               'Passed Data Plane Checks':0, 'Failed Data Plane Checks':0, 'NA Data Plane Checks':0}

    for management_plane_check in management_plane_checks:

        if management_plane_check['Compliant'] == True:
            compliant_score_counter['Passed Management Plane Checks'] += 1
        elif management_plane_check['Compliant'] == False:
            compliant_score_counter['Failed Management Plane Checks'] += 1
        else:
            compliant_score_counter['NA Management Plane Checks'] += 1

    for control_plane_check in control_plane_checks:

        if control_plane_check['Compliant'] == True:
            compliant_score_counter['Passed Control Plane Checks'] += 1
        elif control_plane_check['Compliant'] == False:
            compliant_score_counter['Failed Control Plane Checks'] += 1
        else:
            compliant_score_counter['NA Control Plane Checks'] += 1

    for data_plane_check in data_plane_checks:

        if data_plane_check['Compliant'] == True:
            compliant_score_counter['Passed Data Plane Checks'] += 1
        elif data_plane_check['Compliant'] == False:
            compliant_score_counter['Failed Data Plane Checks'] += 1
        else:
            compliant_score_counter['NA Data Plane Checks'] += 1

    return compliant_score_counter