'''Generates list of open alerts with resource, policy, and tags'''
import os
import argparse
import csv
from prismacloud.api import pc_api

# Settings for Prisma Cloud Compute Edition

settings = {
    "url":      os.environ.get('PC_URL'),
    "identity": os.environ.get('PC_IDENTITY'),
    "secret":   os.environ.get('PC_SECRET')
}

# Argumants

parser = argparse.ArgumentParser()
parser.add_argument(
    '-fsn',
    '--standardname',
    type=str,
    help='(Optional) - Filter - Standard Name.')
parser.add_argument(
    '-fas',
    '--alertstatus',
    type=str,
    choices=['open', 'resolved', 'snoozed', 'dismissed'],
    help='(Optional) - Filter - Alert Status.')
parser.add_argument(
    '-fpt',
    '--policytype',
    type=str,
    help='(Optional) - Filter - Policy Type.')
parser.add_argument(
    '-fpn',
    '--policyname',
    type=str,
    help='(Optional) - Filter - Policy Name.')
parser.add_argument(
    '-tr',
    '--timerange',
    type=int,
    default=30,
    help='(Optional) - Time Range in days (default 30).')
args = parser.parse_args()

# Initialize Connection

pc_api.configure(settings)

# Helpers


def get_alerts():
    '''Apply filters to alert query and return results'''
    alerts_filter = {}
    alerts_filter['filters'] = []
    alerts_filter['limit'] = 1000
    alerts_filter['offset'] = 0
    alerts_filter['sortBy'] = ['id:asc']
    alerts_filter['timeRange'] = {}
    alerts_filter['timeRange']['type'] = 'relative'
    alerts_filter['timeRange']['value'] = {}
    alerts_filter['timeRange']['value']['unit'] = 'day'
    alerts_filter['timeRange']['value']['amount'] = args.timerange
    if args.alertstatus is not None:
        temp_filter = {}
        temp_filter['name'] = 'alert.status'
        temp_filter['operator'] = '='
        temp_filter['value'] = args.alertstatus
        alerts_filter['filters'].append(temp_filter)
    if args.policytype is not None:
        temp_filter = {}
        temp_filter['name'] = 'policy.type'
        temp_filter['operator'] = '='
        temp_filter['value'] = args.policytype
        alerts_filter['filters'].append(temp_filter)
    if args.policyname is not None:
        temp_filter = {}
        temp_filter['name'] = 'policy.name'
        temp_filter['operator'] = '='
        temp_filter['value'] = args.policyname
        alerts_filter['filters'].append(temp_filter)
    print('API - Getting the Alerts list ...', end='')
    alerts_list = pc_api.alert_v2_list_read(body_params=alerts_filter)
    print(' done.')
    return alerts_list


def get_policies():
    '''Get all policies and filter out ones that match specific standard'''
    policies_to_match = {}
    print('API - Getting the Policies list ...', end='')
    policies_list = pc_api.policy_v2_list_read()
    print(' done.')
    if args.standardname is not None:
        standard = args.standardname
        for policy in policies_list:
            if 'complianceMetadata' in policy:
                if any(d['standardName'] == standard for d in policy['complianceMetadata']):
                    policies_to_match[policy['policyId']] = policy['name']
    else:
        for policy in policies_list:
            policies_to_match[policy['policyId']] = policy['name']
    return policies_to_match


def filter_alerts(alerts_list, policies_list):
    '''Return redacted list of alerts matching policies included in specified standard'''
    redacted_alerts = []
    for alert in alerts_list:
        if alert['policyId'] in policies_list.keys():
            alert['policyName'] = policies_list[alert['policyId']]
            redacted_alerts.append(alert)
    return redacted_alerts


def get_resources(alerts_list):
    tagged_alerts = []
    alert_row = ['Alert Id', 'Policy Name', 'Resource Name',
                 'Resource URL', 'Cloud Account', 'Resource Tags']
    tagged_alerts.append(alert_row)
    for alert in alerts_list:
        alert_row = []
        payload = {
            "rrn": alert['resource']['rrn'],
        }
        resource = pc_api.resource_read(payload)
        alert_row = [alert['id'], alert['policyName'], alert['resource']['name'],
                     alert['resource']['url'], alert['resource']['account'], resource['tags']]
        tagged_alerts.append(alert_row)
    return tagged_alerts


def main():
    '''Main Program Control'''
    policies_list = get_policies()
    alerts_list = get_alerts()
    tagged_alerts = []
    if len(alerts_list) > 0 and len(policies_list) > 0:
        alerts_list = filter_alerts(alerts_list, policies_list)
        if len(alerts_list) > 0:
            tagged_alerts = get_resources(alerts_list)
        else:
            print('No matching alerts')
    if len(tagged_alerts) > 0:
        with open("out.csv", "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerows(tagged_alerts)


if __name__ == "__main__":
    main()
