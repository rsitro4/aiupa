"""AWS IAM User Permission Auditor (aiupa)
Author: Rob Sitro
Company: Chainalysis
Email: rob.sitro@chainalysis.com
License: MIT
"""

import boto3
import argparse
import csv
import os
import json
from datetime import datetime

client = boto3.client('iam')
user_paginator = client.get_paginator('list_users')
attached_user_paginator = client.get_paginator('list_attached_user_policies')
group_paginator = client.get_paginator('list_groups_for_user')
group_policy_paginator = client.get_paginator('list_attached_group_policies') 
datetime_obj = datetime.now()
timestamp_string = datetime_obj.strftime("%d_%b_%Y_%H_%M_%S")
output = {}


def main():
    global output
    
    print("Running audit...")

    output_type = get_output_type()
    
    # Obtain a list of all IAM usernames in an AWS account
    users = list_iam_users()
    if not users:
        print("No users found")
        return

    for user in users:
        policies_attached_from_groups = []
        permission_list = []

        # Find policies directly attached to a user profile which is not recommended
        policies_directly_attached_to_user = list_user_policies(user)
        output[user] = {"policiesDirectlyAttachedToUser": policies_directly_attached_to_user}

        # Obtain a list of all groups a user is associated with
        groups = list_user_groups(user)
        output[user].update({"groupsAssignedToUser": groups})

        for group in groups:
            # Obtain a list of policies associated with a group
            group_policies = list_group_policies(group)
            policies_attached_from_groups.append(group_policies)

        # Dedups policies
        policies_attached_from_groups = consolidate_policies(policies_attached_from_groups)
        output[user].update({"policiesAttachedFromGroups": policies_attached_from_groups})
        
        # Obtain permissions tied to a policy for the active policy version
        for policy in policies_attached_from_groups:
            version_id = get_default_version_id(policy)
            permissions = get_permissions(policy, version_id)
            permission_list.append({"policy": policy, "permissions": permissions})
        
        # Obtain permissions tied to a policy for the active policy version [2]
        for policy in policies_directly_attached_to_user:
            version_id = get_default_version_id(policy)
            permissions = get_permissions(policy, version_id)
            permission_list.append({"policy": policy, "permissions": permissions})

        output[user].update({"permissions": permission_list})                        
    
    if output_type == "stdout":
        print(json.dumps(output, indent=4))
    elif output_type == "json":
        write_to_json_file()
    elif output_type == "csv":
        write_to_csv_file()
    
    
def get_output_type():
    """Obtain the report output type from the users via 
    the command line. The default value is stdout in a
    json prettyprint format. 

    Returns:
        [str]: stdout, csv, or json 
    """

    parser = argparse.ArgumentParser()

    parser.add_argument(
        '-o', 
        '--output_type', 
        type=str, 
        default='stdout',
        choices=["stdout", "csv", "json"],
        help='The output data format')

    args = parser.parse_args()

    return args.output_type


def list_iam_users():
    """Use the AWS boto3 paginator function to
    get a list of all usernames for an account. 

    Returns:
        [list]: AWS usernames
    """

    marker = None
    users = []

    while True:
        response_iterator = user_paginator.paginate(
            PaginationConfig={
                'MaxItems': 100,
                'PageSize': 100,
                'StartingToken': marker
            }
        )

        for i in response_iterator:
            marker = i.get('Marker', None)
            
            for user_data in i['Users']:
                users.append(user_data['UserName'])

        if not marker:
            break

    return users


def list_user_policies(user):
    """Use the AWS boto3 paginator function to
    get a list of all policies directly attached to
    a users profile. 

    Args:
        user (str): An AWS username

    Returns:
        [list]: Policies directly attached to an AWS user
    """

    marker = None
    policies = []

    while True:
        response_iterator = attached_user_paginator.paginate(
            UserName=user,
            PaginationConfig={
                'MaxItems': 100,
                'PageSize': 100,
                'StartingToken': marker
            }
        )

        for i in response_iterator:
            marker = i.get('Marker', None)
            
            for policy_data in i['AttachedPolicies']:
                policies.append(policy_data['PolicyArn'])

        if not marker:
            break

    return policies


def list_user_groups(user):
    """Use the AWS boto3 paginator function to
    get a list of all groups an AWS user is 
    assigned to.

    Args:
        user (str): An AWS username

    Returns:
        [list]: Groups assigned to an AWS user
    """

    marker = None
    groups = []

    while True:
        response_iterator = group_paginator.paginate(
            UserName=user,
            PaginationConfig={
                'MaxItems': 100,
                'PageSize': 100,
                'StartingToken': marker
            }
        )

        for i in response_iterator:
            marker = i.get('Marker', None)
            
            for group in i['Groups']:
                groups.append(group['GroupName'])

        if not marker:
            break

    return groups


def list_group_policies(group):
    """Use the AWS boto3 paginator function to
    get a list of all polcies assigned to an AWS
    group.

    Args:
        group (str): An AWS group name

    Returns:
        [list]: Policies assigned to AWS group.
    """

    marker = None
    group_policies = []

    while True:
        response_iterator = group_policy_paginator.paginate(
            GroupName=group,
            PaginationConfig={
                'MaxItems': 100,
                'PageSize': 100,
                'StartingToken': marker
            }
        )

        for i in response_iterator:
            marker = i.get('Marker', None)
            
            for group_policy in i['AttachedPolicies']:
                group_policies.append(group_policy['PolicyArn'])

        if not marker:
            break
        
    return group_policies


def consolidate_policies(policies_attached_from_groups):
    """Deduplicates the list of policies assigned to a group.

    Args:
        policies_attached_from_groups (list): Policies attached from groups

    Returns:
        [list]: Deduped list of policies assigned to groups
    """

    consolidated_policies = []

    for policies in policies_attached_from_groups:
        for policy in policies:
            consolidated_policies.append(policy)

    return list(set(consolidated_policies))


def get_default_version_id(policy):
    """Obtains the current policy document's version ID. 

    Args:
        policy (str): An AWS policy ARN

    Returns:
        [str]: AWS policy document version ID
    """

    response = client.list_policy_versions(
                PolicyArn=policy)

    versions = response['Versions']
    version_id = "v1"

    for version in versions:
        if version['IsDefaultVersion']:
            version_id = version['VersionId']

    return version_id


def get_permissions(policy, version_id):
    """Obtains a list of permissions tied to the current version
    of an AWS policy. 

    Args:
        policy (str): An AWS policy ARN
        version_id (str): AWS policy document version ID

    Returns:
        [list]: Permissions associated with policy
    """

    response = client.get_policy_version(
                PolicyArn=policy,
                VersionId=version_id)

    return response['PolicyVersion']['Document']['Statement']

        
def write_to_json_file():
    """Write audit data to a JSON file with the current timestamp.

    Returns:
        [bool]: True if write is successfull, false if not. 
    """

    output_file = "{}_aws_iam_permissions.json".format(timestamp_string)

    try:
        with open(output_file, "w") as outfile:
            json.dump(output, outfile, indent=4)
    except Exception as e:
        print(e)
        print("Error writing to file. Outputting to stdout instead")
        print(output)
        return False

    print("Complete. Data outputted to {}".format(os.path.abspath(output_file)))
    return True


def write_to_csv_file():
    """Write audit data to a CSV file with the current timestamp.

    Returns:
        [bool]: True if write is successfull, false if not. 
    """

    output_file = "{}_aws_iam_permissions.csv".format(timestamp_string)
    fields = ["username", "policyArn", "permissions"]
    
    # writing to csv file  
    try:
        with open(output_file, 'w') as csvfile:  
            # creating a csv writer object  
            csvwriter = csv.writer(csvfile)  
                
            # writing the fields  
            csvwriter.writerow(fields)  

            for username, data in output.items():
                for permission in data["permissions"]:
                    csvwriter.writerow([username, permission["policy"], permission["permissions"]])
    except Exception as e:
        print(e)
        print("Error writing to file. Outputting to stdout instead")
        print(output)
        return False

    print("Complete. Data outputted to {}".format(os.path.abspath(output_file)))
    return True


if __name__ == "__main__":
    main()
