#!/usr/bin/env python3

# Automatic tagging of AWS resource based on User Identity and Session Tags

# Import AWS modules for python
import botocore
import boto3
# Import JSON
import json
# Import RegEx module
import re
# Import Datetime module
import datetime


endtime = datetime.datetime.now()  # Create start and end time for CloudTrail lookup
interval = datetime.timedelta(hours=24)
starttime = endtime - interval

def lambda_handler(event, context):
    # TODO implement
    def get_unc_cw_event_data(event):
        cw_data_dict = dict()
        cw_data_dict = event['detail']
        return cw_data_dict

    def get_saml_trail():
        try:
            client = boto3.client('cloudtrail')
            response = client.lookup_events(
                LookupAttributes=[
                    {
                    'AttributeKey': 'EventName',
                    'AttributeValue': 'AssumeRoleWithSAML'
                    },
                ],
                StartTime=starttime,
                EndTime=endtime,
                MaxResults=20,
                )
        except botocore.exceptions.ClientError as error:
            print("Boto3 API returned error: ", error)
        return response['Events']

    def get_session_tags(trails,username):
        try:
            for trail in trails:
                if trail['Username'] == username:
                    test = json.loads(trail['CloudTrailEvent'])
                    session_tag = test['requestParameters']['principalTags']
                    return session_tag
        except botocore.exceptions.ClientError as error:
            print("Boto3 API returned error: ", error)

    #Apply tags to resource
    def set_resource_tags(resource_id, resource_tags):
        # Is this an EC2 resource?
        if re.search("^i-", resource_id):
            try:
                client = boto3.client('ec2')
                response = client.create_tags(
                    Resources=[
                        resource_id
                    ],
                    Tags=resource_tags
                )
                response = client.describe_volumes(
                    Filters=[
                        {
                            'Name': 'attachment.instance-id',
                            'Values': [
                                resource_id
                            ]
                        }
                    ]
                )
                try:
                    for volume in response['Volumes']:
                        ec2 = boto3.resource('ec2')
                        ec2_vol = ec2.Volume(volume['VolumeId'])
                        vol_tags = ec2_vol.create_tags(
                        Tags=resource_tags
                        )
                except botocore.exceptions.ClientError as error:
                    print("Boto3 API returned error: ", error)
                    print("No Tags Applied To: ", response['Volumes'])
                    return False
            except botocore.exceptions.ClientError as error:
                print("Boto3 API returned error: ", error)
                print("No Tags Applied To: ", resource_id)
                return False
            return True
        else:
            return False
    
    data_dict = get_unc_cw_event_data(event)
    username = data_dict['userIdentity']['principalId'].split(':')
    username = username[-1]
    trails = get_saml_trail()
    session_tags = get_session_tags(trails,username)
    resource_tags = []

    for k,v in session_tags.items():
        resource_tags.append({'Key': k, 'Value': v})
    

    if 'instancesSet' in data_dict['responseElements']:
        for item in data_dict['responseElements']['instancesSet']['items']:
            resource_id = item['instanceId']
            if set_resource_tags(resource_id, resource_tags):    
                return {
                    'statusCode': 200,
                    'Resource ID': resource_id,
                    'body': json.dumps(resource_tags)
                }
            else:
                return {
                    'statusCode': 500,
                    'No tags applied to Resource ID': resource_id,
                    'Lambda function name': context.function_name,
                    'Lambda function version': context.function_version
                }
    else:
        return {
            'statusCode': 200,
            'No resources to tag': event['id']
        }