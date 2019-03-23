#!/usr/local/bin/python

import boto3
import botocore.session
import base64

def role_arn_to_session(**args):
    client = boto3.Session(profile_name='default').client('sts')

    response = client.assume_role(**args)
    print response['Credentials']['AccessKeyId']
    print response['Credentials']['SecretAccessKey']
    print response['Credentials']['SessionToken']
    return boto3.Session(
        aws_access_key_id=response['Credentials']['AccessKeyId'],
        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
        aws_session_token=response['Credentials']['SessionToken'])


session = role_arn_to_session(
    RoleArn='arn:aws:iam::764112847618:role/Application-A-Role',
    RoleSessionName='session',
    )

