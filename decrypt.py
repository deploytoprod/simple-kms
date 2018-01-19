#!/usr/local/bin/python

import boto3
import botocore.session
import base64

def role_arn_to_session(**args):
    """
    Usage :
        session = role_arn_to_session(
            RoleArn='arn:aws:iam::012345678901:role/example-role',
            RoleSessionName='ExampleSessionName')
        client = session.client('sqs')
    """
    client = boto3.Session(profile_name='cc').client('sts')
    response = client.assume_role(**args)
    return boto3.Session(
        aws_access_key_id=response['Credentials']['AccessKeyId'],
        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
        aws_session_token=response['Credentials']['SessionToken'])


def getopts(argv):
    opts = {}  # Empty dictionary to store key-value pairs.
    while argv:  # While there are arguments left to parse...
        if argv[0][0] == '-':  # Found a "-name value" pair.
            opts[argv[0]] = argv[1]  # Add key and value to the dictionary.
        argv = argv[1:]  # Reduce the argument list by copying it starting from index 1.
    return opts


def readfile(file):
    file = open(file,"r")
    content = str(file.read())
    file.close()
    return content

def kmsdecrypt(token, file_name):
    session = role_arn_to_session(
        RoleArn='arn:aws:iam::764112847618:role/cc',
        RoleSessionName='cc',
        SerialNumber='arn:aws:iam::764112847618:mfa/cc',
        TokenCode=token)
    encrypted_string = readfile(file_name)
    binary_data = base64.b64decode(encrypted_string)
    kms = session.client('kms')
    meta = kms.decrypt(CiphertextBlob=binary_data)
    plaintext = meta[u'Plaintext']
    print("Plaintext content: \n" + plaintext.decode())

if __name__ == '__main__':
    from sys import argv
    myargs = getopts(argv)
    if '--token' in myargs and '--file' in myargs:  # Example usage.
        token = myargs['--token']
        file_name = myargs['--file']
        kmsdecrypt(token, file_name)
    else:
        print "error: the following arguments are required: --token, --file"
