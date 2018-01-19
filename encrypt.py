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
    #session = boto3.Session(profile_name='cc')
    # Any clients created from this session will use credentials
    # from the [dev] section of ~/.aws/credentials.
    client = boto3.Session(profile_name='cc').client('sts')

    #client = boto3.client('sts')
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


def savefile(file, content):
    with open(file, "w") as text_file:
        text_file.write(str(content))


def kmsencrypt(token, plain_text):
    key_id = 'alias/cc'
    session = role_arn_to_session(
        RoleArn='arn:aws:iam::764112847618:role/cc',
        RoleSessionName='cc',
        SerialNumber='arn:aws:iam::764112847618:mfa/cc',
        TokenCode=token)
    kms = session.client('kms')
    stuff = kms.encrypt(KeyId=key_id, Plaintext=plain_text)
    binary_encrypted = stuff[u'CiphertextBlob']
    encrypted_string = base64.b64encode(binary_encrypted)
    print("Ciphertext Blob:\n") + encrypted_string.decode()
    savefile("encrypted.txt", encrypted_string.decode())


if __name__ == '__main__':
    from sys import argv
    myargs = getopts(argv)
    if '--token' in myargs and '--plaintext' in myargs:  # Example usage.
        token = myargs['--token']
        plain_text = myargs['--plaintext']
        kmsencrypt(token, plain_text)
    else:
        print "error: the following arguments are required: --token, --plaintext"