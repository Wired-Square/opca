#!/usr/bin/env python3
"""
#
# aws_lambda.py - A notification script for AWS Lambda
#
"""

import boto3
import os
import json
import sqlite3
import urllib3
from datetime import datetime, timedelta, timezone


now = datetime.now(timezone.utc)
days = int(os.environ.get('DAYS'))
db_bucket = os.environ.get('DB_BUCKET')
db_key = os.environ.get('DB_KEY')
crl_bucket = os.environ.get('CRL_BUCKET')
crl_key = os.environ.get('CRL_KEY')
local_db_path = os.environ.get('LOCAL_DB_PATH')
slack_user = os.environ.get('SLACK_USER')
slack_url = os.environ.get('SLACK_URL')


def ca_database_handler(file):
    conn = sqlite3.connect(file)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT serial, cn, expiry_date 
        FROM certificate_authority 
        WHERE revocation_date IS NULL
    """)

    rows = cursor.fetchall()

    cursor.close()
    conn.close()

    return rows


def concat_msg(msg):
    print(msg)

    return f'{msg}\n'


def file_age_check(description, last_modified):
    warning = False

    age = now - last_modified.replace(tzinfo=timezone.utc)

    total_seconds = int(age.total_seconds())

    age_hours, remainder = divmod(total_seconds - age.days * 86400, 3600)
    age_minutes = remainder // 60
    
    friendly_age = f'{age.days} days, {age_hours} hours, {age_minutes} minutes'

    if age.days > days:
        warning = True
        msg = concat_msg(f'*Warning: {description} is too old at {friendly_age}*')
    else:
        msg = concat_msg(f'{description} file age is {friendly_age}')

    return msg, warning


def find_expiring_certificates(certificates, days):
    expiring_certs = {
        'expiring': False,
        'certs': {},
        'msg': ''
        }
    delta = timedelta(days)
    msg = ''

    for serial, cn, expiry_str in certificates:
        expiry_date = datetime.strptime(expiry_str, "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)
        
        if now <= expiry_date <= now + delta:
            expiring_certs['expiring'] = True
            expiring_certs['certs'][serial] = {'cn': cn, 'expiry': expiry_str}
            msg += concat_msg(f'Serial: {serial}, CN: {cn}, Expiry: {expiry_str}')

    expiring_certs['msg'] = msg

    return expiring_certs


def get_s3_item(bucket, key, path=None):
    s3 = boto3.client('s3')

    if path is not None:
        s3.download_file(bucket, key, path)

    metadata = s3.head_object(Bucket=bucket, Key=key)
    last_modified = metadata['LastModified']

    return last_modified


def send_slack_notification(username, message, webhook_url, warning=False):
    if warning:
        icon = ':warning:'
    else:
        icon = ':robot_face:'

    slack_data = {
        'username': username,
        'icon_emoji': icon,
        'text': message
    }

    http = urllib3.PoolManager()
    response = http.request(
        'POST',
        webhook_url,
        body=json.dumps(slack_data),
        headers={'Content-Type': 'application/json'}
    )

    print(f"Slack response status: {response.status}")


def lambda_handler(event, context):
    msg = ''
    warning = False

    db_msg, db_warning = file_age_check('CA Database', get_s3_item(bucket=db_bucket, key=db_key, path=local_db_path))
    crl_msg, crl_warning = file_age_check('CRL', get_s3_item(bucket=db_bucket, key=db_key))

    msg += db_msg + crl_msg
    warning = warning or db_warning or crl_warning

    expiring_certs = find_expiring_certificates(ca_database_handler(local_db_path), days)
    num_certs = len(expiring_certs['certs'])

    if expiring_certs['expiring']:
        warning = True
        msg += concat_msg(f'*Warning: {num_certs} Certificates expiring in the next {days} days.*\n' +
                          f'{expiring_certs['msg']}')
    else:
        msg += concat_msg(f'No certificates expiring in the next {days} days.')

    send_slack_notification(slack_user, msg, slack_url, warning)

    return {
        'statusCode': 200,
        'expiring': expiring_certs['expiring'],
        'body': expiring_certs['certs']
    }
