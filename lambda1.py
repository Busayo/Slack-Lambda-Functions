import os
import json
import urllib.parse
import hmac
import hashlib
import boto3
from botocore.exceptions import ClientError


def lambda_handler(event, context):

    try:
        is_request_from_slack = check_if_request_from_slack(event)

        if is_request_from_slack == False:
            return send_failure_reason("Request not from Slack")

        command_input = extract_command_input(event)

        if not command_input:
            return send_failure_reason(
                "Send an aws username with the command to get user details. It is neither empty nor blank in the command input.")

        user = get_user(command_input)
        return send_success_response(user)

    except ClientError as error:
        print(error)
        return send_failure_reason(error.response['Error']['Message'])
    except Exception as e:
        print(e)
        return send_failure_reason(
            "Unable to process your request at this time. please try again later or contact the admin.")

# Send success response to the Slack user


def send_success_response(user):
    return {
        'statusCode': 200,
        'body': json.dumps({
            "response_type": "in_channel",
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"Here is the details about aws user *{user.user_name}*"
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"ARN - {user.arn}"
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"Account Created Date - {user.create_date}"
                    }
                }
            ]
        }),
        'headers': {
            'Content-Type': 'application/json'
        }
    }

# Send failure reason to the Slack user


def send_failure_reason(message):
    return {
        'statusCode': 200,
        'body': json.dumps(
            {
                "response_type": "in_channel",
                "text": message
            }
        ),
        'headers': {
            'Content-Type': 'application/json'
        }
    }

# Parse out command input from the posted message


def extract_command_input(event):
    body = event['body']
    command = body.split("text=")[1]
    command_input = urllib.parse.unquote(command.split("&")[0])
    return command_input.strip()

# Get AWS IAM user details with boto3


def get_user(username):
    try:
        iam = boto3.resource('iam')
        user = iam.User(username)
        return user
    except ClientError as boto3ClientError:
        raise boto3ClientError

# Verify the request is from Slack


def check_if_request_from_slack(event):
    body = event['body']
    timestamp = event['headers']['X-Slack-Request-Timestamp']
    slack_signature = event['headers']['X-Slack-Signature']
    slack_signature_basestring = "v0:" + timestamp + ":" + body
    slack_signature_hash = "v0=" + hmac.new(os.environ['SLACK_SIGNING_SECRET'].encode(
        'utf-8'), slack_signature_basestring.encode('utf-8'), hashlib.sha256).hexdigest()

    if not hmac.compare_digest(slack_signature_hash, slack_signature):
        return False
    else:
        return True    
    

# before adding this as lambda function, go into your environment variables, include an env var of key-SLACK_SIGNING_SECRET with the value gotten
# from your slack credentials.

# ensure that your IAM function is has IAMReadOnlyAccess enabled as a policy along with the regular Lambda IAM function already created.
