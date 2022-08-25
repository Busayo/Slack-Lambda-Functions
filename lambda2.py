import json
import os
import hmac
import hashlib
import urllib.parse
from botocore.vendored import requests

def lambda_handler(event, context):

    # Make sure this request has come from Slack
    if not verify_request(event):

        # If you're having problems, uncomment this line and check the cloudwatch logs:
        # print(json.dumps(event))
        return {
            'statusCode': 401
        }

    # Get a joke from icanhazdadjoke.com
    joke = get_joke()

    if not joke:
        return {
            'statusCode': 200,
            'body': json.dumps({
                'text': 'No jokes are available at this time',
                'response_type': 'ephemeral'  # Only tell the requester
            })
        }

    # Send the joke to the channel as a delayed message
    request = urllib.parse.parse_qs(event['body'])
    url = request['response_url'][0]
    response = {
            'text': joke,
        'response_type': 'in_channel'
    }
    result = requests.post(url, json=response)
    # If the delayed response was successful then we'll send an empty success message to Slack

    if result.status_code == 200:
        return {
            'statusCode': 200,
        }

    # If the delayed response failed for any reason, we'll send the joke in the API response
    return {
        'statusCode': 200,
        'body': json.dumps({
            'text': joke,
            'response_type': 'in_channel'
        })
    }

def get_joke():
    url = 'https://icanhazdadjoke.com/'
    headers = {
        'Accept': 'text/plain'
    }
    result = requests.get(url, headers=headers)
    if result.status_code == 200:
        return result.text
    return None
    
def verify_request(event):
    # Refer to this document for information on verifying requests:
    # https://api.slack.com/docs/verifying-requests-from-slack

    signature = event['headers']['X-Slack-Signature']
    req = 'v0:' + event['headers']['X-Slack-Request-Timestamp'] + ':' + event['body']
    request_hash = 'v0=' + hmac.new(
        os.environ["SIGNING_SECRET"].encode(),
        req.encode(), hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(request_hash, signature)

# before adding this as lambda function, go into your environment variables, include an env var of key-SIGNING_SECRET with the value gotten
# from your slack credentials.
