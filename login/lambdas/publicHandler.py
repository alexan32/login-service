# Description: Handler for user sign in, sign out, and sign up
# Input:
# Output:
# Last Update: 

import logging
import json
import boto3
import os
from lambdas.utils import *
from lambdas.loginService import *

logger = logging.getLogger()
loglevel = os.environ["LOG_LEVEL"]
logger.setLevel(eval(loglevel))

def handler(event, ctx):

    # logger.info(f"event: {json.dumps(event)}") # we don't want to log passwords!
    method = event['httpMethod']
    path = event['path']
    body = event.get('body')
    if body is not None:
        body = json.loads(event.get('body', '{}'))
    status = 400
    message = "bad request method or malformed request"

    logger.info(f"\npath: {path}\nmethod: {method}\nbody: {event['body']}")
    
    if method == 'GET' and path == '/health':
        response = buildResponse(200, "UP")
    
    elif method == 'POST' and path == '/register':
        response = register(body)
    
    elif method == 'POST' and path == '/login':
        response = login(body)
    
    elif method == 'POST' and path == '/verify':
        response = verify(body, event['headers'].get('Authorization'))

    else:
        response = buildResponse(status, message)

    logger.info(f"Response: {json.dumps(response)}")
    return response