# Description: Handler for user sign in, sign out, and sign up
# Input:
# Output:
# Last Update: 

import logging
import json
import boto3
import os
from lambdas.utils import *
from boto3.dynamodb.conditions import Key

logger = logging.getLogger()
loglevel = os.environ["LOG_LEVEL"]
logger.setLevel(eval(loglevel))

dynamodb = boto3.resource('dynamodb')
userTable = dynamodb.Table(os.environ['USER_TABLE'])


def handler(event, ctx):

    # logger.info(f"event: {json.dumps(event)}")
    method = event['httpMethod']
    path = event['path']
    body = json.loads(event['body'])
    status = 400
    message = "bad request method"
    
    logger.info(f"\npath: {path}\nmethod: {method}\nbody: {event['body']}")
    
    if method == 'GET' and path == '/health':
        return buildResponse(200, "UP")
    
    elif method == 'POST' and path == '/register':
        return register(body)
    
    elif method == 'POST' and path == '/login':
        pass
    
    elif method == 'POST' and path == '/verify':
        pass

    return buildResponse(status, message)

# REQUEST HANDLERS ----------------------------------------

def register(body):
    username = body.get("username", "").strip().lower()
    password = body.get("password", "").strip().lower()
    if username == "" or password == "":
        return buildResponse(401, "missing required parameters")
    else:
        status, message, users = queryUsers(username)
        if len(users) > 0:
            return buildResponse(409, "A user already exists with that username.")
        else:
            status, message = createNewUser(username, password)
            return buildResponse(status, "New user successfully created")

def login(body):
    pass

def verify(body):
    pass

# OTHER OPERATIONS ----------------------------------------

def createNewUser(username, password):
    #TODO: add password encryption system
    user = {
        'username': username,
        'password': encrypt(password),
        'discordId': None
    }
    return putItem(userTable, user)

def queryUsers(username:str):
    return performQuery(userTable, {"KeyConditionExpression": Key('username').eq(username)})
