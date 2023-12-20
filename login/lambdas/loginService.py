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
tokenDuration = int(os.environ.get("TOKEN_DURATION", '3'))

def handler(event, ctx):

    # logger.info(f"event: {json.dumps(event)}") # we don't want to log passwords! 
    httpContext = event['requestContext'].get("http", {})
    method = httpContext["method"]
    path = httpContext['path']
    body = event.get('body')
    if body is not None:
        body = json.loads(event.get('body', '{}'))
    status = 400
    message = "bad request method or malformed request"

    logger.info(f"\npath: {path}\nmethod: {method}\nbody: {body}") 
    
    if method == 'GET' and path == '/health':
        response = buildResponse(200, "UP")
    
    elif method == 'POST' and path == '/register':
        response = register(body)
    
    elif method == 'POST' and path == '/login':
        response = login(body)
    
    elif method == 'POST' and path == '/verify':
        response = verify(body, event['headers'].get('authorization'))

    else:
        response = buildResponse(status, message)

    logger.info(f"Response: {json.dumps(response)}")
    return response

# REQUEST HANDLERS ----------------------------------------

# creates a new user
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


# verifies user/password, sends back JWT
def login(body):
    username = body.get("username", "").strip().lower()
    password = body.get("password", "").strip().lower()
    if username == "" or password == "":
        return buildResponse(401, "missing required parameters")
    else:
        status, message, data = queryUsers(username)
        if status != 200:
            return buildResponse(500, "An error occurred when trying to login. Please retry later.")
        if len(data) == 0:
            return buildResponse(403, "We could not find an account with that username.")
        user = data[0]
        savedPassword = user['password']
        encryptedPassword = encryptPassword(password)
        if savedPassword != encryptedPassword:
            return buildResponse(403, "The password was invalid")
        
        # user's password is not directly in response body, but is in token.
        token = buildUserToken(user)
        del user['password']
        responseBody = {
            "user": user,
            "token": token
        }
        return buildResponse(200, "Valid username and password. Login successful.", responseBody)


# confirms a JWT is valid.
def verify(body, token):

    responseBody = {
        "verified": False,
        "expired": False 
    }

    if token is None:
        return buildResponse(403, "Missing \"Authorization\" header.", responseBody)
    
    decodedToken = jwtDecodeToken(token)
    currentTime = getUnixTime()
    expiration = decodedToken.get('expiration', 0)
    username = decodedToken.get('username')
    permissions = decodedToken.get('permissions')

    if currentTime > expiration:
        responseBody["expired"] = True
        return buildResponse(401, "Token is expired.", responseBody)
    
    status, message, data = queryUsers(username)
    if status != 200:
        return buildResponse(500, "An error occurred when trying to login. Please retry later.", responseBody)
    if len(data) == 0:
        return buildResponse(401, "Token was invalid", responseBody)

    # If permissions do not match, assumption is that permissions probably changed. Mark as expired
    # to indicate to the client that the user should be redirected to login again.
    user = data[0]
    if permissions != user['permissions']:
        responseBody["expired"] = True
        return buildResponse(401, "Permissions in token did not match user.", responseBody)
    
    responseBody["verified"] = True
    return buildResponse(200, "Token is verified", responseBody)
    

# OTHER OPERATIONS ----------------------------------------

def createNewUser(username, password):
    user = {
        'username': username,
        'password': encryptPassword(password),
        'discordId': None,
        'permissions': []
    }
    return putItem(userTable, user)


def buildUserToken(user):
    payload = {**user}
    payload['expiration'] = getUnixTime(hours=tokenDuration)
    del payload['password']                 # remove password from token. JIC.
    return jwtEncodeData(payload)


def queryUsers(username:str):
    return performQuery(userTable, {"KeyConditionExpression": Key('username').eq(username)})
