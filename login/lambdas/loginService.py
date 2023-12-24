# DESCRIPTION: Handler for user registration, login, and verification
#
# NOTES: login service and user table should be kept generic. Data in table 
# should not be directly tied to specific features.
#
# LAST UPDATE: 12/24/2023, lightly_caffienated. code revision and update to 
# user row info.

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
        response = verify(event['headers'].get('authorization'), body.get('action'))

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
            if status != 200:
                return buildResponse(status, "Failed to register new user")
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
        
        # update last access
        user["lastAccess"] = getDateString()
        status, message = putItem(userTable, user)
        if status != 200:
            logger.warn("Failed to update 'lastAccess' for user!")

        # user's password is not directly in response body, but is in token.
        token = buildUserToken(user)
        del user['password']
        del user['data']
        responseBody = {
            "user": user,
            "token": token
        }
        return buildResponse(200, "Valid username and password. Login successful.", responseBody)


# confirms a JWT is valid / user is allowed to perform action
def verify(token, action=None):

    responseBody = {
        "verified": False,
        "expired": False 
    }

    if token is None:
        return buildResponse(403, "Missing \"Authorization\" header.", responseBody)
    
    try:
        decodedToken = jwtDecodeToken(token)
    except Exception as e:
        logger.error(f"Failed to decode token! Error: {e}")
        return buildResponse(401, "Token was invalid", responseBody)

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
    
    # if action field is present, check if user is authorized for action.
    if action:
        if not action in permissions:
            return(401, f"User is not authorized to perform '{action}'.", responseBody)


    responseBody["verified"] = True
    return buildResponse(200, "Token is verified", responseBody)
    

# OTHER OPERATIONS ----------------------------------------

def createNewUser(username, password):
    user = {
        'username': username,
        'password': encryptPassword(password),
        'created': getDateString(),
        'verified': False,
        'permissions': [],
        'lastAccess': "never",
        'data': {} # use this to keep key data to associate user with other tables, ie discordId. keep the auth service generic. 
    }
    return putItem(userTable, user)


def buildUserToken(user):
    payload = {**user}
    payload['expiration'] = getUnixTime(hours=tokenDuration)
    del payload['password']                 # remove password from token. JIC.
    return jwtEncodeData(payload)


def queryUsers(username:str):
    return performQuery(userTable, {"KeyConditionExpression": Key('username').eq(username)})
