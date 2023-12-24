import jwt
import os
import json
import time
import base64
import logging
from datetime import datetime, timedelta
from botocore.exceptions import ClientError


logger = logging.getLogger()
loglevel = os.environ["LOG_LEVEL"]
logger.setLevel(eval(loglevel))


def jwtDecodeToken(token: str):
    secretKey = os.environ.get("SECRET_KEY")
    return jwt.decode(jwt=token, key=secretKey, algorithms=["HS256"])

def jwtEncodeData(data):
    secretKey = os.environ.get("SECRET_KEY")
    return jwt.encode(payload=data, key=secretKey, algorithm="HS256")

def encryptPassword(text):
    return str(base64.b64encode(text.encode("utf-8")))

def getUnixTime(**kwargs):
    return int(time.mktime((datetime.now() + timedelta(**kwargs)).timetuple()))

def getDateString():
    return datetime.today().strftime('%Y-%m-%d')

def putItem(table, item, maxRetries=2, depth=0,):
    try:
        response = table.put_item(Item=item) 
    except ClientError as e:
        message = f"Encountered error while updating table. Error: {e}"
        logger.error(message)
        if depth == maxRetries:
            logger.error("Maximum depth reached, putItem returning failure.")
            return 400, message
        else:
            time.sleep(1)
            return putItem(table, item, maxRetries, depth + 1)
    
    return 200, "ok"

def callFunctionWithRetry(func, kwargs, maxRetries=2, depth=0):
    success = False
    response = None

    try:
        response = func(**kwargs)
    except Exception as e:
        logger.error(f"Failed to perform function {func.__name__}. Error: {e}")
        if depth == maxRetries:
            logger.error(f"Maximum depth reached, {func.__name__} returning failure.")
            return success, response
        else:
            time.sleep(1)
            return callFunctionWithRetry(func, kwargs, maxRetries, depth + 1)
    else:
        return True, response

def performQuery(table, queryArgs:dict, maxRetries=2, depth=0):
    status = 200
    message = "ok"
    data = None
    response = None

    try:
        response = table.query(**queryArgs)
        logger.info(f"Query response: {response}")
    except ClientError as e:
        message = f"Failed to perform query on table: {table}. Error: {e}"
        logger.error(message)
        if depth == maxRetries:
            logger.error("Maximum depth reached, perform query returning failure.")
            return status, message, data
        else:
            time.sleep(1)
            return performQuery(table, queryArgs, maxRetries, depth + 1 )
    else:
        if response != None and status == 200:
            data = response["Items"]

    return status, message, data

def buildResponse(statusCode, message="ok", body=None):
    if body:
        body['message'] = message
    else:
        body = {'message': message}
    body['statusCode']=statusCode
    
    return {
        "isBase64Encoded": False,
        "statusCode": statusCode,
        "headers": { 
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'applicaiton/json'
        },
        "body": json.dumps(body)
    }