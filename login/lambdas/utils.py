import logging
import json
import boto3
import os
import time
from datetime import datetime, timedelta
from botocore.exceptions import ClientError
import base64
import jwt

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

def getUnixTime(dt=0):
    return int(time.mktime((datetime.now() + timedelta(hours=dt)).timetuple()))

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
    
    return {
        "isBase64Encoded": False,
        "statusCode": statusCode,
        "headers": { 
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'applicaiton/json'
        },
        "body": json.dumps(body)
    }