import logging
import json
import boto3
import os
import time
from botocore.exceptions import ClientError

logger = logging.getLogger()
loglevel = os.environ["LOG_LEVEL"]
logger.setLevel(eval(loglevel))


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