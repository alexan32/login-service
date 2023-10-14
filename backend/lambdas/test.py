# Description:
# Input:
# Output:
# Last Update: 

import logging
import json
import boto3
import os

logger = logging.getLogger()
loglevel = os.environ["LOG_LEVEL"]
logger.setLevel(eval(loglevel))

def handler(event, ctx):

    logger.info(json.dumps(event))

    return {
        "status" : 200,
        "message": "ok"
    }