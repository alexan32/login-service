# Description: 
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


def passwordResetEmail():
    client = boto3.client("ses")
    pass


def verifyAccountEmail():
    client = boto3.client("ses")
    pass