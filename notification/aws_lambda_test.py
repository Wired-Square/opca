#!/usr/bin/env python3
"""
#
# aws_lambda_test.py - A local test script for the AWS Lambda notification function
#
"""

import subprocess
import os
from aws_lambda import lambda_handler

event = {
    "key1": "value1",
    "key2": "value2"
}

class Context:
    def __init__(self):
        self.function_name = "test_lambda"
        self.memory_limit_in_mb = 128
        self.invoked_function_arn = "arn:aws:lambda:ap-southeast-1:123456789012:function:test_lambda"
        self.aws_request_id = "test-request-id"

context = Context()

command = ["op", "plugin", "run", "--", "aws", "configure", "export-credentials", "--format", "env"]
result = subprocess.run(command, capture_output=True, text=True)

if result.returncode == 0:
    for line in result.stdout.splitlines():
        if line.startswith("export "):
            var, value = line[len("export "):].split("=", 1)
            os.environ[var] = value
            print(f'{var} is now set')
else:
    print("Error:")
    print(result.stderr)

response = lambda_handler(event, context)
print(response)

