# -*- coding: utf-8 -*-
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
ECS queue worker: long-polls SQS, processes one message at a time (scan S3 object
with ClamAV, set tags, SNS, metrics), deletes message, repeats forever.
"""

import json
import sys

import boto3

from common import AV_SCAN_QUEUE_URL
from common import get_timestamp
import scan


def run():
    if not AV_SCAN_QUEUE_URL:
        print("AV_SCAN_QUEUE_URL is not set.", file=sys.stderr)
        sys.exit(1)

    sqs = boto3.client("sqs")
    s3 = boto3.resource("s3")

    print(
        "Worker starting at %s, queue %s" % (get_timestamp(), AV_SCAN_QUEUE_URL),
        flush=True,
    )

    while True:
        try:
            resp = sqs.receive_message(
                QueueUrl=AV_SCAN_QUEUE_URL,
                MaxNumberOfMessages=1,
                WaitTimeSeconds=20,
                VisibilityTimeout=900,
            )
        except Exception as e:
            print("SQS receive_message error: %s" % e, file=sys.stderr, flush=True)
            continue

        messages = resp.get("Messages") or []
        for msg in messages:
            receipt_handle = msg["ReceiptHandle"]
            try:
                body = json.loads(msg["Body"])
                bucket = body.get("bucket")
                key = body.get("key")
                if not bucket or not key:
                    print(
                        "Invalid message body (missing bucket/key), deleting: %s"
                        % body,
                        flush=True,
                    )
                    sqs.delete_message(
                        QueueUrl=AV_SCAN_QUEUE_URL,
                        ReceiptHandle=receipt_handle,
                    )
                    continue

                s3_object = s3.Object(bucket, key)
                scan.scan_one_object(s3_object)

                sqs.delete_message(
                    QueueUrl=AV_SCAN_QUEUE_URL,
                    ReceiptHandle=receipt_handle,
                )
            except Exception as e:
                print(
                    "Failed to process message (will retry after visibility timeout): %s"
                    % e,
                    file=sys.stderr,
                    flush=True,
                )


if __name__ == "__main__":
    run()
