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
Signature updates run in a background thread every 60 min; clamd SelfCheck
auto-reloads when new .cvd files appear on disk.
Prefetcher thread pipelines receive+download with scan+post-process for throughput.
"""

import json
import os
import queue
import sys
import threading
import time

import boto3

import clamav
import scan
from common import AV_DEFINITION_S3_BUCKET
from common import AV_DEFINITION_S3_PREFIX
from common import AV_DELETE_INFECTED_FILES
from common import AV_SCAN_QUEUE_URL
from common import AV_STATUS_INFECTED
from common import create_dir
from common import get_timestamp


def _sync_defs_from_s3(s3_client, s3_resource):
    """Download new virus defs from S3 to AV_DEFINITION_PATH. No manual reload; SelfCheck handles it."""
    try:
        to_download = clamav.update_defs_from_s3(
            s3_client, AV_DEFINITION_S3_BUCKET, AV_DEFINITION_S3_PREFIX
        )
        for download in to_download.values():
            s3_path = download["s3_path"]
            local_path = download["local_path"]
            print(
                "Background sync: downloading %s from s3://%s/%s"
                % (local_path, AV_DEFINITION_S3_BUCKET, s3_path),
                flush=True,
            )
            s3_resource.Bucket(AV_DEFINITION_S3_BUCKET).download_file(
                s3_path, local_path
            )
            print("Background sync: %s complete" % local_path, flush=True)
    except Exception as e:
        print(
            "Background def sync error (will retry in 60 min): %s" % e,
            file=sys.stderr,
            flush=True,
        )


def _def_sync_loop(s3_client, s3_resource):
    """Run S3 def sync every 60 minutes. Errors are caught and logged."""
    while True:
        _sync_defs_from_s3(s3_client, s3_resource)
        time.sleep(3600)


def _prefetcher_loop(sqs, s3, ready_queue):
    """Receive SQS messages, download files to /tmp, put (receipt_handle, s3_object, file_path) in ready_queue."""
    while True:
        try:
            resp = sqs.receive_message(
                QueueUrl=AV_SCAN_QUEUE_URL,
                MaxNumberOfMessages=1,
                WaitTimeSeconds=20,
                VisibilityTimeout=900,
            )
        except Exception as e:
            print(
                "Prefetcher SQS receive_message error: %s" % e,
                file=sys.stderr,
                flush=True,
            )
            continue
        for msg in resp.get("Messages") or []:
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
                        ReceiptHandle=msg["ReceiptHandle"],
                    )
                    continue
                s3_object = s3.Object(bucket, key)
                file_path = scan.get_local_path(s3_object, "/tmp")
                create_dir(os.path.dirname(file_path))
                s3_object.download_file(file_path)
                ready_queue.put((msg["ReceiptHandle"], s3_object, file_path))
            except Exception as e:
                print(
                    "Prefetcher error (message will retry after visibility timeout): %s"
                    % e,
                    file=sys.stderr,
                    flush=True,
                )


def run():
    if not AV_SCAN_QUEUE_URL:
        print("AV_SCAN_QUEUE_URL is not set.", file=sys.stderr)
        sys.exit(1)

    # Initialize clients once at startup (connection reuse across loop iterations)
    sqs = boto3.client("sqs")
    s3 = boto3.resource("s3")
    s3_client = boto3.client("s3")
    sns_client = boto3.client("sns")

    # Background thread: sync virus defs from S3 every 60 min. SelfCheck in clamd auto-reloads.
    if AV_DEFINITION_S3_BUCKET:
        sync_thread = threading.Thread(
            target=_def_sync_loop,
            args=(s3_client, s3),
            daemon=True,
        )
        sync_thread.start()
        print("Background def sync thread started (every 60 min)", flush=True)
    else:
        print(
            "AV_DEFINITION_S3_BUCKET not set; skipping background def sync", flush=True
        )

    # Prefetch queue: (receipt_handle, s3_object, file_path). Max 2 items to limit /tmp usage.
    ready_queue = queue.Queue(maxsize=2)
    prefetcher_thread = threading.Thread(
        target=_prefetcher_loop,
        args=(sqs, s3, ready_queue),
        daemon=True,
    )
    prefetcher_thread.start()
    print(
        "Prefetcher thread started (pipelines receive+download with scan)", flush=True
    )

    print(
        "Worker starting at %s, queue %s" % (get_timestamp(), AV_SCAN_QUEUE_URL),
        flush=True,
    )

    # Main loop: consume prefetched items, scan, post-process, delete. Never exit.
    files_processed = 0
    loop_start = time.time()
    while True:
        iter_start = time.time()
        receipt_handle, s3_object, file_path = ready_queue.get()
        try:
            scan_result, _ = scan.scan_one_object_from_path(
                s3_object,
                file_path,
                s3_resource=s3,
                s3_client=s3_client,
                sns_client=sns_client,
            )
            sqs.delete_message(
                QueueUrl=AV_SCAN_QUEUE_URL,
                ReceiptHandle=receipt_handle,
            )
            should_delete_infected = (
                scan_result is not None
                and str_to_bool(AV_DELETE_INFECTED_FILES)
                and scan_result == AV_STATUS_INFECTED
            )
            if should_delete_infected:
                scan.delete_s3_object(s3_object)
        except Exception as e:
            print(
                "Failed to process message (will retry after visibility timeout): %s"
                % e,
                file=sys.stderr,
                flush=True,
            )
        finally:
            try:
                os.remove(file_path)
            except OSError:
                pass
            files_processed += 1
            iter_elapsed = time.time() - iter_start
            total_elapsed = time.time() - loop_start
            files_per_sec = files_processed / total_elapsed if total_elapsed > 0 else 0
            print(
                "[Throughput] file %d: %.2fs this file | %.1f files/sec (%.0f files in %.1fs)"
                % (
                    files_processed,
                    iter_elapsed,
                    files_per_sec,
                    files_processed,
                    total_elapsed,
                ),
                flush=True,
            )


if __name__ == "__main__":
    run()
