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
Post-scan I/O (S3 tagging, SNS publish, SQS delete) runs in parallel via ThreadPoolExecutor.
"""

import json
import os
import queue
import sys
from collections import deque
import threading
import time
from concurrent.futures import ThreadPoolExecutor, wait

import boto3
from botocore.config import Config

import clamav
import metrics
import scan
from scan import str_to_bool
from common import AV_DEFINITION_S3_BUCKET
from common import AV_DEFINITION_S3_PREFIX
from common import AV_DELETE_INFECTED_FILES
from common import AV_SCAN_QUEUE_URL
from common import AV_STATUS_SNS_ARN
from common import AV_STATUS_INFECTED
from common import create_dir
from common import get_timestamp

# Connection pool sized for parallel post-scan I/O
BOTO_CONFIG = Config(max_pool_connections=20)
POST_PROCESS_EXECUTOR = ThreadPoolExecutor(max_workers=5)


def _run_s3_tagging(s3_client, s3_object, scan_result, scan_signature, timestamp):
    """S3 put_object_tagging task. Logs errors without raising."""
    try:
        scan.set_av_tags(s3_client, s3_object, scan_result, scan_signature, timestamp)
    except Exception as e:
        print(
            "Post-processing S3 tagging error for %s/%s: %s"
            % (s3_object.bucket_name, s3_object.key, e),
            file=sys.stderr,
            flush=True,
        )


def _run_sns_publish(sns_client, s3_object, scan_result, scan_signature, timestamp):
    """SNS publish task. Logs errors without raising."""
    try:
        if AV_STATUS_SNS_ARN not in [None, ""]:
            scan.sns_scan_results(
                sns_client,
                s3_object,
                AV_STATUS_SNS_ARN,
                scan_result,
                scan_signature,
                timestamp,
            )
    except Exception as e:
        print(
            "Post-processing SNS publish error for %s/%s: %s"
            % (s3_object.bucket_name, s3_object.key, e),
            file=sys.stderr,
            flush=True,
        )


def _run_sqs_delete(sqs_client, receipt_handle):
    """SQS delete_message task. Logs errors without raising."""
    try:
        sqs_client.delete_message(
            QueueUrl=AV_SCAN_QUEUE_URL,
            ReceiptHandle=receipt_handle,
        )
    except Exception as e:
        print(
            "Post-processing SQS delete_message error: %s" % e,
            file=sys.stderr,
            flush=True,
        )


def run_post_processing_tasks(
    s3_object,
    receipt_handle,
    scan_result,
    scan_signature,
    *,
    s3_client=None,
    sns_client=None,
    sqs_client=None,
):
    """
    Run S3 tagging, SNS publish, and SQS delete in parallel.
    Waits for all tasks to finish before returning.
    """
    s3_client = s3_client or boto3.client("s3", config=BOTO_CONFIG)
    sns_client = sns_client or boto3.client("sns", config=BOTO_CONFIG)
    sqs_client = sqs_client or boto3.client("sqs", config=BOTO_CONFIG)
    timestamp = get_timestamp()

    futures = [
        POST_PROCESS_EXECUTOR.submit(
            _run_s3_tagging,
            s3_client,
            s3_object,
            scan_result,
            scan_signature,
            timestamp,
        ),
        POST_PROCESS_EXECUTOR.submit(
            _run_sns_publish,
            sns_client,
            s3_object,
            scan_result,
            scan_signature,
            timestamp,
        ),
        POST_PROCESS_EXECUTOR.submit(_run_sqs_delete, sqs_client, receipt_handle),
    ]
    wait(futures)


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
    sqs = boto3.client("sqs", config=BOTO_CONFIG)
    s3 = boto3.resource("s3", config=BOTO_CONFIG)
    s3_client = boto3.client("s3", config=BOTO_CONFIG)
    sns_client = boto3.client("sns", config=BOTO_CONFIG)

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
    # Throughput: moving average of last 10 files. Reset deque after 5 min idle.
    processing_times = deque(maxlen=10)
    IDLE_RESET_SECONDS = 300
    files_processed = 0
    while True:
        try:
            receipt_handle, s3_object, file_path = ready_queue.get(
                timeout=IDLE_RESET_SECONDS
            )
        except queue.Empty:
            if processing_times:
                print(
                    "[Throughput] idle %d min, resetting metric window"
                    % (IDLE_RESET_SECONDS / 60),
                    flush=True,
                )
                processing_times.clear()
            files_processed = 0
            continue
        iter_start = time.time()
        try:
            scan_result, scan_signature = scan.scan_one_object_from_path(
                s3_object,
                file_path,
                s3_resource=s3,
                s3_client=s3_client,
                sns_client=sns_client,
                skip_post_processing=True,
            )
            metrics.send(
                env=os.getenv("ENV", ""),
                bucket=s3_object.bucket_name,
                key=s3_object.key,
                status=scan_result,
            )
            run_post_processing_tasks(
                s3_object,
                receipt_handle,
                scan_result,
                scan_signature,
                s3_client=s3_client,
                sns_client=sns_client,
                sqs_client=sqs,
            )
            processing_times.append(time.time() - iter_start)
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
            last_file_time = time.time() - iter_start
            avg_duration = (
                sum(processing_times) / len(processing_times)
                if processing_times
                else last_file_time
            )
            moving_fps = 1.0 / avg_duration if avg_duration > 0 else 0
            print(
                "[Throughput] file %d: %.2fs | Avg (last %d): %.2fs | %.1f files/sec"
                % (
                    files_processed,
                    last_file_time,
                    len(processing_times),
                    avg_duration,
                    moving_fps,
                ),
                flush=True,
            )


if __name__ == "__main__":
    run()
