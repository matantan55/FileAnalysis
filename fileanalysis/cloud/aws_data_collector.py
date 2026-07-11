"""AWS Malware Data Collector for Model Training."""

import csv
import logging
import os
import tempfile
import urllib.request
import urllib.error

import boto3

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

URLHAUS_CSV = "https://urlhaus.abuse.ch/downloads/csv_recent/"
MAX_DOWNLOADS_PER_RUN = 50
TIMEOUT_SEC = 10

def fetch_recent_urls() -> list[str]:
    """Fetch the latest active malware URLs from URLhaus."""
    logger.info(f"Fetching latest malware feeds from {URLHAUS_CSV}...")
    urls = []
    try:
        req = urllib.request.Request(URLHAUS_CSV, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=TIMEOUT_SEC) as response:
            text = response.read().decode('utf-8')
            
        # Parse CSV (format: id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter)
        lines = text.splitlines()
        reader = csv.reader(lines)
        for row in reader:
            if not row or row[0].startswith('#'):
                continue
            if len(row) > 3 and row[3] == "online":
                urls.append(row[2])
                
        logger.info(f"Found {len(urls)} online malware URLs.")
    except Exception as e:
        logger.error(f"Failed to fetch URLhaus feed: {e}")
        
    return urls

def download_and_upload_to_s3(urls: list[str], bucket: str):
    """Download malware payloads and stream them to S3."""
    s3 = boto3.client('s3')
    success_count = 0
    
    for url in urls:
        if success_count >= MAX_DOWNLOADS_PER_RUN:
            break
            
        try:
            logger.info(f"Downloading {url} ...")
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            
            with urllib.request.urlopen(req, timeout=TIMEOUT_SEC) as response:
                payload = response.read()
                
            if not payload:
                continue
                
            # Extract a safe filename from the URL or use a generic name
            filename = url.split('/')[-1]
            if not filename or '?' in filename:
                filename = f"payload_{success_count}.bin"
                
            s3_key = f"raw_samples/{filename}"
            
            # Upload to S3
            logger.info(f"Uploading to s3://{bucket}/{s3_key}...")
            s3.put_object(Bucket=bucket, Key=s3_key, Body=payload)
            success_count += 1
            
        except urllib.error.URLError as e:
            logger.warning(f"Failed to download {url}: {e.reason}")
        except Exception as e:
            logger.warning(f"Error processing {url}: {e}")
            
    logger.info(f"Successfully collected {success_count} new samples.")

def lambda_handler(event, context):
    """AWS Lambda entry point."""
    bucket = os.environ.get("AWS_S3_BUCKET")
    if not bucket:
        logger.error("AWS_S3_BUCKET environment variable not set.")
        return {"statusCode": 500, "body": "Configuration error"}
        
    urls = fetch_recent_urls()
    if not urls:
        return {"statusCode": 200, "body": "No online URLs found."}
        
    download_and_upload_to_s3(urls, bucket)
    
    return {"statusCode": 200, "body": "Collection completed successfully."}

if __name__ == "__main__":
    # Local/EC2 execution
    bucket = os.environ.get("AWS_S3_BUCKET")
    if not bucket:
        logger.error("AWS_S3_BUCKET is not set. Run with AWS_S3_BUCKET=my-bucket-name")
    else:
        urls = fetch_recent_urls()
        download_and_upload_to_s3(urls, bucket)
