# Cloud_Project
# LeakBlocker (AWS) — A simple DLP system
LeakBlocker is a simple serverless security tool that scans files uploaded to an **S3 uploads bucket**.  
If a file contains risky patterns (like **AWS access key IDs**, **private keys**, or **password=...**), it:
- copies the file to a **quarantine bucket**
- deletes it from the uploads bucket
- sends an **email alert** using **SNS**

## AWS Services Used
- **S3** (uploads bucket + quarantine bucket)
- **Lambda** (scanner/enforcement)
- **SNS** (email alerts)
- **IAM** (permissions)
- **CloudWatch Logs** (logs)

---

## Setup 

### 1) Create S3 buckets
Create two buckets :
- 'leakblocker-public-a'
- 'leakblocker-quarantine-b'

Enable:
- **Default encryption (SSE-S3)**
- **Block Public Access for the quarantine bucket** 

### 2) Create SNS topic + email
- SNS → Topics → Create topic → name: 'LeakBlockerAlerts'
- Create **Email subscription** and confirm it

### 3) Create Lambda function
- Lambda → Create function
- Name: 'LeakBlockerScanner' 
- Add environment variables:
  - 'QUARANTINE_BUCKET' = your quarantine bucket name
  - 'SNS_TOPIC_ARN' = your SNS topic ARN
- Paste the code from 'lambda_function.py' and **Deploy**

### 4) Give Lambda permissions
Attach the policy in 'iam-policy.json' to the Lambda execution role (S3 read/copy/delete/tag + SNS publish).

### 5) Connect S3 trigger
Uploads bucket → Properties → Event notifications:
- Event: **ObjectCreated (All)**
- Destination: **LeakBlockerScanner**

---

## Testing

### Test 1 (clean)
Upload 'notes.txt' with normal text → stays in uploads bucket, no email alert.

### Test 2 (leak)
Upload 'config.txt' containing:
'password=123456' or 'AKIA...'
→ moves to quarantine bucket + gets deleted from the uploads bucket + email alert.


## Logs
Lambda → Monitor → View logs in CloudWatch
