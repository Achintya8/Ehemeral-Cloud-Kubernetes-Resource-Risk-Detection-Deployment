terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    http = {
      source  = "hashicorp/http"
      version = "~> 3.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "ephemeral-security-test"
      Environment = "free-tier"
      CostControl = "strict"
    }
  }
}

# ─── COST CONTROL: USE DEFAULT VPC (FREE) ───────────────────────────────────
data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

data "aws_caller_identity" "current" {}

data "http" "my_ip" {
  url = "https://checkip.amazonaws.com"
}

# ─── FREE TIER: SINGLE EC2 t3.micro ─────────────────────────────────────────
resource "aws_instance" "test_runner" {
  ami                    = data.aws_ami.amazon_linux_2023.id
  instance_type          = "t3.micro"
  subnet_id              = data.aws_subnets.default.ids[0]
  vpc_security_group_ids = [aws_security_group.test.id]
  iam_instance_profile   = aws_iam_instance_profile.test.name

  user_data = base64encode(format(<<-EOF
    #!/bin/bash
    SHUTDOWN_MINUTES=%d
    dnf install -y at 2>/dev/null || yum install -y at 2>/dev/null
    dnf install -y amazon-cloudwatch-agent 2>/dev/null || yum install -y amazon-cloudwatch-agent 2>/dev/null
    if command -v at &> /dev/null; then
      echo "shutdown -h now" | at now + $SHUTDOWN_MINUTES minutes
    else
      (sleep $((SHUTDOWN_MINUTES * 60)) && shutdown -h now) &
    fi
    echo "[$(date)] Auto-shutdown in $SHUTDOWN_MINUTES min" > /var/log/auto-shutdown.log
  EOF
  , var.shutdown_minutes))

  root_block_device {
    volume_size           = 30
    volume_type           = "gp3"
    delete_on_termination = true
  }

  tags = {
    Name         = "ephemeral-test-runner"
    AutoShutdown = "true"
    Schedule     = "testing-only"
  }

  lifecycle {
    prevent_destroy = false
  }
}

# ─── FREE TIER: LAMBDA FUNCTION ─────────────────────────────────────────────
resource "aws_lambda_function" "event_generator" {
  function_name = "ephemeral-event-generator"
  role          = aws_iam_role.lambda.arn
  handler       = "index.handler"
  runtime       = "python3.12"
  timeout       = 30
  memory_size   = 128

  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      LOG_LEVEL = "INFO"
    }
  }

  tags = {
    Purpose = "security-pipeline-test"
  }
}

# ─── FREE TIER: S3 BUCKET FOR CLOUDTRAIL ────────────────────────────────────
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "ephemeral-ct-logs-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    id     = "expire-old-logs"
    status = "Enabled"

    filter {}

    expiration {
      days = 1
    }

    noncurrent_version_expiration {
      noncurrent_days = 1
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail_logs.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ─── FREE TIER: CLOUDTRAIL (1st COPY FREE) ──────────────────────────────────
resource "aws_cloudtrail" "test" {
  name                  = "ephemeral-test-trail"
  s3_bucket_name        = aws_s3_bucket.cloudtrail_logs.id
  is_multi_region_trail = false
  enable_logging        = true

  event_selector {
    read_write_type           = "WriteOnly"
    include_management_events = true
    exclude_management_event_sources = ["kms.amazonaws.com"]
  }

  depends_on = [
    aws_s3_bucket_policy.cloudtrail,
    aws_s3_bucket_public_access_block.cloudtrail
  ]

  tags = {
    Purpose = "free-tier-testing"
  }
}

# ─── FREE TIER: CLOUDWATCH LOGS ─────────────────────────────────────────────
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/ephemeral-event-generator"
  retention_in_days = 1
}

# ─── SECURITY GROUP ───────────────────────────────────────────────────────────
resource "aws_security_group" "test" {
  name_prefix = "ephemeral-test-"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["${chomp(data.http.my_ip.response_body)}/32"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "ephemeral-test-sg"
  }
}

# ─── IAM ROLES ───────────────────────────────────────────────────────────────
resource "aws_iam_role" "lambda" {
  name = "ephemeral-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

# FIX: Corrected policy ARN - was missing 'S' in AWSLambdaBasicExecutionRole
resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role" "ec2" {
  name = "ephemeral-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "ec2_minimal" {
  name = "minimal-policy"
  role = aws_iam_role.ec2.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "test" {
  name = "ephemeral-test-profile"
  role = aws_iam_role.ec2.name
}

# ─── LAMBDA FUNCTION CODE ───────────────────────────────────────────────────
data "archive_file" "lambda_zip" {
  type        = "zip"
  output_path = "${path.module}/lambda.zip"

  source {
    filename = "index.py"
    content  = <<-EOF
      import json
      import boto3
      import random
      import os
      import datetime

      def handler(event, context):
          actions = [
              "CreateInstance", "DeleteInstance", "ModifyInstance",
              "CreateUser", "DeleteUser", "AssumeRole",
              "PutObject", "GetObject", "DeleteObject",
              "CreateAccessKey", "DeleteAccessKey",
              "AttachRolePolicy", "DetachRolePolicy"
          ]

          event_data = {
              "eventTime": datetime.datetime.utcnow().isoformat() + "Z",
              "eventSource": random.choice([
                  "ec2.amazonaws.com", 
                  "iam.amazonaws.com", 
                  "s3.amazonaws.com",
                  "lambda.amazonaws.com"
              ]),
              "eventName": random.choice(actions),
              "awsRegion": os.environ.get('AWS_REGION', 'us-east-1'),
              "sourceIPAddress": "10.0.0." + str(random.randint(1, 254)),
              "userAgent": "ephemeral-test-script/1.0",
              "requestParameters": {
                  "instanceType": random.choice(["t3.micro", "t3.small", "t2.micro"]),
                  "ttl": random.randint(60, 3600),
                  "ephemeral": True
              },
              "responseElements": {
                  "status": "success"
              }
          }

          print(json.dumps(event_data))

          return {
              'statusCode': 200,
              'body': json.dumps({
                  'message': 'Event generated',
                  'event': event_data,
                  'timestamp': datetime.datetime.utcnow().isoformat()
              })
          }
      EOF
  }
}

# ─── DATA SOURCES ───────────────────────────────────────────────────────────
data "aws_ami" "amazon_linux_2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}

# ─── OUTPUTS ────────────────────────────────────────────────────────────────
output "ec2_instance_id" {
  value = aws_instance.test_runner.id
}

output "ec2_public_ip" {
  value = aws_instance.test_runner.public_ip
}

output "lambda_function_name" {
  value = aws_lambda_function.event_generator.function_name
}

output "cloudtrail_name" {
  value = aws_cloudtrail.test.name
}

output "s3_bucket_name" {
  value = aws_s3_bucket.cloudtrail_logs.id
}

output "account_id" {
  value = data.aws_caller_identity.current.account_id
}