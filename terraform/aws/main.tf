# Insecure AWS Infrastructure Configuration

# S3 bucket without encryption
resource "aws_s3_bucket" "insecure_bucket" {
  bucket = "my-insecure-bucket-12345"
  
  # Missing encryption configuration
  # Missing versioning
  # Missing logging
}

# S3 bucket with public access
resource "aws_s3_bucket_public_access_block" "bad_public_access" {
  bucket = aws_s3_bucket.insecure_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# RDS instance without encryption
resource "aws_db_instance" "insecure_database" {
  identifier           = "insecure-db"
  engine              = "mysql"
  engine_version      = "5.7"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "admin"
  password            = "hardcoded-password-123"  # Hardcoded password!
  skip_final_snapshot = true
  
  # Missing encryption at rest
  storage_encrypted = false
  
  # Publicly accessible
  publicly_accessible = true
  
  # Missing backup configuration
  backup_retention_period = 0
}

# Security group allowing unrestricted access
resource "aws_security_group" "allow_all" {
  name        = "allow_all"
  description = "Allow all inbound traffic"

  ingress {
    description = "Allow all"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]  # Open to the world!
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# IAM policy with admin access
resource "aws_iam_policy" "admin_policy" {
  name = "admin-access"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = "*"
        Effect   = "Allow"
        Resource = "*"  # Too permissive!
      },
    ]
  })
}

# EC2 instance with hardcoded credentials
resource "aws_instance" "insecure_instance" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_class = "t2.micro"

  user_data = <<-EOF
              #!/bin/bash
              export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
              export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
              EOF

  # Missing encryption for EBS volumes
  # No monitoring enabled
  # Missing IAM role
  
  tags = {
    Name = "insecure-instance"
  }
}

# EBS volume without encryption
resource "aws_ebs_volume" "unencrypted" {
  availability_zone = "us-west-2a"
  size              = 40
  encrypted         = false  # Not encrypted!
}

# Elasticsearch domain without encryption
resource "aws_elasticsearch_domain" "insecure_es" {
  domain_name           = "insecure-es-domain"
  elasticsearch_version = "7.10"

  cluster_config {
    instance_type = "t3.small.elasticsearch"
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

  # Missing encryption at rest and in transit
  encrypt_at_rest {
    enabled = false
  }

  node_to_node_encryption {
    enabled = false
  }

  # Missing domain endpoint options (enforce HTTPS)
}

# CloudTrail without log file validation
resource "aws_cloudtrail" "insecure_trail" {
  name                          = "insecure-trail"
  s3_bucket_name                = aws_s3_bucket.insecure_bucket.id
  enable_log_file_validation    = false  # No integrity checking!
  
  # Missing encryption
  # Missing CloudWatch integration
}

# KMS key with overly permissive policy
resource "aws_kms_key" "insecure_key" {
  description             = "Insecure KMS key"
  deletion_window_in_days = 7
  enable_key_rotation     = false  # No rotation!

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Allow all"
        Effect = "Allow"
        Principal = {
          AWS = "*"  # Anyone can use this key!
        }
        Action   = "kms:*"
        Resource = "*"
      }
    ]
  })
}

# Lambda function with environment secrets
resource "aws_lambda_function" "insecure_lambda" {
  filename      = "lambda_function.zip"
  function_name = "insecure_lambda"
  role          = aws_iam_role.lambda_role.arn
  handler       = "index.handler"
  runtime       = "python3.9"

  environment {
    variables = {
      DB_PASSWORD = "SuperSecret123!"  # Hardcoded secret!
      API_KEY     = "sk_live_51HqL..."
    }
  }

  # Missing VPC configuration
  # Missing encryption
}

# API Gateway without authorization
resource "aws_api_gateway_rest_api" "insecure_api" {
  name        = "insecure-api"
  description = "API without proper authorization"
}

resource "aws_api_gateway_method" "insecure_method" {
  rest_api_id   = aws_api_gateway_rest_api.insecure_api.id
  resource_id   = aws_api_gateway_rest_api.insecure_api.root_resource_id
  http_method   = "ANY"
  authorization = "NONE"  # No authorization!
}
