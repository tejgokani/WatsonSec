# WatsonSec fixture — intentionally insecure Terraform for Checkov adapter testing.
# DO NOT use in production.

# Checkov should flag: S3 bucket with no encryption, no versioning, public ACL
resource "aws_s3_bucket" "insecure_bucket" {
  bucket = "watsonsec-fixture-insecure"
  acl    = "public-read"   # CKV_AWS_20: S3 Bucket has an ACL defined which allows public READ access
}

# Checkov should flag: security group allows unrestricted ingress on all ports
resource "aws_security_group" "open_sg" {
  name = "watsonsec-fixture-open-sg"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # CKV_AWS_25: too permissive
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Checkov should flag: IAM policy with wildcard resource
resource "aws_iam_policy" "wildcard_policy" {
  name = "watsonsec-fixture-wildcard"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:*", "ec2:*"]
      Resource = "*"  # CKV_AWS_49: too permissive
    }]
  })
}

# Checkov should flag: RDS without encryption at rest
resource "aws_db_instance" "insecure_db" {
  identifier        = "watsonsec-fixture-db"
  engine            = "mysql"
  engine_version    = "8.0"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  username          = "admin"
  password          = "SuperSecretP@ssw0rd!"  # CKV_AWS_16: hardcoded credentials
  storage_encrypted = false                    # CKV_AWS_16: not encrypted
  skip_final_snapshot = true
}
