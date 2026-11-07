# MediCare HMS: sample AWS infrastructure. Scanned by Checkov, never applied (see ../README.md).

data "aws_caller_identity" "current" {}

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  name = "medicare-${var.environment}"
}

# --- Encryption key --------------------------------------------------------------

data "aws_iam_policy_document" "kms" {
  statement {
    sid       = "AccountAdministration"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }
}

resource "aws_kms_key" "medicare" {
  description             = "Encrypts MediCare data at rest (RDS, S3, logs)"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.kms.json
}

# --- Network -----------------------------------------------------------------------

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = local.name }
}

resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id
  # No ingress/egress rules: the default security group denies all traffic.
}

resource "aws_subnet" "private" {
  count                   = 2
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = false
  tags                    = { Name = "${local.name}-private-${count.index}" }
}

resource "aws_flow_log" "vpc" {
  vpc_id               = aws_vpc.main.id
  traffic_type         = "ALL"
  log_destination_type = "s3"
  log_destination      = aws_s3_bucket.logs.arn
}

resource "aws_security_group" "app" {
  name        = "${local.name}-app"
  description = "MediCare application tasks"
  vpc_id      = aws_vpc.main.id
}

resource "aws_security_group" "db" {
  name        = "${local.name}-db"
  description = "MediCare PostgreSQL, reachable only from the application"
  vpc_id      = aws_vpc.main.id
}

resource "aws_vpc_security_group_ingress_rule" "db_from_app" {
  security_group_id            = aws_security_group.db.id
  description                  = "PostgreSQL from application security group only"
  referenced_security_group_id = aws_security_group.app.id
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
}

resource "aws_vpc_security_group_egress_rule" "app_to_db" {
  security_group_id            = aws_security_group.app.id
  description                  = "Application to PostgreSQL"
  referenced_security_group_id = aws_security_group.db.id
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
}

# --- Database ----------------------------------------------------------------------

resource "aws_db_subnet_group" "medicare" {
  name       = local.name
  subnet_ids = aws_subnet.private[*].id
}

resource "aws_db_parameter_group" "postgres16" {
  name   = "${local.name}-pg16"
  family = "postgres16"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }

  parameter {
    name  = "log_connections"
    value = "1"
  }
}

data "aws_iam_policy_document" "rds_monitoring_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["monitoring.rds.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "rds_monitoring" {
  name               = "${local.name}-rds-monitoring"
  assume_role_policy = data.aws_iam_policy_document.rds_monitoring_assume.json
}

resource "aws_iam_role_policy_attachment" "rds_monitoring" {
  role       = aws_iam_role.rds_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

resource "aws_db_instance" "medicare" {
  identifier     = local.name
  engine         = "postgres"
  engine_version = "16"
  instance_class = var.db_instance_class
  db_name        = "medicare"
  username       = "medicare"

  # Credentials are generated and rotated by AWS Secrets Manager: no password in code.
  manage_master_user_password = true

  allocated_storage = 20
  storage_encrypted = true
  kms_key_id        = aws_kms_key.medicare.arn

  db_subnet_group_name   = aws_db_subnet_group.medicare.name
  vpc_security_group_ids = [aws_security_group.db.id]
  parameter_group_name   = aws_db_parameter_group.postgres16.name
  publicly_accessible    = false
  multi_az               = true

  iam_database_authentication_enabled = true
  auto_minor_version_upgrade          = true
  deletion_protection                 = true
  backup_retention_period             = 7
  copy_tags_to_snapshot               = true
  skip_final_snapshot                 = false
  final_snapshot_identifier           = "${local.name}-final"

  enabled_cloudwatch_logs_exports       = ["postgresql", "upgrade"]
  monitoring_interval                   = 60
  monitoring_role_arn                   = aws_iam_role.rds_monitoring.arn
  performance_insights_enabled          = true
  performance_insights_kms_key_id       = aws_kms_key.medicare.arn
  performance_insights_retention_period = 7
}

# --- Storage -----------------------------------------------------------------------

resource "aws_s3_bucket" "logs" {
  bucket = "${local.name}-logs"
}

resource "aws_s3_bucket" "imaging" {
  bucket = "${local.name}-imaging"
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "imaging" {
  bucket                  = aws_s3_bucket.imaging.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.medicare.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "imaging" {
  bucket = aws_s3_bucket.imaging.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.medicare.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_versioning" "imaging" {
  bucket = aws_s3_bucket.imaging.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_logging" "imaging" {
  bucket        = aws_s3_bucket.imaging.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "s3-access/imaging/"
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    id     = "expire-old-logs"
    status = "Enabled"
    filter {}
    expiration {
      days = 400
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "imaging" {
  bucket = aws_s3_bucket.imaging.id
  rule {
    id     = "archive-old-imaging"
    status = "Enabled"
    filter {}
    transition {
      days          = 365
      storage_class = "GLACIER"
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

data "aws_iam_policy_document" "imaging_tls_only" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.imaging.arn, "${aws_s3_bucket.imaging.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "imaging" {
  bucket = aws_s3_bucket.imaging.id
  policy = data.aws_iam_policy_document.imaging_tls_only.json
}
