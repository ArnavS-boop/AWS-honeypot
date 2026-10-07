terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}

locals {
  artifact_files = setsubtract(
    fileset("${path.module}/scripts", "**/*"),
    fileset("${path.module}/scripts", "**/*.pyc")
  )

  decoy_scripts = setsubtract(
    local.artifact_files,
    toset(["captor.py", "captor-supervisor.sh", "captor-init.sh.tftpl"])
  )

  kafka_bootstrap_servers = var.deployment_target == "aws" ? aws_msk_cluster.honeypot.bootstrap_brokers_tls : aws_msk_cluster.honeypot.bootstrap_brokers
  kafka_security_protocol = var.deployment_target == "aws" ? "SSL" : "PLAINTEXT"
  s3_endpoint             = var.deployment_target == "aws" ? "" : "http://localhost.localstack.cloud:4566"
}
provider "aws" {
  region = "us-east-1"
}

variable "deployment_target" {
  type    = string
  default = "localstack"

  validation {
    condition     = contains(["aws", "localstack"], var.deployment_target)
    error_message = "deployment_target must be aws or localstack."
  }
}

variable "kafka_cluster_name" {
  type    = string
  default = "honeypot-cluster"
}

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

resource "aws_security_group" "kafka" {
  name_prefix = "${var.kafka_cluster_name}-"
  description = "Kafka access for the honeypot instances"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    from_port   = 9092
    to_port     = 9098
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.default.cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_kms_key" "kafka" {
  description = "MSK encryption key for the honeypot cluster"
}

resource "aws_msk_cluster" "honeypot" {
  cluster_name           = var.kafka_cluster_name
  kafka_version          = "3.6.0"
  number_of_broker_nodes = 3

  broker_node_group_info {
    instance_type   = "kafka.t3.small"
    client_subnets  = slice(sort(data.aws_subnets.default.ids), 0, 3)
    security_groups = [aws_security_group.kafka.id]

    storage_info {
      ebs_storage_info {
        volume_size = 100
      }
    }
  }

  client_authentication {
    unauthenticated = true
  }

  encryption_info {
    encryption_at_rest_kms_key_arn = aws_kms_key.kafka.arn

    encryption_in_transit {
      client_broker = var.deployment_target == "aws" ? "TLS" : "PLAINTEXT"
      in_cluster    = true
    }
  }
}

resource "aws_s3_bucket" "decoy_artifacts" {
  bucket = "honeypot-decoy-artifacts"
}

resource "aws_iam_role" "captor" {
  name = "${var.kafka_cluster_name}-captor"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "captor_s3" {
  role = aws_iam_role.captor.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:PutObject"]
      Resource = "${aws_s3_bucket.decoy_artifacts.arn}/*"
    }]
  })
}

resource "aws_iam_instance_profile" "captor" {
  name = "${var.kafka_cluster_name}-captor"
  role = aws_iam_role.captor.name
}

resource "aws_iam_role" "decoy" {
  name = "${var.kafka_cluster_name}-decoy"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "decoy_s3" {
  role = aws_iam_role.decoy.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "${aws_s3_bucket.decoy_artifacts.arn}/*"
      },
      {
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = aws_s3_bucket.decoy_artifacts.arn
      }
    ]
  })
}

resource "aws_iam_instance_profile" "decoy" {
  name = "${var.kafka_cluster_name}-decoy"
  role = aws_iam_role.decoy.name
}

resource "aws_sns_topic" "alerts" {
  name = "${var.kafka_cluster_name}-alerts"
}

resource "aws_iam_role" "orchestrator" {
  name = "${var.kafka_cluster_name}-orchestrator"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "orchestrator_s3" {
  role = aws_iam_role.orchestrator.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:ListBucket", "s3:PutObject"]
      Resource = [aws_s3_bucket.decoy_artifacts.arn, "${aws_s3_bucket.decoy_artifacts.arn}/*"]
    }]
  })
}

resource "aws_iam_instance_profile" "orchestrator" {
  name = "${var.kafka_cluster_name}-orchestrator"
  role = aws_iam_role.orchestrator.name
}

resource "aws_iam_role" "risk_assessment" {
  name = "${var.kafka_cluster_name}-risk-assessment"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "risk_assessment" {
  role = aws_iam_role.risk_assessment.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:ListBucket"]
        Resource = [aws_s3_bucket.decoy_artifacts.arn, "${aws_s3_bucket.decoy_artifacts.arn}/*"]
      },
      {
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.alerts.arn
      }
    ]
  })
}

resource "aws_iam_instance_profile" "risk_assessment" {
  name = "${var.kafka_cluster_name}-risk-assessment"
  role = aws_iam_role.risk_assessment.name
}

resource "aws_s3_object" "decoy_artifacts" {
  for_each = local.artifact_files

  bucket = aws_s3_bucket.decoy_artifacts.id
  key    = "decoy/${each.value}"

  content_base64 = base64encode(
    replace(
      file("${path.module}/scripts/${each.value}"),
      "\r\n",
      "\n"
    )
  )
}

resource "aws_instance" "decoy" {
  ami                  = "ami-61ad6e59d7b0"
  instance_type        = "t3.micro"
  iam_instance_profile = aws_iam_instance_profile.decoy.name

  user_data = replace(
    templatefile(
      "${path.module}/scripts/decoy-init.sh.tftpl",
      {
        bucket_name             = aws_s3_bucket.decoy_artifacts.id
        kafka_bootstrap_servers = local.kafka_bootstrap_servers
        kafka_security_protocol = local.kafka_security_protocol
        kafka_localstack_mode   = var.deployment_target == "localstack"
        s3_endpoint             = local.s3_endpoint

        # Force user_data to change whenever anything in scripts/
        # changes, so user_data_replace_on_change actually works.
        scripts_hash = sha256(join(
          "",
          [
            for file in sort(local.decoy_scripts) :
            filesha256("${path.module}/scripts/${file}")
          ]
        ))
      }
    ),
    "\r\n",
    "\n"
  )

  depends_on = [
    aws_s3_object.decoy_artifacts,
    aws_msk_cluster.honeypot,
    aws_iam_role_policy.decoy_s3
  ]

  user_data_replace_on_change = true

  tags = {
    Name = "app-server-01"
    Role = "decoy"
  }
}

resource "aws_instance" "captor" {
  ami                  = "ami-61ad6e59d7b0"
  instance_type        = "t3.micro"
  iam_instance_profile = aws_iam_instance_profile.captor.name

  user_data = replace(
    templatefile(
      "${path.module}/scripts/captor-init.sh.tftpl",
      {
        bucket_name             = aws_s3_bucket.decoy_artifacts.id
        kafka_bootstrap_servers = local.kafka_bootstrap_servers
        kafka_security_protocol = local.kafka_security_protocol
        kafka_localstack_mode   = var.deployment_target == "localstack"
        s3_endpoint             = local.s3_endpoint

        scripts_hash = sha256(join(
          "",
          [
            for file in sort(local.artifact_files) :
            filesha256("${path.module}/scripts/${file}")
          ]
        ))
      }
    ),
    "\r\n",
    "\n"
  )

  depends_on = [
    aws_s3_object.decoy_artifacts,
    aws_msk_cluster.honeypot,
    aws_iam_role_policy.captor_s3
  ]

  user_data_replace_on_change = true

  tags = {
    Name = "honeypot-captor"
    Role = "captor"
  }
}

resource "aws_instance" "risk_assessment" {
  ami                  = "ami-61ad6e59d7b0"
  instance_type        = "t3.micro"
  iam_instance_profile = aws_iam_instance_profile.risk_assessment.name

  user_data = replace(
    templatefile(
      "${path.module}/scripts/analysis-init.sh.tftpl",
      {
        bucket_name           = aws_s3_bucket.decoy_artifacts.id
        s3_endpoint           = local.s3_endpoint
        kafka_localstack_mode = var.deployment_target == "localstack"
        service_script        = "risk_assessment.py"
        sns_topic_export      = "export SNS_TOPIC_ARN=\"${aws_sns_topic.alerts.arn}\""
        scripts_hash          = filesha256("${path.module}/scripts/risk_assessment.py")
      }
    ),
    "\r\n",
    "\n"
  )

  depends_on = [
    aws_s3_object.decoy_artifacts,
    aws_iam_role_policy.risk_assessment
  ]

  user_data_replace_on_change = true

  tags = {
    Name = "honeypot-risk-assessment"
    Role = "risk-assessment"
  }
}

resource "aws_instance" "orchestrator" {
  ami                  = "ami-61ad6e59d7b0"
  instance_type        = "t3.micro"
  iam_instance_profile = aws_iam_instance_profile.orchestrator.name

  user_data = replace(
    templatefile(
      "${path.module}/scripts/analysis-init.sh.tftpl",
      {
        bucket_name           = aws_s3_bucket.decoy_artifacts.id
        s3_endpoint           = local.s3_endpoint
        kafka_localstack_mode = var.deployment_target == "localstack"
        service_script        = "orchestrator.py"
        sns_topic_export      = ""
        scripts_hash          = filesha256("${path.module}/scripts/orchestrator.py")
      }
    ),
    "\r\n",
    "\n"
  )

  depends_on = [
    aws_s3_object.decoy_artifacts,
    aws_iam_role_policy.orchestrator_s3
  ]

  user_data_replace_on_change = true

  tags = {
    Name = "honeypot-orchestrator"
    Role = "orchestrator"
  }
}

output "kafka_cluster_arn" {
  value = aws_msk_cluster.honeypot.arn
}

output "kafka_bootstrap_servers" {
  value     = local.kafka_bootstrap_servers
  sensitive = true
}