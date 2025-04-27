terraform {
    required_providers {
    aws = {
        source = "hashicorp/aws"
        version = "5.96.0"
    }
    random = {
        source = "hashicorp/random"
        version = "~> 3.0"
    }
    }
}

provider "aws" {
    region = "us-east-1"
}

#########################
# VPC DAN SUBNET
#########################

resource "aws_vpc" "techno_vpc" {
    cidr_block           = "25.1.0.0/16"
    enable_dns_support   = true
    enable_dns_hostnames = true
    tags = {
        Name = "techno-imannuel"
    }
}

resource "aws_vpc_ipv6_cidr_block_association" "ipv6ass" {
    vpc_id = aws_vpc.techno_vpc.id
    assign_generated_ipv6_cidr_block = "true"
}

resource "aws_internet_gateway" "techno_igw" {
    vpc_id = aws_vpc.techno_vpc.id
    tags = {
    Name = "techno-igw"
    }
}

resource "aws_subnet" "techno_public_a" {
    vpc_id                  = aws_vpc.techno_vpc.id
    cidr_block              = "25.1.0.0/24"
    availability_zone       = "us-east-1a"
    map_public_ip_on_launch = true
    tags = {
    Name = "techno-public-subnet-a"
    }
}

resource "aws_subnet" "techno_public_b" {
    vpc_id                  = aws_vpc.techno_vpc.id
    cidr_block              = "25.1.2.0/24"
    availability_zone       = "us-east-1b"
    map_public_ip_on_launch = true
    tags = {
    Name = "techno-public-subnet-b"
    }
}

resource "aws_subnet" "techno_private_a" {
    vpc_id            = aws_vpc.techno_vpc.id
    cidr_block        = "25.1.1.0/24"
    availability_zone = "us-east-1a"
    tags = {
    Name = "techno-private-subnet-a"
    }
}

resource "aws_subnet" "techno_private_b" {
    vpc_id            = aws_vpc.techno_vpc.id
    cidr_block        = "25.1.3.0/24"
    availability_zone = "us-east-1b"
    tags = {
    Name = "techno-private-subnet-b"
    }
}

resource "aws_eip" "techno_nat_eip" {
    vpc = true
}

resource "aws_nat_gateway" "techno_nat" {
    allocation_id = aws_eip.techno_nat_eip.id
    subnet_id     = aws_subnet.techno_public_a.id
    tags = {
    Name = "techno-nat"
    }
}

resource "aws_route_table" "techno_public_rt" {
    vpc_id = aws_vpc.techno_vpc.id

    route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.techno_igw.id
    }

    tags = {
        Name = "Techno-public"
    }
}

resource "aws_route_table_association" "techno_public_assoc_a" {
    subnet_id      = aws_subnet.techno_public_a.id
    route_table_id = aws_route_table.techno_public_rt.id
}

resource "aws_route_table_association" "techno_public_assoc_b" {
    subnet_id      = aws_subnet.techno_public_b.id
    route_table_id = aws_route_table.techno_public_rt.id
}

resource "aws_route_table" "techno_private_rt" {
    vpc_id = aws_vpc.techno_vpc.id

    route {
        cidr_block     = "0.0.0.0/0"
        nat_gateway_id = aws_nat_gateway.techno_nat.id
    }

    tags = {
        Name = "Techno-private"
    }
}

resource "aws_route_table_association" "techno_private_assoc_a" {
    subnet_id      = aws_subnet.techno_private_a.id
    route_table_id = aws_route_table.techno_private_rt.id
}

resource "aws_route_table_association" "techno_private_assoc_b" {
    subnet_id      = aws_subnet.techno_private_b.id
    route_table_id = aws_route_table.techno_private_rt.id
}

#########################
# SECURITY GROUPS
#########################

resource "aws_security_group" "techno_sg_app" {
    name   = "techno-sg-app"
    vpc_id = aws_vpc.techno_vpc.id

    ingress {
        from_port   = 2000
        to_port     = 2000
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
    }

    egress {
        from_port   = 0
        to_port     = 0
        protocol    = "-1"
        cidr_blocks = ["0.0.0.0/0"]
    }

    tags = {
        Name = "techno-sg-apps"
    }
}

resource "aws_security_group" "techno_sg_alb" {
    name   = "techno-sg-alb"
    vpc_id = aws_vpc.techno_vpc.id

    ingress {
        from_port   = 80
        to_port     = 80
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
    }

    ingress {
        from_port   = 443
        to_port     = 443
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
    }

    egress {
        from_port   = 0
        to_port     = 0
        protocol    = "-1"
        cidr_blocks = ["0.0.0.0/0"]
    }

    tags = {
        Name = "techno-sg-lb"
    }
}

#########################
# S3, DYNAMODB, KINESIS
#########################
resource "random_string" "suffix" {
    length = 1
    special = false
    upper = false
}

resource "aws_s3_bucket" "technoinput" {
    bucket = "technoinput-banyumas-jeremi${random_string.suffix.result}"
    tags = {
    Name = "technoinput-banyumas-jeremi"
    }
}

resource "aws_s3_bucket_ownership_controls" "owncontrol" {
    bucket = aws_s3_bucket.technoinput.id
    rule {
        object_ownership = "BucketOwnerPreferred"
    }
}

resource "aws_s3_bucket_public_access_block" "accesspub" {
    bucket = aws_s3_bucket.technoinput.id
    block_public_acls = false
    block_public_policy = false
    ignore_public_acls = false
    restrict_public_buckets = false
}

resource "aws_s3_bucket_acl" "acl" {
    depends_on = [ 
        aws_s3_bucket_ownership_controls.owncontrol,
        aws_s3_bucket_public_access_block.accesspub,
        ]
    bucket = aws_s3_bucket.technoinput.id
    acl = "public-read-write"
}


resource "aws_s3_bucket" "technooutput" {
    bucket = "technooutput-banyumas-jeremi${random_string.suffix.result}"
    tags = {
    Name = "technoinput-banyumas-jeremi"
    }
}

resource "aws_s3_bucket_ownership_controls" "owncontrol2" {
    bucket = aws_s3_bucket.technooutput.id
    rule {
        object_ownership = "BucketOwnerPreferred"
    }
}

resource "aws_s3_bucket_public_access_block" "accesspub2" {
    bucket = aws_s3_bucket.technooutput.id
    block_public_acls = false
    block_public_policy = false
    ignore_public_acls = false
    restrict_public_buckets = false
}

resource "aws_s3_bucket_acl" "acl2" {
    depends_on = [ 
        aws_s3_bucket_ownership_controls.owncontrol2,
        aws_s3_bucket_public_access_block.accesspub2,
        ]
    bucket = aws_s3_bucket.technooutput.id
    acl = "public-read-write"
}
resource "aws_dynamodb_table" "dynamodb" {
    name         = "Tokens"
    billing_mode = "PAY_PER_REQUEST"
    hash_key     = "token"
    range_key = "expired"

    attribute {
        name = "token"
        type = "S"
    }

    attribute {
        name = "expired"
        type = "N"
    }

}

resource "aws_kinesis_stream" "techno_stream" {
    name        = "techno-stream"
    stream_mode_details {
        stream_mode = "ON_DEMAND"
    }
    tags = {
        Name = "techno-stream"
    }
}

#########################
# AWS GLUE
#########################

resource "aws_glue_catalog_database" "techno_glue_db" {
    name = "techno_glue_db"
}

resource "aws_glue_crawler" "techno_crawler" {
    name          = "techno-crawler"
    role          = "arn:aws:iam::767398040510:role/LabRole"
    database_name = aws_glue_catalog_database.techno_glue_db.name
    
    s3_target {
        path = "s3://${aws_s3_bucket.technooutput.bucket}/input-data"
    }
}

#########################
# API GATEWAY & SNS
#########################


resource "aws_sns_topic" "sns" {
    name = "techno-alerts"
}

resource "aws_sns_topic_subscription" "subscription" {
    topic_arn = aws_sns_topic.sns.arn
    protocol = "email"
    endpoint = "imannueljeremi@gmail.com"
}

# Ambil IAM Role yang sudah ada
data "aws_iam_role" "existing_lab_role" {
    name = "LabRole"
}

# Archive file lambda dari luar folder terraform
data "archive_file" "get" {
    type        = "zip"
    source_file = "${path.module}/../lambda_get/lambda_function.py"
    output_path = "${path.module}/lambda_get.zip"
}

# Deploy Lambda function pakai role existing
resource "aws_lambda_function" "getlambda" {
    function_name    = "lambda-get"
    role             = data.aws_iam_role.existing_lab_role.arn
    handler          = "lambda_function.lambda_handler"
    runtime          = "python3.13"

    filename         = data.archive_file.get.output_path
    source_code_hash = data.archive_file.get.output_base64sha256

}

data "archive_file" "post" {
    type        = "zip"
    source_file = "${path.module}/../lambda_post/lambda_function.py"
    output_path = "${path.module}/lambda_post.zip"
}

# Deploy Lambda function pakai role existing
resource "aws_lambda_function" "postlambda" {
    function_name    = "lambda-post"
    role             = data.aws_iam_role.existing_lab_role.arn
    handler          = "lambda_function.lambda_handler"
    runtime          = "python3.13"

    filename         = data.archive_file.post.output_path
    source_code_hash = data.archive_file.post.output_base64sha256

}

data "archive_file" "lambda_s3" {
    type        = "zip"
    source_file = "${path.module}/../lambda_s3/lambda_function.py"
    output_path = "${path.module}/lambda_s3.zip"
}

# Deploy Lambda function pakai role existing
resource "aws_lambda_function" "s3lambda" {
    function_name    = "lambda-s3"
    role             = data.aws_iam_role.existing_lab_role.arn
    handler          = "lambda_function.lambda_handler"
    runtime          = "python3.13"

    filename         = data.archive_file.lambda_s3.output_path
    source_code_hash = data.archive_file.lambda_s3.output_base64sha256

}

resource "aws_api_gateway_rest_api" "api" {
    name = "techno-api"
}

resource "aws_api_gateway_resource" "resource" {
    path_part   = "techno"
    parent_id   = aws_api_gateway_rest_api.api.root_resource_id
    rest_api_id = aws_api_gateway_rest_api.api.id
}
# Get Method
resource "aws_api_gateway_method" "get_method" {
    rest_api_id   = aws_api_gateway_rest_api.api.id
    resource_id   = aws_api_gateway_resource.resource.id
    http_method   = "GET"
    authorization = "NONE"
}

resource "aws_api_gateway_integration" "get_integration" {
    rest_api_id             = aws_api_gateway_rest_api.api.id
    resource_id             = aws_api_gateway_resource.resource.id
    http_method             = aws_api_gateway_method.get_method.http_method
    integration_http_method = "POST"
    type                    = "AWS_PROXY"
    uri                     = aws_lambda_function.getlambda.invoke_arn
}

resource "aws_lambda_permission" "get_premission" {
    statement_id  = "AllowAPIGatewayInvoke"
    action        = "lambda:InvokeFunction"
    function_name = aws_lambda_function.getlambda.function_name
    principal     = "apigateway.amazonaws.com"

    source_arn = "${aws_api_gateway_rest_api.api.execution_arn}//"
}

# Post Method
resource "aws_api_gateway_method" "post_method" {
    rest_api_id   = aws_api_gateway_rest_api.api.id
    resource_id   = aws_api_gateway_resource.resource.id
    http_method   = "POST"
    authorization = "NONE"
}

resource "aws_api_gateway_integration" "get_integration_2" {
    rest_api_id             = aws_api_gateway_rest_api.api.id
    resource_id             = aws_api_gateway_resource.resource.id
    http_method             = aws_api_gateway_method.post_method.http_method
    integration_http_method = "POST"
    type                    = "AWS_PROXY"
    uri                     = aws_lambda_function.postlambda.invoke_arn
}

resource "aws_lambda_permission" "get_premission_2" {
    statement_id  = "AllowAPIGatewayInvoke"
    action        = "lambda:InvokeFunction"
    function_name = aws_lambda_function.postlambda.function_name
    principal     = "apigateway.amazonaws.com"

    source_arn = "${aws_api_gateway_rest_api.api.execution_arn}//"
}

