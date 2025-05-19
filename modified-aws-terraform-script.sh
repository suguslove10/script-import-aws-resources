#!/bin/bash

# AWS Resource Discovery and Terraform Import Script
# This script:
# 1. Discovers AWS resources using AWS CLI
# 2. Creates Terraform configurations for discovered resources
# 3. Imports the resources using terraform import
# 4. Excludes default AWS resources (default VPCs, subnets, etc.)

set -e

# Color definitions for better output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner function
banner() {
  echo -e "\n${BLUE}=====================================================${NC}"
  echo -e "${GREEN}$1${NC}"
  echo -e "${BLUE}=====================================================${NC}\n"
}

# Check dependencies
check_dependencies() {
  banner "Checking dependencies"
  
  local dependencies=("aws" "jq" "terraform")
  local missing_deps=()
  
  for dep in "${dependencies[@]}"; do
    if ! command -v "$dep" &> /dev/null; then
      missing_deps+=("$dep")
    else
      echo -e "✅ ${GREEN}$dep is installed${NC}"
    fi
  done
  
  if [ ${#missing_deps[@]} -ne 0 ]; then
    echo -e "\n${RED}Missing dependencies:${NC}"
    for missing in "${missing_deps[@]}"; do
      echo -e "❌ ${RED}$missing${NC}"
    done
    exit 1
  fi
}

# Verify AWS credentials and connectivity
verify_aws_access() {
  banner "Verifying AWS access"
  
  echo "Checking AWS CLI configuration..."
  if ! aws sts get-caller-identity &> /dev/null; then
    echo -e "${RED}AWS CLI is not configured correctly or lacks permissions${NC}"
    echo "Please run 'aws configure' and ensure you have the necessary permissions"
    exit 1
  fi
  
  local account_id=$(aws sts get-caller-identity --query "Account" --output text)
  local username=$(aws sts get-caller-identity --query "Arn" --output text | cut -d '/' -f 2)
  local region=$(aws configure get region)
  
  echo -e "${GREEN}Successfully authenticated to AWS!${NC}"
  echo -e "Account ID: ${YELLOW}$account_id${NC}"
  echo -e "Username: ${YELLOW}$username${NC}"
  echo -e "Default Region: ${YELLOW}$region${NC}"

  # Set AWS_REGION environment variable
  export AWS_REGION="$region"
  export AWS_DEFAULT_REGION="$region"
}

# Select AWS region
select_region() {
  banner "Select AWS region"
  
  echo "Available regions:"
  aws ec2 describe-regions --query "Regions[].RegionName" --output text | tr '\t' '\n' | sort
  
  echo -e "\n${YELLOW}Enter the region to scan (default: $AWS_REGION):${NC}"
  read -r selected_region
  
  if [ -n "$selected_region" ]; then
    export AWS_REGION="$selected_region"
    export AWS_DEFAULT_REGION="$selected_region"
  fi
  
  echo -e "Using region: ${GREEN}$AWS_REGION${NC}"
}

# Create Terraform project structure
create_terraform_project() {
  banner "Creating Terraform project structure"
  
  # Create base directory
  BASE_DIR="terraform-aws-modules"
  mkdir -p "$BASE_DIR"
  cd "$BASE_DIR"
  
  # Create provider configuration
  cat > provider.tf << EOF
provider "aws" {
  region = "$AWS_REGION"
}

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}
EOF

  # Create modules directory structure
  mkdir -p modules/{ec2,vpc,s3,rds,iam,lambda,cloudwatch}
  
  echo -e "${GREEN}Created Terraform project structure in${NC} ${YELLOW}$BASE_DIR${NC}"
}

# Check if a VPC is default
is_default_vpc() {
  local vpc_id="$1"
  local is_default=$(aws ec2 describe-vpcs --vpc-ids "$vpc_id" --query 'Vpcs[0].IsDefault' --output text)
  
  if [ "$is_default" = "true" ]; then
    return 0  # true in bash return code (success)
  else
    return 1  # false in bash return code (failure)
  fi
}

# Discover VPC resources
discover_vpc_resources() {
  banner "Discovering VPC resources (excluding default VPCs)"
  
  echo "Scanning for VPCs..."
  
  # Get list of VPCs
  vpc_ids=$(aws ec2 describe-vpcs --query "Vpcs[].VpcId" --output text)
  
  if [ -z "$vpc_ids" ]; then
    echo -e "${YELLOW}No VPCs found${NC}"
    return
  fi
  
  echo -e "${GREEN}Found VPCs:${NC}"
  
  # Create VPC module directory
  mkdir -p modules/vpc
  cat > modules/vpc/main.tf << EOF
# VPC resources
EOF
  
  for vpc_id in $vpc_ids; do
    # Skip default VPCs
    if is_default_vpc "$vpc_id"; then
      echo -e " - ${YELLOW}$vpc_id (Default VPC - skipped)${NC}"
      continue
    fi
    
    echo " - $vpc_id"
    
    # Get VPC details
    vpc_name=$(aws ec2 describe-vpcs --vpc-ids "$vpc_id" --query 'Vpcs[0].Tags[?Key==`Name`].Value' --output text)
    cidr_block=$(aws ec2 describe-vpcs --vpc-ids "$vpc_id" --query 'Vpcs[0].CidrBlock' --output text)
    
    # If no name tag, use VPC ID as name
    if [ -z "$vpc_name" ] || [ "$vpc_name" = "None" ]; then
      vpc_name="vpc-$vpc_id"
    fi
    
    # Create VPC resource in Terraform
    cat >> modules/vpc/main.tf << EOF

resource "aws_vpc" "$vpc_name" {
  cidr_block           = "$cidr_block"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "$vpc_name"
  }
}
EOF
    
    # Add to import commands
    echo "terraform import 'module.vpc.aws_vpc.$vpc_name' '$vpc_id'" >> import_commands.sh
    
    # Discover subnets for this VPC
    echo "   Scanning for subnets in VPC $vpc_id..."
    subnet_ids=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=$vpc_id" --query "Subnets[].SubnetId" --output text)
    
    for subnet_id in $subnet_ids; do
      subnet_details=$(aws ec2 describe-subnets --subnet-ids "$subnet_id" --output json)
      subnet_name=$(echo "$subnet_details" | jq -r '.Subnets[0].Tags[] | select(.Key=="Name") | .Value' 2>/dev/null || echo "subnet-$subnet_id")
      subnet_cidr=$(echo "$subnet_details" | jq -r '.Subnets[0].CidrBlock')
      az=$(echo "$subnet_details" | jq -r '.Subnets[0].AvailabilityZone')
      
      echo "    - $subnet_id ($subnet_cidr in $az)"
      
      # Create subnet resource in Terraform
      cat >> modules/vpc/main.tf << EOF

resource "aws_subnet" "$subnet_name" {
  vpc_id                  = aws_vpc.$vpc_name.id
  cidr_block              = "$subnet_cidr"
  availability_zone       = "$az"
  map_public_ip_on_launch = true

  tags = {
    Name = "$subnet_name"
  }
}
EOF
      
      # Add to import commands
      echo "terraform import 'module.vpc.aws_subnet.$subnet_name' '$subnet_id'" >> import_commands.sh
    done
    
    # Discover security groups for this VPC
    echo "   Scanning for security groups in VPC $vpc_id..."
    sg_ids=$(aws ec2 describe-security-groups --filters "Name=vpc-id,Values=$vpc_id" --query "SecurityGroups[?GroupName!='default'].GroupId" --output text)
    
    for sg_id in $sg_ids; do
      sg_details=$(aws ec2 describe-security-groups --group-ids "$sg_id" --output json)
      sg_name=$(echo "$sg_details" | jq -r '.SecurityGroups[0].GroupName' | tr -d ' ' | tr '.' '_' | tr '-' '_')
      sg_description=$(echo "$sg_details" | jq -r '.SecurityGroups[0].Description')
      
      echo "    - $sg_id ($sg_name)"
      
      # Create security group resource in Terraform
      cat >> modules/vpc/main.tf << EOF

resource "aws_security_group" "$sg_name" {
  name        = "$sg_name"
  description = "$sg_description"
  vpc_id      = aws_vpc.$vpc_name.id

  # Rules will be added later or manually
  
  tags = {
    Name = "$sg_name"
  }
}
EOF
      
      # Add to import commands
      echo "terraform import 'module.vpc.aws_security_group.$sg_name' '$sg_id'" >> import_commands.sh
    done
  done
  
  echo -e "${GREEN}VPC resources discovery completed${NC}"
}

# Check if an EC2 instance is in a default VPC
is_instance_in_default_vpc() {
  local instance_id="$1"
  local vpc_id=$(aws ec2 describe-instances --instance-ids "$instance_id" --query "Reservations[].Instances[].VpcId" --output text)
  
  if [ -n "$vpc_id" ]; then
    is_default_vpc "$vpc_id"
    return $?
  else
    return 1
  fi
}

# Discover EC2 instances
discover_ec2_instances() {
  banner "Discovering EC2 instances (excluding those in default VPCs)"
  
  echo "Scanning for EC2 instances..."
  
  # Get list of EC2 instances
  instances=$(aws ec2 describe-instances --query "Reservations[].Instances[].[InstanceId,Tags[?Key=='Name'].Value|[0],InstanceType,State.Name]" --output text)
  
  if [ -z "$instances" ]; then
    echo -e "${YELLOW}No EC2 instances found${NC}"
    return
  fi
  
  echo -e "${GREEN}Found EC2 instances:${NC}"
  
  # Create EC2 module directory
  mkdir -p modules/ec2
  cat > modules/ec2/main.tf << EOF
# EC2 instances
EOF
  
  echo "$instances" | while read -r instance_id name instance_type state; do
    if [ "$state" != "terminated" ]; then
      # Skip instances in default VPCs
      if is_instance_in_default_vpc "$instance_id"; then
        echo -e " - ${YELLOW}$instance_id ($name, $instance_type, $state - in default VPC, skipped)${NC}"
        continue
      fi
      
      echo " - $instance_id ($name, $instance_type, $state)"
      
      # If no name, use instance ID as name
      if [ -z "$name" ] || [ "$name" = "None" ]; then
        name="instance-$instance_id"
      fi
      
      # Sanitize name for Terraform
      resource_name=$(echo "$name" | tr -d ' ' | tr '.' '_' | tr '-' '_')
      
      # Get instance details
      ami_id=$(aws ec2 describe-instances --instance-ids "$instance_id" --query "Reservations[].Instances[].ImageId" --output text)
      subnet_id=$(aws ec2 describe-instances --instance-ids "$instance_id" --query "Reservations[].Instances[].SubnetId" --output text)
      key_name=$(aws ec2 describe-instances --instance-ids "$instance_id" --query "Reservations[].Instances[].KeyName" --output text)
      security_groups=$(aws ec2 describe-instances --instance-ids "$instance_id" --query "Reservations[].Instances[].SecurityGroups[].GroupId" --output text)
      
      # Create EC2 instance resource in Terraform
      cat >> modules/ec2/main.tf << EOF

resource "aws_instance" "$resource_name" {
  ami                    = "$ami_id"
  instance_type          = "$instance_type"
  subnet_id              = "$subnet_id"
  key_name               = "$key_name"
  # The security groups below may need adjustment
  vpc_security_group_ids = [
EOF

      # Add security groups
      for sg in $security_groups; do
        cat >> modules/ec2/main.tf << EOF
    "$sg",
EOF
      done

      cat >> modules/ec2/main.tf << EOF
  ]

  tags = {
    Name = "$name"
  }
}
EOF
      
      # Add to import commands
      echo "terraform import 'module.ec2.aws_instance.$resource_name' '$instance_id'" >> import_commands.sh
    fi
  done
  
  echo -e "${GREEN}EC2 instances discovery completed${NC}"
}

# Discover S3 buckets
discover_s3_buckets() {
  banner "Discovering S3 buckets"
  
  echo "Scanning for S3 buckets..."
  
  # Get list of S3 buckets
  buckets=$(aws s3api list-buckets --query "Buckets[].Name" --output text)
  
  if [ -z "$buckets" ]; then
    echo -e "${YELLOW}No S3 buckets found${NC}"
    return
  fi
  
  echo -e "${GREEN}Found S3 buckets:${NC}"
  
  # Create S3 module directory
  mkdir -p modules/s3
  cat > modules/s3/main.tf << EOF
# S3 buckets
EOF
  
  for bucket in $buckets; do
    echo " - $bucket"
    
    # Sanitize bucket name for Terraform
    resource_name=$(echo "$bucket" | tr -d ' ' | tr '.' '_' | tr '-' '_')
    
    # Create S3 bucket resource in Terraform
    cat >> modules/s3/main.tf << EOF

resource "aws_s3_bucket" "$resource_name" {
  bucket = "$bucket"
}

resource "aws_s3_bucket_ownership_controls" "${resource_name}_ownership" {
  bucket = aws_s3_bucket.$resource_name.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}
EOF
    
    # Add to import commands
    echo "terraform import 'module.s3.aws_s3_bucket.$resource_name' '$bucket'" >> import_commands.sh
    echo "terraform import 'module.s3.aws_s3_bucket_ownership_controls.${resource_name}_ownership' '$bucket'" >> import_commands.sh
  done
  
  echo -e "${GREEN}S3 buckets discovery completed${NC}"
}

# Check if a RDS instance is in a default VPC
is_rds_in_default_vpc() {
  local db_instance="$1"
  local vpc_id=$(aws rds describe-db-instances --db-instance-identifier "$db_instance" --query "DBInstances[].DBSubnetGroup.VpcId" --output text)
  
  if [ -n "$vpc_id" ]; then
    is_default_vpc "$vpc_id"
    return $?
  else
    return 1
  fi
}

# Discover RDS instances
discover_rds_instances() {
  banner "Discovering RDS instances (excluding those in default VPCs)"
  
  echo "Scanning for RDS instances..."
  
  # Get list of RDS instances
  rds_instances=$(aws rds describe-db-instances --query "DBInstances[].DBInstanceIdentifier" --output text 2>/dev/null || echo "")
  
  if [ -z "$rds_instances" ]; then
    echo -e "${YELLOW}No RDS instances found${NC}"
    return
  fi
  
  echo -e "${GREEN}Found RDS instances:${NC}"
  
  # Create RDS module directory
  mkdir -p modules/rds
  cat > modules/rds/main.tf << EOF
# RDS instances
EOF
  
  for instance in $rds_instances; do
    # Skip RDS instances in default VPCs
    if is_rds_in_default_vpc "$instance"; then
      echo -e " - ${YELLOW}$instance (in default VPC, skipped)${NC}"
      continue
    fi
    
    echo " - $instance"
    
    # Get instance details
    instance_details=$(aws rds describe-db-instances --db-instance-identifier "$instance" --output json)
    engine=$(echo "$instance_details" | jq -r '.DBInstances[0].Engine')
    engine_version=$(echo "$instance_details" | jq -r '.DBInstances[0].EngineVersion')
    instance_class=$(echo "$instance_details" | jq -r '.DBInstances[0].DBInstanceClass')
    storage=$(echo "$instance_details" | jq -r '.DBInstances[0].AllocatedStorage')
    
    # Sanitize instance name for Terraform
    resource_name=$(echo "$instance" | tr -d ' ' | tr '.' '_' | tr '-' '_')
    
    # Create RDS instance resource in Terraform
    cat >> modules/rds/main.tf << EOF

resource "aws_db_instance" "$resource_name" {
  identifier           = "$instance"
  engine               = "$engine"
  engine_version       = "$engine_version"
  instance_class       = "$instance_class"
  allocated_storage    = $storage
  # Sensitive data like passwords would need to be provided manually
  # password             = var.${resource_name}_password
  skip_final_snapshot  = true

  # Add other configuration options as needed
}
EOF
    
    # Add to import commands
    echo "terraform import 'module.rds.aws_db_instance.$resource_name' '$instance'" >> import_commands.sh
  done
  
  echo -e "${GREEN}RDS instances discovery completed${NC}"
}

# Discover IAM resources
discover_iam_resources() {
  banner "Discovering IAM resources"
  
  echo "Scanning for IAM roles..."
  
  # Create IAM module directory
  mkdir -p modules/iam
  cat > modules/iam/main.tf << EOF
# IAM resources
EOF
  
  # Get list of IAM roles
  roles=$(aws iam list-roles --query "Roles[].RoleName" --output text 2>/dev/null || echo "")
  
  if [ -n "$roles" ]; then
    echo -e "${GREEN}Found IAM roles:${NC}"
    
    for role in $roles; do
      # Skip service-linked roles and default AWS roles
      if [[ "$role" != "AWSServiceRole"* ]] && [[ "$role" != "AWS"* ]]; then
        echo " - $role"
        
        # Sanitize role name for Terraform
        resource_name=$(echo "$role" | tr -d ' ' | tr '.' '_' | tr '-' '_')
        
        # Get role details
        role_details=$(aws iam get-role --role-name "$role" --output json)
        assume_role_policy=$(echo "$role_details" | jq -r '.Role.AssumeRolePolicyDocument')
        
        # Create IAM role resource in Terraform using HEREDOC
        cat >> modules/iam/main.tf << EOF

resource "aws_iam_role" "$resource_name" {
  name               = "$role"
  assume_role_policy = <<POLICY
$assume_role_policy
POLICY
}
EOF
        
        # Add to import commands
        echo "terraform import 'module.iam.aws_iam_role.$resource_name' '$role'" >> import_commands.sh
      else
        echo -e " - ${YELLOW}$role (default AWS role, skipped)${NC}"
      fi
    done
  else
    echo -e "${YELLOW}No IAM roles found or insufficient permissions${NC}"
  fi
  
  echo "Scanning for IAM users..."
  
  # Get list of IAM users
  users=$(aws iam list-users --query "Users[].UserName" --output text 2>/dev/null || echo "")
  
  if [ -n "$users" ]; then
    echo -e "${GREEN}Found IAM users:${NC}"
    
    for user in $users; do
      echo " - $user"
      
      # Sanitize user name for Terraform
      resource_name=$(echo "$user" | tr -d ' ' | tr '.' '_' | tr '-' '_')
      
      # Create IAM user resource in Terraform
      cat >> modules/iam/main.tf << EOF

resource "aws_iam_user" "$resource_name" {
  name = "$user"
}
EOF
      
      # Add to import commands
      echo "terraform import 'module.iam.aws_iam_user.$resource_name' '$user'" >> import_commands.sh
    done
  else
    echo -e "${YELLOW}No IAM users found or insufficient permissions${NC}"
  fi
  
  echo -e "${GREEN}IAM resources discovery completed${NC}"
}

# Check if a Lambda function uses a default security group or VPC
is_lambda_in_default_vpc() {
  local function_name="$1"
  local vpc_config=$(aws lambda get-function-configuration --function-name "$function_name" --query "VpcConfig" --output json 2>/dev/null || echo "{}")
  local vpc_id=$(echo "$vpc_config" | jq -r '.VpcId')
  
  if [ -n "$vpc_id" ] && [ "$vpc_id" != "null" ]; then
    is_default_vpc "$vpc_id"
    return $?
  else
    return 1
  fi
}

# Discover Lambda functions
discover_lambda_functions() {
  banner "Discovering Lambda functions (excluding those in default VPCs)"
  
  echo "Scanning for Lambda functions..."
  
  # Get list of Lambda functions
  functions=$(aws lambda list-functions --query "Functions[].FunctionName" --output text 2>/dev/null || echo "")
  
  if [ -z "$functions" ]; then
    echo -e "${YELLOW}No Lambda functions found${NC}"
    return
  fi
  
  echo -e "${GREEN}Found Lambda functions:${NC}"
  
  # Create Lambda module directory
  mkdir -p modules/lambda
  cat > modules/lambda/main.tf << EOF
# Lambda functions
EOF
  
  for function in $functions; do
    # Skip Lambda functions in default VPCs
    if is_lambda_in_default_vpc "$function"; then
      echo -e " - ${YELLOW}$function (in default VPC, skipped)${NC}"
      continue
    fi
    
    echo " - $function"
    
    # Get function details
    function_details=$(aws lambda get-function --function-name "$function" --output json)
    runtime=$(echo "$function_details" | jq -r '.Configuration.Runtime')
    handler=$(echo "$function_details" | jq -r '.Configuration.Handler')
    role=$(echo "$function_details" | jq -r '.Configuration.Role')
    
    # Sanitize function name for Terraform
    resource_name=$(echo "$function" | tr -d ' ' | tr '.' '_' | tr '-' '_')
    
    # Create Lambda function resource in Terraform
    cat >> modules/lambda/main.tf << EOF

resource "aws_lambda_function" "$resource_name" {
  function_name    = "$function"
  runtime          = "$runtime"
  handler          = "$handler"
  role             = "$role"
  
  # Source code would need to be provided manually
  filename         = "dummy.zip"  # Replace with actual source code
  source_code_hash = filebase64sha256("dummy.zip")  # Replace with actual hash
  
  # Add other configuration options as needed
}
EOF
    
    # Add to import commands
    echo "terraform import 'module.lambda.aws_lambda_function.$resource_name' '$function'" >> import_commands.sh
  done
  
  echo -e "${GREEN}Lambda functions discovery completed${NC}"
}

# Create root module
create_root_module() {
  banner "Creating root module"
  # Create main.tf to reference all modules
  cat > main.tf << EOF
# Root module - Calls all child modules

module "vpc" {
  source = "./modules/vpc"
}

module "ec2" {
  source = "./modules/ec2"
  # Add dependencies as needed
  # depends_on = [module.vpc]
}

module "s3" {
  source = "./modules/s3"
}

module "rds" {
  source = "./modules/rds"
  # Add dependencies as needed
  # depends_on = [module.vpc]
}

module "iam" {
  source = "./modules/iam"
}

module "lambda" {
  source = "./modules/lambda"
  # Add dependencies as needed
  # depends_on = [module.iam]
}
EOF
  
  # Make import script executable
  chmod +x import_commands.sh
  
  echo -e "${GREEN}Created root module and import commands${NC}"
}

# Main function
main() {
  # Check dependencies
  check_dependencies
  
  # Verify AWS access
  verify_aws_access
  
  # Select AWS region
  select_region
  
  # Create Terraform project structure
  create_terraform_project
  
  # Discover resources
  discover_vpc_resources
  discover_ec2_instances
  discover_s3_buckets
  discover_rds_instances
  discover_iam_resources
  discover_lambda_functions
  
  # Create root module
  create_root_module
  
  banner "Discovery Complete!"
  
  echo -e "${GREEN}Successfully discovered AWS resources and created Terraform configuration${NC}"
  echo -e "Terraform project is located in: ${YELLOW}$PWD${NC}"
  echo -e "\nNext steps:"
  echo -e "1. Review the generated Terraform configuration in ${YELLOW}terraform-aws-modules/${NC}"
  echo -e "2. Run the import commands: ${YELLOW}cd terraform-aws-modules && ./import_commands.sh${NC}"
  echo -e "3. Initialize Terraform: ${YELLOW}terraform init${NC}"
  echo -e "4. Validate the configuration: ${YELLOW}terraform validate${NC}"
  echo -e "5. Generate a plan: ${YELLOW}terraform plan${NC}"
  
  echo -e "\n${YELLOW}Note: You may need to adjust some resource configurations manually.${NC}"
  echo -e "${YELLOW}Default AWS resources (default VPCs, subnets, security groups, etc.) have been excluded from this configuration.${NC}"
}

# Run main function
main
