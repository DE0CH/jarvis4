# Jarvis 4's session machines on AWS (docs/PLAN-aws.md): per region a launch template `jarvis4-session` (Flatcar
# Container Linux, IMDSv2, terminate on shutdown, a security group with no ingress) that the spawner's RunInstances
# names, and the IAM users: the spawner's (start, read, console, terminate instances tagged jarvis4_source) and the
# router's read-only one (instances, costs). OpenTofu, applied by .github/workflows/aws.yml on push. Keys are minted
# by hand once (`aws iam create-access-key`) and sealed to the spawner (infra/setup.py aws-credentials) / put in the
# router's secrets; tofu never sees them.
terraform {
  required_version = ">= 1.10"
  required_providers {
    aws = { source = "hashicorp/aws", version = "6.20.0" }
  }
  # State in R2 on Deyao's Cloudflare account, beside DE0CH/services' (bucket deyao-tofu-state, lockfile).
  backend "s3" {
    bucket                      = "deyao-tofu-state"
    key                         = "jarvis4/aws/terraform.tfstate"
    region                      = "auto"
    endpoints                   = { s3 = "https://ee3b4deef856baf11e1a67b242438325.r2.cloudflarestorage.com" }
    use_lockfile                = true
    use_path_style              = true
    skip_credentials_validation = true
    skip_region_validation      = true
    skip_requesting_account_id  = true
    skip_metadata_api_check     = true
    skip_s3_checksum            = true
  }
}

# The workflow's AWS key (IAM user jarvis4-infra), apart from the backend's R2 key in AWS_ACCESS_KEY_ID
variable "aws_access_key" {
  type      = string
  sensitive = true
}
variable "aws_secret_key" {
  type      = string
  sensitive = true
}

# Flatcar stable, pinned per region (a bump is a commit: `aws ec2 describe-images --owners 075585003325 --filters
# Name=name,Values=Flatcar-stable-<version>-hvm` in each region). Instances that are up keep theirs.
locals {
  flatcar = "4757.2.3"
  amis = {
    "eu-west-2"      = "ami-00ad783931676ef90"
    "ap-southeast-1" = "ami-0b033f21410ef992f"
    "ap-northeast-1" = "ami-04c41a20ea1b07bf9"
  }
}

provider "aws" {
  region     = "eu-west-2"
  alias      = "lon"
  access_key = var.aws_access_key
  secret_key = var.aws_secret_key
}
provider "aws" {
  region     = "ap-southeast-1"
  alias      = "sin"
  access_key = var.aws_access_key
  secret_key = var.aws_secret_key
}
provider "aws" {
  region     = "ap-northeast-1"
  alias      = "tyo"
  access_key = var.aws_access_key
  secret_key = var.aws_secret_key
}

module "lon" {
  source    = "./region"
  providers = { aws = aws.lon }
  ami       = local.amis["eu-west-2"]
}
module "sin" {
  source    = "./region"
  providers = { aws = aws.sin }
  ami       = local.amis["ap-southeast-1"]
}
module "tyo" {
  source    = "./region"
  providers = { aws = aws.tyo }
  ami       = local.amis["ap-northeast-1"]
}
