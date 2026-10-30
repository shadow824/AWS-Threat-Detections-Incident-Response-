terraform {
  required_version = ">= 1.10"

  backend "s3" {
    bucket       = "depi-team-5-tfstate"
    key          = "project/terraform.tfstate"
    region       = "us-east-1"
    profile      = "depi-team-5"
    encrypt      = true
    use_lockfile = true
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region  = "us-east-1"
  profile = "depi-team-5"

  default_tags {
    tags = {
      Project   = "depi-team-5"
      ManagedBy = "terraform"
    }
  }
}