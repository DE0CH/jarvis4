# The spawner's IAM user: instances from the session launch templates only, tagged with their source; it reads,
# reads the console of (GetConsoleOutput, and live over the EC2 Serial Console: kernel/spawner/awsserial.go) and
# terminates only instances that carry that tag.
resource "aws_iam_user" "spawner" {
  provider = aws.sin # IAM is global; any region's provider
  name     = "jarvis4-spawner"
  path     = "/jarvis4/"
}

data "aws_caller_identity" "me" {
  provider = aws.sin
}

resource "aws_iam_user_policy" "spawner" {
  provider = aws.sin # IAM is global; any region's provider
  name     = "jarvis4-spawner"
  user     = aws_iam_user.spawner.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "RunFromTheTemplate"
        Effect   = "Allow"
        Action   = "ec2:RunInstances"
        Resource = "arn:aws:ec2:*:${data.aws_caller_identity.me.account_id}:instance/*"
        Condition = {
          ArnLike = { "ec2:LaunchTemplate" = "arn:aws:ec2:*:${data.aws_caller_identity.me.account_id}:launch-template/*" }
          Bool    = { "ec2:IsLaunchTemplateResource" = "true" }
          Null    = { "aws:RequestTag/jarvis4_source" = "false" }
        }
      },
      {
        Sid    = "RunsResources"
        Effect = "Allow"
        Action = "ec2:RunInstances"
        Resource = [
          "arn:aws:ec2:*:${data.aws_caller_identity.me.account_id}:volume/*",
          "arn:aws:ec2:*:${data.aws_caller_identity.me.account_id}:network-interface/*",
          "arn:aws:ec2:*:${data.aws_caller_identity.me.account_id}:subnet/*",
          "arn:aws:ec2:*:${data.aws_caller_identity.me.account_id}:security-group/*",
          "arn:aws:ec2:*:${data.aws_caller_identity.me.account_id}:launch-template/*",
          "arn:aws:ec2:*::image/*",
        ]
      },
      {
        Sid       = "TagAtLaunch"
        Effect    = "Allow"
        Action    = "ec2:CreateTags"
        Resource  = "*"
        Condition = { StringEquals = { "ec2:CreateAction" = "RunInstances" } }
      },
      {
        Sid      = "Read"
        Effect   = "Allow"
        Action   = ["ec2:DescribeInstances"]
        Resource = "*"
      },
      {
        Sid       = "OnlyItsInstances"
        Effect    = "Allow"
        Action    = ["ec2:GetConsoleOutput", "ec2:TerminateInstances", "ec2:DescribeInstanceAttribute"]
        Resource  = "arn:aws:ec2:*:${data.aws_caller_identity.me.account_id}:instance/*"
        Condition = { Null = { "aws:ResourceTag/jarvis4_source" = "false" } }
      },
      {
        # a one-off key for one serial console session (the keys line, read live)
        Sid       = "ReadItsSerialConsoles"
        Effect    = "Allow"
        Action    = "ec2-instance-connect:SendSerialConsoleSSHPublicKey"
        Resource  = "arn:aws:ec2:*:${data.aws_caller_identity.me.account_id}:instance/*"
        Condition = { Null = { "aws:ResourceTag/jarvis4_source" = "false" } }
      },
    ]
  })
}

# The router's read-only user: the instances (lost machines, the lifecycle log) and the costs (the budget, router/
# awsbudget.go: every instance, volume, snapshot and Elastic IP for the live estimate; Cost Explorer's billed figure
# as the cross-check; the price list)
resource "aws_iam_user" "router" {
  provider = aws.sin # IAM is global; any region's provider
  name     = "jarvis4-router-read"
  path     = "/jarvis4/"
}

resource "aws_iam_user_policy" "router" {
  provider = aws.sin # IAM is global; any region's provider
  name     = "jarvis4-router-read"
  user     = aws_iam_user.router.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["ec2:DescribeInstances", "ec2:DescribeVolumes", "ec2:DescribeSnapshots", "ec2:DescribeAddresses", "ce:GetCostAndUsage", "pricing:GetProducts"]
      Resource = "*"
    }]
  })
}
