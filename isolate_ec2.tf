variable "isolate_dry_run" {
  description = "When true, the isolation Lambda only logs and changes nothing"
  type        = bool
  default     = true
}

data "archive_file" "isolate_ec2" {
  type        = "zip"
  source_dir  = "${path.module}/lambda/isolate_ec2"
  output_path = "${path.module}/isolate_ec2.zip"
  excludes    = ["__pycache__", "test_event.json"]
}

resource "aws_iam_role" "isolate_ec2" {
  name = "ir-isolate-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "isolate_ec2_logs" {
  role       = aws_iam_role.isolate_ec2.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "isolate_ec2" {
  name = "ir-isolate-ec2-policy"
  role = aws_iam_role.isolate_ec2.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "ec2:DescribeInstances",
        "ec2:DescribeSecurityGroups",
        "ec2:CreateSecurityGroup",
        "ec2:RevokeSecurityGroupEgress",
        "ec2:ModifyNetworkInterfaceAttribute",
        "ec2:CreateSnapshot",
        "ec2:CreateTags"
      ]
      Resource = "*"
    }]
  })
}

resource "aws_lambda_function" "isolate_ec2" {
  function_name    = "ir-isolate-ec2"
  role             = aws_iam_role.isolate_ec2.arn
  runtime          = "python3.12"
  handler          = "handler.lambda_handler"
  filename         = data.archive_file.isolate_ec2.output_path
  source_code_hash = data.archive_file.isolate_ec2.output_base64sha256
  timeout          = 60

  environment {
    variables = {
      DRY_RUN = tostring(var.isolate_dry_run)
    }
  }
}

resource "aws_cloudwatch_event_rule" "guardduty_ec2" {
  name        = "ir-guardduty-ec2-high-severity"
  description = "High severity GuardDuty findings on EC2 instances"

  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", 7] }]
      resource = { resourceType = ["Instance"] }
    }
  })
}

resource "aws_cloudwatch_event_target" "isolate_ec2" {
  rule = aws_cloudwatch_event_rule.guardduty_ec2.name
  arn  = aws_lambda_function.isolate_ec2.arn
}

resource "aws_lambda_permission" "eventbridge_isolate_ec2" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.isolate_ec2.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_ec2.arn
}