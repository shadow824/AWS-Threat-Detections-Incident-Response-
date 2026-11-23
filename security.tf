# ---------- Member 5: Detection ----------

resource "aws_guardduty_detector" "ir" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"

  tags = {
    Name = "ir-guardduty-detector"
  }
}

resource "aws_securityhub_account" "ir" {}