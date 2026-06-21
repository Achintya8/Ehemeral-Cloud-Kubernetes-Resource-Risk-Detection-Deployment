variable "aws_region" {
  description = "AWS region (us-east-1 is cheapest for Free Tier)"
  type        = string
  default     = "us-east-1"
}

variable "shutdown_minutes" {
  description = "Auto-shutdown EC2 after N minutes"
  type        = number
  default     = 120
}