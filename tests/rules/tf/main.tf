resource "aws_security_group_rule" "ssh" {
  type        = "ingress"
  # ruleid: tf.open-ingress
  from_port   = 22
  to_port     = 22
  cidr_blocks = ["0.0.0.0/0"]
}
resource "aws_s3_bucket_acl" "site" {
  # ruleid: tf.public-bucket
  acl = "public-read"
}
resource "aws_db_instance" "db" {
  # ruleid: tf.unencrypted
  storage_encrypted = false
}
