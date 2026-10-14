# ok-file: tf.open-ingress, tf.public-bucket, tf.unencrypted
resource "aws_security_group_rule" "ssh" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  cidr_blocks = ["10.20.0.0/16"]
}
resource "aws_s3_bucket_public_access_block" "site" {
  block_public_acls   = true
  block_public_policy = true
}
resource "aws_db_instance" "db" {
  storage_encrypted = true
}
