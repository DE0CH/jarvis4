# One region's session network and launch template: a VPC with a public subnet per zone (a public IPv4 per instance: the
# m-gateways reach its WireGuard there, from the cluster's pods, whose IPv4 goes out through Cloudflare WARP), nothing
# in but WireGuard; Flatcar, IMDSv2 only, and an instance that shuts itself down is terminated (the session unit powers off
# when the machine ends).
terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}

variable "ami" { type = string } # Flatcar
variable "session_image" { type = string }

# bake.sh's AMI for the pinned session image: Flatcar with the image already pulled, tagged once its test boot found
# the image there and Ignition ran again (none yet: plain Flatcar)
data "aws_ami_ids" "baked" {
  owners = ["self"]
  filter {
    name   = "tag:jarvis4_session_image"
    values = [var.session_image]
  }
  filter {
    name   = "state"
    values = ["available"]
  }
}

data "aws_availability_zones" "up" { state = "available" }

# the account's EC2 Serial Console in this region: the spawner reads a new machine's keys line live through it
# (kernel/spawner/awsserial.go; only with a key it pushes for one of its tagged instances, iam.tf)
resource "aws_ec2_serial_console_access" "on" {
  enabled = true
}

resource "aws_vpc" "sessions" {
  cidr_block           = "10.40.0.0/16"
  enable_dns_hostnames = true
  tags                 = { Name = "jarvis4-sessions" }
}

resource "aws_internet_gateway" "sessions" {
  vpc_id = aws_vpc.sessions.id
  tags   = { Name = "jarvis4-sessions" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.sessions.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.sessions.id
  }
  tags = { Name = "jarvis4-sessions" }
}

resource "aws_subnet" "public" {
  count                   = length(data.aws_availability_zones.up.names)
  vpc_id                  = aws_vpc.sessions.id
  availability_zone       = data.aws_availability_zones.up.names[count.index]
  cidr_block              = cidrsubnet(aws_vpc.sessions.cidr_block, 8, count.index)
  map_public_ip_on_launch = true
  tags                    = { Name = "jarvis4-sessions-${data.aws_availability_zones.up.names[count.index]}" }
}

resource "aws_route_table_association" "public" {
  count          = length(aws_subnet.public)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_security_group" "session" {
  name        = "jarvis4-session"
  description = "Jarvis 4 session machines: WireGuard in (the m-gateways start the handshakes), any outbound"
  vpc_id      = aws_vpc.sessions.id
  ingress {
    description = "WireGuard (kernel/spawner/aws.go wgPort): silent to anything without a peer key"
    from_port   = 51820
    to_port     = 51820
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"] # WARP's addresses vary
  }
  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
}

resource "aws_launch_template" "session" {
  name                                 = "jarvis4-session"
  description                          = "Jarvis 4 session machine (kernel/spawner/aws.go sets type, disk, tags, user-data)"
  image_id                             = length(data.aws_ami_ids.baked.ids) > 0 ? data.aws_ami_ids.baked.ids[0] : var.ami
  instance_initiated_shutdown_behavior = "terminate"
  update_default_version               = true
  network_interfaces {
    device_index                = 0
    associate_public_ip_address = true
    security_groups             = [aws_security_group.session.id]
    subnet_id                   = aws_subnet.public[0].id # one zone: a capacity refusal is a new spawn (ReasonHostFull)
    delete_on_termination       = true
  }
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
  credit_specification {
    cpu_credits = "unlimited" # t3: a busy session never stalls on credits
  }
  monitoring {
    enabled = false
  }
}
