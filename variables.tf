variable "region" {
  type    = string
  default = "europe-west1"
}

variable "zone" {
  type    = string
  default = "europe-west1-d"
}

variable "project_id" {}

variable "state_bucket" {}

variable "machine_type" {
  type    = string
  default = "e2-medium"
}

variable "vpc_network" {
  type    = string
  default = "production"
}

variable "vpc_subnetwork" {
  type    = string
  default = "prod-10-254-0-0"
}

variable "vpc_subnetwork_cidr" {
  type    = string
  default = "10.254.0.0/24"
}

variable "source_ranges" {
  type = map
  default = {
    "private"    = ["10.254.0.0/24"]
    "public"     = ["0.0.0.0/0"]
    "restricted" = ["10.0.0.0/32"] # This is a dummy IP address. Add here your public IP.
  }
}

variable "ports" {
  type = map
  default = {
    "ssh"   = "22"
    "sftp"  = "2222"
    "http"  = "80"
    "https" = "443"
    "mysql" = "3306"
  }
}

variable "tags" {
  type = map
  default = {
    "http"  = "http-server"
    "https" = "https-server"
    "mysql" = "mysql"
    "sftp"  = "secure"
  }
}

variable "instance_public_ip_name" {
  type    = string
  default = "instance-prod-public-ip"
}

variable "disk_image" {
  type    = string
  default = "debian-cloud/debian-10"
}

variable "disk_image_size" { # Size expressed in GB
  type    = string
  default = "30"
}

variable "hostname" {
  type    = string
  default = "instance-prod"
}

variable "instance_group_name" {
  type    = string
  default = "instance-prod-group-instance"
}

variable "ssh_user" {
  type    = string
  default = "ansible"
}

variable "private_key_path" {
  type    = string
  default = "creds/id_rsa"
}

variable "public_key_path" {
  type    = string
  default = "creds/id_rsa.pub"
}

variable "ansible_vault_pass" {
  type    = string
  default = "ansible/vault_pass"
}

variable "snapshot_schedule_policy_name" {
  type    = string
  default = "snapshot-schedule-instance-prod"
}

variable "max_retention_days" {
  type    = string
  default = "14"
}

variable "storage_locations" {
  type    = string
  default = "eu"
}

variable "lb_proxy_instance_public_ip_name" {
  type    = string
  default = "lb-proxy-public-ip"
}

variable "email_address" {}

variable "lb_proxy_name" {
  type    = string
  default = "proxy"
}

variable "global_forwarding_rule_port" {
  type = map
  default = {
    "http"  = "80"
    "https" = "443"
  }
}

variable "backend_service_port_name" {
  type    = string
  default = "http"
}

variable "backend_service_timeout" {
  type    = string
  default = "60"
}

variable "health_check_port" {
  type    = string
  default = "80"
}

variable "backend_service_name" {
  type    = string
  default = "instance-prod-backend-service"
}

variable "slack_auth_token" {}
