# PROVIDERS

provider "google" {
  credentials = file("account.json")
  project     = var.project_id
  region      = var.region
  # version     = "~> 3.47.0"
}

provider "acme" {
  server_url = "https://acme-staging-v02.api.letsencrypt.org/directory"
}

# CLOUD STORAGE

resource "google_storage_bucket" "state" {
  name          = var.state_bucket
  location      = var.region
  project       = var.project_id
  storage_class = "NEARLINE"
  labels = {
    environment = "development"
    created-by  = "terraform"
    # owner       = "yourname"
  }
}

# TERRAFORM BACKEND

terraform {
  backend "gcs" {
    # Your unique bucket name
    bucket      = "terraform-wp-tfstate-20201114165452"
    prefix      = "terraform/state"
    credentials = "account.json"
  }
}

# NETWORKING

## VPC network
resource "google_compute_network" "vpc_network" {
  name                    = var.vpc_network
  auto_create_subnetworks = false
}

## VPC subnetwork
resource "google_compute_subnetwork" "vpc_subnetwork" {
  name          = var.vpc_subnetwork
  region        = var.region
  network       = google_compute_network.vpc_network.id
  ip_cidr_range = var.vpc_subnetwork_cidr
}

## Firewall rules

resource "google_compute_firewall" "prod-allow-internal" {
  name    = "prod-allow-internal"
  network = google_compute_network.vpc_network.id

  allow {
    protocol = "all"
  }

  source_ranges = var.source_ranges["private"]
}

resource "google_compute_firewall" "prod-allow-ssh" {
  name    = "prod-allow-ssh"
  network = google_compute_network.vpc_network.id

  allow {
    protocol = "tcp"
    ports    = [var.ports["ssh"]]
  }

  source_ranges = var.source_ranges["public"]
}

resource "google_compute_firewall" "prod-allow-mysql" {
  name    = "prod-allow-mysql"
  network = google_compute_network.vpc_network.id

  allow {
    protocol = "tcp"
    ports    = [var.ports["mysql"]]
  }

  target_tags   = [var.tags["mysql"]]
  source_ranges = var.source_ranges["restricted"]
}

resource "google_compute_firewall" "prod-allow-sftp" {
  name    = "prod-allow-sftp"
  network = google_compute_network.vpc_network.id

  allow {
    protocol = "tcp"
    ports    = [var.ports["sftp"]]
  }

  target_tags   = [var.tags["sftp"]]
  source_ranges = var.source_ranges["public"]
}

resource "google_compute_firewall" "prod-allow-http" {
  name    = "prod-allow-http"
  network = google_compute_network.vpc_network.id

  allow {
    protocol = "tcp"
    ports    = [var.ports["http"]]
  }

  target_tags   = [var.tags["http"]]
  source_ranges = var.source_ranges["public"]
}

# resource "google_compute_firewall" "prod-allow-https" {
#   name    = "prod-allow-https"
#   network = google_compute_network.vpc_network.id

#   allow {
#     protocol = "tcp"
#     ports    = [var.ports["https"]]
#   }

#   target_tags   = [var.tags["https"]]
#   source_ranges = var.source_ranges["public"]
# }

# INSTANCE

resource "google_compute_address" "instance_public_ip" {
  name = var.instance_public_ip_name
}

resource "google_compute_instance" "instance" {
  project      = var.project_id
  name         = var.hostname
  machine_type = var.machine_type
  zone         = var.zone

  boot_disk {
    initialize_params {
      image = var.disk_image
      size  = var.disk_image_size
    }
  }

  network_interface {
    network    = google_compute_network.vpc_network.id
    subnetwork = google_compute_subnetwork.vpc_subnetwork.id
    access_config {
      nat_ip = google_compute_address.instance_public_ip.address
    }
  }

  metadata = {
    Name     = "Terraform and Ansible provisiong"
    ssh-keys = "${var.ssh_user}:${file("${var.public_key_path}")}"
  }

  metadata_startup_script = "echo hi > /test.txt"

  service_account {
    scopes = [
      "https://www.googleapis.com/auth/devstorage.read_only",
      "https://www.googleapis.com/auth/logging.write",
      "https://www.googleapis.com/auth/monitoring.write",
      "https://www.googleapis.com/auth/service.management.readonly",
      "https://www.googleapis.com/auth/servicecontrol",
      "https://www.googleapis.com/auth/trace.append"
    ]
  }

  # Wait for instance to be up and ready
  provisioner "remote-exec" {
    inline = ["echo 'Hello World'"]

    connection {
      type        = "ssh"
      user        = var.ssh_user
      private_key = file("${var.private_key_path}")
      host        = google_compute_instance.instance.network_interface.0.access_config.0.nat_ip
    }
  }
  provisioner "local-exec" {
    command = "ansible-playbook -i '${google_compute_instance.instance.network_interface.0.access_config.0.nat_ip},' --vault-password-file=${var.ansible_vault_pass} --private-key ${var.private_key_path} --ssh-common-args='-o StrictHostKeyChecking=no' -e 'ansible_python_interpreter=/usr/bin/python3' ansible/playbook.yml"
  }

  allow_stopping_for_update = true

  // Apply the firewall rule to allow external IPs to access this instance
  tags = [var.tags["http"], var.tags["mysql"], var.tags["sftp"]]
}

resource "google_compute_instance_group" "instance_group" {
  name    = var.instance_group_name
  network = google_compute_network.vpc_network.id

  instances = [google_compute_instance.instance.self_link]

  named_port {
    name = "http"
    port = var.ports["http"]
  }

  zone = var.zone
}

# SNAPSHOT SCHEDULE POLICY

resource "google_compute_resource_policy" "snapshot_schedule_policy" {
  name   = var.snapshot_schedule_policy_name
  region = var.region
  snapshot_schedule_policy {
    schedule {
      daily_schedule {
        days_in_cycle = 1
        start_time    = "01:00"
      }
    }
    retention_policy {
      max_retention_days    = var.max_retention_days
      on_source_disk_delete = "KEEP_AUTO_SNAPSHOTS"
    }
    snapshot_properties {
      labels = {
        my_label = "value"
      }
      storage_locations = [var.storage_locations]
      guest_flush       = true
    }
  }
}

## Snapshot schedule policy attachment - Boot disk
resource "google_compute_disk_resource_policy_attachment" "snapshot_schedule_policy_attachment_boot_disk" {
  name = google_compute_resource_policy.snapshot_schedule_policy.name
  disk = var.hostname
  zone = var.zone
}

# LOAD BALANCER

## Load balancer public IP address
resource "google_compute_global_address" "lb_proxy_instance_public_ip" {
  name = var.lb_proxy_instance_public_ip_name
}

## Load balancer with unmanaged instance group

## TLS certificates

resource "tls_private_key" "private_key" {
  algorithm = "RSA"
}

resource "acme_registration" "reg" {
  account_key_pem = tls_private_key.private_key.private_key_pem
  email_address   = var.email_address
}

resource "google_compute_managed_ssl_certificate" "managed_ssl_certificate" {
  provider = google-beta
  name     = "managed-ssl-certificate"
  project  = var.project_id
  managed {
    domains = ["${google_compute_global_address.lb_proxy_instance_public_ip.address}.xip.io"]
  }
}

## Global forwarding rules HTTP
resource "google_compute_global_forwarding_rule" "global_forwarding_rule_http" {
  name       = "${var.lb_proxy_name}-global-forwarding-rule-http"
  project    = var.project_id
  target     = google_compute_target_http_proxy.target_http_proxy.id
  port_range = var.global_forwarding_rule_port["http"]
  ip_address = google_compute_global_address.lb_proxy_instance_public_ip.address
}

## Global forwarding rules HTTPS
resource "google_compute_global_forwarding_rule" "global_forwarding_rule_https" {
  provider   = google-beta
  name       = "${var.lb_proxy_name}-global-forwarding-rule-https"
  project    = var.project_id
  target     = google_compute_target_https_proxy.target_https_proxy.id
  port_range = var.global_forwarding_rule_port["https"]
  ip_address = google_compute_global_address.lb_proxy_instance_public_ip.address
}

## Proxy HTTP
resource "google_compute_target_http_proxy" "target_http_proxy" {
  name    = "${var.lb_proxy_name}-http-proxy"
  project = var.project_id
  url_map = google_compute_url_map.lb_url_map.id
}

## Proxy HTTPS
resource "google_compute_target_https_proxy" "target_https_proxy" {
  provider         = google-beta
  name             = "${var.lb_proxy_name}-https-proxy"
  project          = var.project_id
  url_map          = google_compute_url_map.lb_url_map.id
  ssl_certificates = [google_compute_managed_ssl_certificate.managed_ssl_certificate.id]
}

## Backend service
resource "google_compute_backend_service" "backend_service" {
  name          = var.backend_service_name
  project       = var.project_id
  port_name     = var.backend_service_port_name
  protocol      = "HTTP"
  timeout_sec   = var.backend_service_timeout
  health_checks = [google_compute_health_check.health_check.id]
  backend {
    group = google_compute_instance_group.instance_group.id
  }
}

## Health checks

resource "google_compute_health_check" "health_check" {
  name               = "health-check"
  timeout_sec        = 5
  check_interval_sec = 10
  http_health_check {
    port         = var.health_check_port
    request_path = "/status"
  }
}

## URL maps
resource "google_compute_url_map" "lb_url_map" {
  name            = "${var.lb_proxy_name}-lb"
  project         = var.project_id
  default_service = google_compute_backend_service.backend_service.id

  host_rule {
    hosts        = ["${google_compute_global_address.lb_proxy_instance_public_ip.address}.xip.io"]
    path_matcher = "instance-prod-rules"
  }

  path_matcher {
    name = "instance-prod-rules"

    default_service = google_compute_backend_service.backend_service.id

    path_rule {
      paths   = ["/"]
      service = google_compute_backend_service.backend_service.id
    }
  }

}

# MONITORING

resource "google_monitoring_notification_channel" "status" {
  display_name = "#status"
  type         = "slack"
  labels = {
    "channel_name" = "#status"
  }
  sensitive_labels {
    auth_token = var.slack_auth_token
  }
}

## CPU utilization 80% policy

resource "google_monitoring_alert_policy" "alert_policy_cpu_80_percent" {
  display_name = "CPU utilization 80% policy"
  combiner     = "OR"
  conditions {
    display_name = "GCE VM Instance - CPU utilization"
    condition_threshold {
      filter          = "metric.type=\"compute.googleapis.com/instance/cpu/utilization\" AND resource.type=\"gce_instance\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = "0.8"
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_MEAN"
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.status.id]
}

## Memory utilization 80% policy

resource "google_monitoring_alert_policy" "alert_policy_memory_80_percent" {
  display_name = "Memory utilization 80% policy"
  combiner     = "OR"
  conditions {
    display_name = "GCE VM Instance - Memory utilization"
    condition_threshold {
      filter          = "metric.type=\"agent.googleapis.com/memory/percent_used\" AND resource.type=\"gce_instance\" AND metric.labels.state = \"used\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = "80"
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_MEAN"
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.status.id]
}

## Disk utilization 90% policy

resource "google_monitoring_alert_policy" "alert_policy_disk_90_percent" {
  display_name = "Disk utilization 90% policy"
  combiner     = "OR"
  conditions {
    display_name = "GCE VM Instance - Disk utilization"
    condition_threshold {
      filter          = "metric.type=\"agent.googleapis.com/disk/percent_used\" AND resource.type=\"gce_instance\" AND metric.labels.device = starts_with(\"sd\") AND metric.labels.state = \"used\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = "90"
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_MEAN"
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.status.id]
}

## Uptime check

resource "google_monitoring_uptime_check_config" "uptime_check_https" {
  display_name = "HTTPS uptime check"
  timeout      = "60s"
  period       = "60s"
  http_check {
    path         = "/"
    port         = "443"
    use_ssl      = true
    validate_ssl = true
  }
  monitored_resource {
    type = "uptime_url"
    labels = {
      project_id = var.project_id
      host       = "${google_compute_global_address.lb_proxy_instance_public_ip.address}.xip.io"
    }
  }
  lifecycle {
    create_before_destroy = true
  }
}

resource "google_monitoring_alert_policy" "alert_policy_https_uptime_check" {
  display_name = "https uptime check"
  enabled      = true
  combiner     = "OR"
  conditions {
    display_name = "https uptime check condition"
    condition_threshold {
      filter          = "metric.type=\"monitoring.googleapis.com/uptime_check/check_passed\" resource.type=\"uptime_url\" metric.label.\"check_id\"=\"${basename(google_monitoring_uptime_check_config.uptime_check_https.id)}\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 1.0
      trigger {
        count = 1
      }
      # aggregations {
      #   alignment_period = "1200s"
      #   cross_series_reducer = "REDUCE_COUNT_FALSE"
      #   group_by_fields = ["resource.*"]
      #   per_series_aligner = "ALIGN_NEXT_OLDER"
      # }
    }
  }
  notification_channels = [google_monitoring_notification_channel.status.id]
}
