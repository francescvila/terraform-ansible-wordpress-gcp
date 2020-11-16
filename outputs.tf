# Show external ip address of instances
output "instance-public-ip" {
  value = google_compute_instance.instance.network_interface.0.access_config.0.nat_ip
}

# Show external ip address of load balancer
output "lb-proxy-instance-public-ip" {
  value = google_compute_global_forwarding_rule.global_forwarding_rule_http.ip_address
}

# Show website URL
output "external-url" {
  value = "https://${google_compute_global_address.lb_proxy_instance_public_ip.address}.xip.io"
}
