resource "google_compute_network" "vpc_network" {
  project = var.project_id
  name = "vpc-${var.cluster_name}"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "horcrux_subnetwork" {
  project = var.project_id
  name          = "subnetwork-horcrux-${var.cluster_name}"
  ip_cidr_range = var.horcrux_subnet_cidr
  region        = var.region
  network       = google_compute_network.vpc_network.id
  secondary_ip_range {
    range_name    = "horcrux-pods-${var.cluster_name}"
    ip_cidr_range = var.horcrux_subnet_pods_cidr
  }
  secondary_ip_range {
    range_name    = "horcrux-services-${var.cluster_name}"
    ip_cidr_range = var.horcrux_subnet_service_cidr
  }
}

resource "google_compute_subnetwork" "sentry_subnetwork" {
  project = var.project_id
  name          = "subnetwork-sentry-${var.cluster_name}"
  ip_cidr_range = var.sentry_subnet_cidr
  region        = var.region
  network       = google_compute_network.vpc_network.id
  secondary_ip_range {
    range_name    = "sentry-pods-${var.cluster_name}"
    ip_cidr_range = var.sentry_subnet_pods_cidr
  }
  secondary_ip_range {
    range_name    = "sentry-services-${var.cluster_name}"
    ip_cidr_range = var.sentry_subnet_service_cidr
  }
}