provider "kubernetes" {
  alias                  = "sentry"
  host                   = "https://${module.gke_sentry.endpoint}"
  token                  = data.google_client_config.default.access_token
  cluster_ca_certificate = base64decode(module.gke_sentry.ca_certificate)
}

module "gke_sentry" {
  depends_on = [resource.google_compute_subnetwork.sentry_subnetwork]
  providers = {
    kubernetes = kubernetes.sentry
  }
  source                     = "terraform-google-modules/kubernetes-engine/google//modules/private-cluster"
  project_id                 = var.project_id
  name                       = "${var.cluster_name}-sentry"
  region                     = var.region
  zones                      = var.cluster_zones
  network                    = "vpc-${var.cluster_name}"
  subnetwork                 = "subnetwork-sentry-${var.cluster_name}"
  ip_range_pods              = "sentry-pods-${var.cluster_name}"
  ip_range_services          = "sentry-services-${var.cluster_name}"
  http_load_balancing        = false
  horizontal_pod_autoscaling = false
  network_policy             = false
  enable_private_endpoint    = false
  enable_private_nodes       = false
  master_ipv4_cidr_block     = var.sentry_master_cidr
  remove_default_node_pool   = true

  node_pools = [
    {
      name                      = "sentry-node-pool"
      node_count                = var.num_sentry_nodes
      disk_size_gb              = var.sentry_disk_size_gb
      machine_type              = var.sentry_machine_type
      disk_type                 = var.sentry_disk_type
      image_type                = var.sentry_image_type
      auto_repair               = true
      auto_upgrade              = true
      preemptible               = false
    },
  ]

  node_pools_oauth_scopes = {
    all = []

    sentry-node-pool = [
      "https://www.googleapis.com/auth/cloud-platform",
    ]
  }
}