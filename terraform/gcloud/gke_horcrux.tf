provider "kubernetes" {
  alias                  = "horcrux"
  host                   = "https://${module.gke_horcrux.endpoint}"
  token                  = data.google_client_config.default.access_token
  cluster_ca_certificate = base64decode(module.gke_horcrux.ca_certificate)
}

module "gke_horcrux" {
  depends_on = [resource.google_compute_subnetwork.horcrux_subnetwork]
  providers = {
    kubernetes = kubernetes.horcrux
  }
  source                     = "terraform-google-modules/kubernetes-engine/google//modules/private-cluster"
  project_id                 = var.project_id
  name                       = "${var.cluster_name}-horcrux"
  region                     = var.region
  zones                      = var.cluster_zones
  network                    = "vpc-${var.cluster_name}"
  subnetwork                 = "subnetwork-horcrux-${var.cluster_name}"
  ip_range_pods              = "horcrux-pods-${var.cluster_name}"
  ip_range_services          = "horcrux-services-${var.cluster_name}"
  http_load_balancing        = false
  horizontal_pod_autoscaling = false
  network_policy             = false
  enable_private_endpoint    = true
  enable_private_nodes       = true
  master_ipv4_cidr_block     = var.horcrux_master_cidr
  remove_default_node_pool   = true

  master_authorized_networks = [{
    cidr_block = var.horcrux_authorized_cidr
    display_name = "cluster_authorized"
  }]

  node_pools = [
    {
      name                      = "horcrux-node-pool"
      node_count                = var.num_signer_nodes
      disk_size_gb              = var.horcrux_disk_size_gb
      machine_type              = var.horcrux_machine_type
      disk_type                 = var.horcrux_disk_type
      image_type                = var.horcrux_image_type
      auto_repair               = true
      auto_upgrade              = true
      preemptible               = false
    },
  ]

  node_pools_oauth_scopes = {
    all = []

    horcrux-node-pool = [
      "https://www.googleapis.com/auth/cloud-platform",
    ]
  }
}