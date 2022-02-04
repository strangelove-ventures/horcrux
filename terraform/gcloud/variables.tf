variable "cluster_name" {
  description = "The name of the GKE cluster"
}

variable "num_signer_nodes" {
  default     = 3
  description = "number of horcrux signer nodes"
}

variable "num_sentry_nodes" {
  default     = 3
  description = "number of validator sentry nodes"
}

variable "project_id" {
  description = "The project ID to host the cluster in"
}

variable "region" {
  description = "The region to host the cluster in"
}

variable "cluster_zones" {
  description = "The zones where the cluster will be deployed"
  type        = list
}

# Machine Types
variable "horcrux_machine_type" {
  description = "The machine type for the horcrux nodes"
  default = "n1-highcpu-2"
}

variable "sentry_machine_type" {
  description = "The machine type for the sentry nodes"
  default = "n2d-standard-4"
}

# Image Types
variable "horcrux_image_type" {
  description = "The image type for the horcrux nodes"
  default = "UBUNTU"
}

variable "sentry_image_type" {
  description = "The image type for the sentry nodes"
  default = "UBUNTU"
}

# Disk Types
variable "horcrux_disk_type" {
  description = "The disk type for the horcrux nodes"
  default = "pd-ssd"
}

variable "sentry_disk_type" {
  description = "The disk type for the sentry nodes"
  default = "pd-ssd"
}

# Disk Space
variable "horcrux_disk_size_gb" {
  description = "The disk space (GB) for the horcrux nodes"
  default = 20
}

variable "sentry_disk_size_gb" {
  description = "The disk space (GB) for the sentry nodes"
  default = 500
}

# Horcrux Cluster CIDR Ranges
variable "horcrux_master_cidr" {
  description = "The CIDR for the horcrux cluster"
  default = "192.168.1.0/28"
}

variable "horcrux_subnet_cidr" {
  description = "The CIDR for the horcrux subnet"
  default = "192.168.4.0/24"
}

variable "horcrux_subnet_pods_cidr" {
  description = "The CIDR for the horcrux pods subnet"
  default = "10.5.0.0/16"
}

variable "horcrux_subnet_service_cidr" {
  description = "The CIDR for the horcrux service subnet"
  default = "10.6.0.0/16"
}

# Sentry Cluster CIDR Ranges
variable "sentry_master_cidr" {
  description = "The CIDR for the sentry cluster"
  default = "192.168.2.0/28"
}

variable "horcrux_authorized_cidr" {
  description = "The CIDR for the network authorized to connect to the horcrux cluster"
  default = "192.168.0.0/16"
}

variable "sentry_subnet_cidr" {
  description = "The CIDR for the horcrux subnet"
  default = "192.168.5.0/24"
}

variable "sentry_subnet_pods_cidr" {
  description = "The CIDR for the sentry pods subnet"
  default = "10.7.0.0/16"
}

variable "sentry_subnet_service_cidr" {
  description = "The CIDR for the sentry service subnet"
  default = "10.8.0.0/16"
}