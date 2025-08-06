terraform {
  required_version = ">=1.10.5"

  required_providers {
    azapi = {
      source  = "azure/azapi"
      version = "2.2.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "2.17.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "4.17.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "3.6.3"
    }
    time = {
      source  = "hashicorp/time"
      version = "0.12.1"
    }
  }
}

provider "azurerm" {
  features {}
  subscription_id = var.ARM_SUBSCRIPTION_ID
  tenant_id       = var.ARM_TENANT_ID
  client_id       = var.ARM_CLIENT_ID
  client_secret   = var.ARM_CLIENT_SECRET
}

provider "kubernetes" {
  host                   = azurerm_kubernetes_cluster.primary.kube_config[0].host
  client_certificate     = base64decode(azurerm_kubernetes_cluster.primary.kube_config[0].client_certificate)
  client_key             = base64decode(azurerm_kubernetes_cluster.primary.kube_config[0].client_key)
  cluster_ca_certificate = base64decode(azurerm_kubernetes_cluster.primary.kube_config[0].cluster_ca_certificate)
}
