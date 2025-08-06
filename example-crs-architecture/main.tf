#resource for random prefixes, helps with unique names and identifiers
resource "random_pet" "ssh_key_name" {
  prefix    = "ssh"
  separator = ""
}
#azapi_resource_action resource is used to perform specific actions on an Azure resource, such as starting or stopping a virtual machine. Here we're generating ssh keys
resource "azapi_resource_action" "ssh_public_key_gen" {
  type        = "Microsoft.Compute/sshPublicKeys@2022-11-01"
  resource_id = azapi_resource.ssh_public_key.id
  action      = "generateKeyPair"
  method      = "POST"

  response_export_values = ["publicKey", "privateKey"]
}

resource "azapi_resource" "ssh_public_key" {
  type      = "Microsoft.Compute/sshPublicKeys@2022-11-01"
  name      = random_pet.ssh_key_name.id
  location  = azurerm_resource_group.rg.location
  parent_id = azurerm_resource_group.rg.id
}

output "key_data" {
  value = azapi_resource_action.ssh_public_key_gen.output.publicKey
}


# Generate random resource group name
resource "random_pet" "rg_name" {
  prefix = var.resource_group_name_prefix
}

resource "azurerm_resource_group" "rg" {
  #ts:skip=AC_AZURE_0389 Locks not required
  location = var.resource_group_location
  name     = random_pet.rg_name.id
}

# Optional: Adds resource lock to prevent deletion of the RG. Requires additional configuration
#resource "azurerm_management_lock" "resource-group-level" {
#  name       = "resource-group-cannotdelete-lock"
#  scope      = azurerm_resource_group.rg.id
#  lock_level = "CanNotDelete"
#  notes      = "This Resource Group is set to CanNotDelete to prevent accidental deletion."
#}

resource "random_pet" "azurerm_kubernetes_cluster_name" {
  prefix = "cluster"
}

resource "random_pet" "azurerm_kubernetes_cluster_dns_prefix" {
  prefix = "dns"
}

resource "azurerm_kubernetes_cluster" "primary" {
  location            = azurerm_resource_group.rg.location
  name                = random_pet.azurerm_kubernetes_cluster_name.id
  resource_group_name = azurerm_resource_group.rg.name
  dns_prefix          = random_pet.azurerm_kubernetes_cluster_dns_prefix.id
  sku_tier            = "Standard"

  identity {
    type = "SystemAssigned"
  }

  default_node_pool {
    name                         = "sys"
    vm_size                      = var.sys_vm_size
    max_pods                     = 100
    temporary_name_for_rotation  = "tempnodepool"
    only_critical_addons_enabled = true
    auto_scaling_enabled         = true
    min_count                    = var.sys_node_count
    max_count                    = var.sys_node_count
    upgrade_settings {
      max_surge = "10%"
    }
  }

  linux_profile {
    admin_username = var.username

    ssh_key {
      key_data = azapi_resource_action.ssh_public_key_gen.output.publicKey
    }
  }
  network_profile {
    network_plugin    = "azure"
    network_policy    = "azure"
    load_balancer_sku = "standard"
  }
  oms_agent {
    log_analytics_workspace_id      = azurerm_log_analytics_workspace.aks_logs.id
    msi_auth_for_monitoring_enabled = true
  }
}

resource "azurerm_kubernetes_cluster_node_pool" "tailnodes" {
  name                  = "tailnodes"
  mode                  = "User"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.primary.id
  vm_size               = var.sys_vm_size
  max_pods              = 100
  auto_scaling_enabled  = true
  min_count             = 1
  max_count             = 1
  node_labels = {
    "tailscale" = "true"
  }
}

resource "azurerm_kubernetes_cluster_node_pool" "webservice" {
  name                  = "webservice"
  mode                  = "User"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.primary.id
  vm_size               = "Standard_D32ds_v6"
  max_pods              = 100
  auto_scaling_enabled  = true
  min_count             = 2
  max_count             = 2
  node_labels           = {
    "webservice-node" = "true"
  }
}

resource "azurerm_kubernetes_cluster_node_pool" "otel" {
  name                  = "otel"
  mode                  = "User"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.primary.id
  vm_size               = "Standard_D16ds_v6"
  max_pods              = 100
  auto_scaling_enabled  = true
  min_count             = 2
  max_count             = 2
  node_labels           = {
    "otel-node" = "true"
  }
}

resource "azurerm_kubernetes_cluster_node_pool" "luserjava" {
  name                  = "luserjava"
  mode                  = "User"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.primary.id
  vm_size               = "Standard_D16ds_v6"
  max_pods              = 100
  auto_scaling_enabled  = true
  min_count             = var.litellm_node_count
  max_count             = var.litellm_node_count
  node_labels           = {
    "litellm-user-java-node" = "true"
  }
}

resource "azurerm_kubernetes_cluster_node_pool" "lmultilang" {
  name                  = "lmultilang"
  mode                  = "User"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.primary.id
  vm_size               = "Standard_D16ds_v6"
  max_pods              = 100
  auto_scaling_enabled  = true
  min_count             = var.litellm_node_count
  max_count             = var.litellm_node_count
  node_labels           = {
    "litellm-multilang-node" = "true"
  }
}

resource "azurerm_kubernetes_cluster_node_pool" "lpatch" {
  name                  = "lpatch"
  mode                  = "User"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.primary.id
  vm_size               = "Standard_D16ds_v6"
  max_pods              = 100
  auto_scaling_enabled  = true
  min_count             = var.litellm_node_count
  max_count             = var.litellm_node_count
  node_labels           = {
    "litellm-patch-node" = "true"
  }
}

resource "azurerm_kubernetes_cluster_node_pool" "capi" {
  count = var.capi_node_count == 1 ? 1 : 0
  name                  = "capi"
  mode                  = "User"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.primary.id
  vm_size               = "Standard_D128ds_v6"
  max_pods              = 100
  auto_scaling_enabled  = true
  min_count             = var.capi_node_count
  max_count             = var.capi_node_count
  node_labels           = {
    "capi-node" = "true"
  }
}

resource "azurerm_kubernetes_cluster_node_pool" "gpu" {
  name                  = "gpu"
  mode                  = "User"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.primary.id
  vm_size               = var.gpu_vm_size
  max_pods              = 100
  auto_scaling_enabled  = true
  min_count             = var.gpu_node_count
  max_count             = var.gpu_node_count
}

#Monitoring Log Anayltics
resource "azurerm_log_analytics_workspace" "aks_logs" {
  name                = "${random_pet.rg_name.id}-logs"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
}

resource "kubernetes_secret" "docker_registry_secret" {
  metadata {
    name      = "registry-secret"
    namespace = "crs-webservice"
  }

  type = "kubernetes.io/dockerconfigjson"

  data = {
    ".dockerconfigjson" = jsonencode({
      auths = {
        "${var.acr_server}" = {
          username = var.acr_id
          password = var.acr_pw
        },
        "ghcr.io" = {
          username = var.github_id
          password = var.github_pat
        },
      }
    })
  }
}
