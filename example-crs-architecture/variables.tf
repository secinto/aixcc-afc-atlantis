variable "resource_group_location" {
  type        = string
  default     = "westus"
  description = "Location of the resource group."
}

variable "resource_group_name_prefix" {
  type        = string
  default     = "example"
  description = "Prefix of the resource group name that's combined with a random ID so name is unique in your Azure subscription."
}

variable "sys_node_count" {
  type        = number
  description = "The initial quantity of nodes for the node pool."
  default     = 4
}

variable "usr_node_count" {
  type        = number
  description = "The initial quantity of nodes for the node pool."
  default     = 3
}

variable "capi_node_count" {
  type        = number
  description = "The initial quantity of nodes for the node pool."
  default     = 0
}

variable "litellm_node_count" {
  type        = number
  description = "The initial quantity of nodes for the node pool."
  default     = 4
}

variable "acr_server" {
  type        = string
  description = "acr server"
}

variable "acr_id" {
  type        = string
  description = "acr id"
}

variable "acr_pw" {
  type        = string
  description = "acr pw"
}

variable "github_id" {
  type        = string
  description = "github id"
}

variable "github_pat" {
  type        = string
  description = "github pat"
}

variable "sys_vm_size" {
  type        = string
  description = "The vm size of sys node"
  default     = "Standard_D16ds_v6"
}

variable "cp_mgr_vm_size" {
  type        = string
  description = "The vm size of cp_mgr node"
  default     = "Standard_D32ds_v6"
}

variable "username" {
  type        = string
  description = "The admin username for the new cluster."
  default     = "azureadmin"
}

variable "ARM_SUBSCRIPTION_ID" {
  type        = string
  description = "Azure subscription ID"
}

variable "ARM_TENANT_ID" {
  type        = string
  description = "Azure tenant ID"
}

variable "ARM_CLIENT_ID" {
  type        = string
  description = "Azure client ID"
}

variable "ARM_CLIENT_SECRET" {
  type        = string
  sensitive   = true
  description = "Azure client secret"
}

variable "gpu_node_count" {
  type        = number
  description = "The initial quantity of nodes for the GPU node pool."
  default     = 1
}

variable "gpu_vm_size" {
  type        = string
  description = "The vm size for GPU nodes"
  default     = "standard_nc64as_t4_v3"
}

variable "huggingface_token" {
  type        = string
  description = "Hugging Face API token for accessing Llama model"
  sensitive   = true
}
