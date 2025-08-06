resource "kubernetes_namespace" "crs_webservice" {
  metadata {
    name = "crs-webservice"
  }
}

resource "kubernetes_persistent_volume_claim" "shared_azurefile_pvc" {
  metadata {
    name      = "shared-crs-fs"
    namespace = "crs-webservice"
  }

  spec {
    access_modes = ["ReadWriteMany"]

    storage_class_name = "azurefile-csi-premium" #azurefile-csi-premium

    resources {
      requests = {
        storage = "8Ti"
      }
    }
  }
}

resource "kubernetes_persistent_volume_claim" "tarball_azurefile_pvc" {
  metadata {
    name      = "tarball-fs"
    namespace = "crs-webservice"
  }

  spec {
    access_modes = ["ReadWriteMany"]

    storage_class_name = "azurefile-csi-premium" #azurefile-csi-premium

    resources {
      requests = {
        storage = "8Ti"
      }
    }
  }
}

resource "kubernetes_persistent_volume_claim" "crs_db_backup" {
  metadata {
    name      = "crs-db-backup"
    namespace = "crs-webservice"
  }

  spec {
    access_modes = ["ReadWriteMany"]

    storage_class_name = "azurefile-csi-premium" #azurefile-csi-premium

    resources {
      requests = {
        storage = "8Ti"
      }
    }
  }
}

resource "kubernetes_persistent_volume_claim" "crs_multilang_db_backup" {
  metadata {
    name      = "crs-multilang-db-backup"
    namespace = "crs-webservice"
  }

  spec {
    access_modes = ["ReadWriteMany"]

    storage_class_name = "azurefile-csi-premium" #azurefile-csi-premium

    resources {
      requests = {
        storage = "8Ti"
      }
    }
  }
}

resource "kubernetes_persistent_volume_claim" "crs_java_cpmeta_db_backup" {
  metadata {
    name      = "crs-java-cpmeta-db-backup"
    namespace = "crs-webservice"
  }

  spec {
    access_modes = ["ReadWriteMany"]

    storage_class_name = "azurefile-csi-premium" #azurefile-csi-premium

    resources {
      requests = {
        storage = "1Ti"
      }
    }
  }
}

resource "kubernetes_storage_class_v1" "azurefile_csi_premium_litellm_pg" {
  metadata {
    name = "azurefile-csi-premium-litellm-pg"
  }
  storage_provisioner   = "file.csi.azure.com"
  reclaim_policy         = "Retain"
  volume_binding_mode    = "Immediate"
  allow_volume_expansion = true

  parameters = {
    skuName = "Premium_LRS"
  }

  mount_options = [
    "uid=999",
    "gid=999",
    "file_mode=0750",
    "dir_mode=0750"
  ]
}

resource "kubernetes_persistent_volume_claim" "litellm_db_backup" {
  metadata {
    name      = "litellm-db-backup"
    namespace = "crs-webservice"
  }

  spec {
    access_modes = ["ReadWriteMany"]

    storage_class_name = kubernetes_storage_class_v1.azurefile_csi_premium_litellm_pg.metadata[0].name

    resources {
      requests = {
        storage = "8Ti"
      }
    }
  }
}

resource "kubernetes_persistent_volume_claim" "otel_fs" {
  metadata {
    name      = "otel-fs"
    namespace = "crs-webservice"
  }

  spec {
    access_modes = ["ReadWriteMany"]

    storage_class_name = "azurefile-csi-premium" #azurefile-csi-premium

    resources {
      requests = {
        storage = "1Ti"
      }
    }
  }
}
