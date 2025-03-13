locals {
  dc_informaiton = yamldecode(file("../confgis/${var.vsphere_datacenter}.yaml"))
}