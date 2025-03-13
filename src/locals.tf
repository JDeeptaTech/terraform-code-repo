locals {
  dc_informaiton = yamldecode(file("../configs/${var.vsphere_datacenter}.yaml"))
}
