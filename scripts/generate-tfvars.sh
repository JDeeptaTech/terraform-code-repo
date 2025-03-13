#!/bin/bash

destination_dir=$1
requestor=$2
datacenter=$3

out_file="$destination_dir/terraform.tfvars"
tfvars_file_data=$(cat <<EOF
requestor = \"$requestor\"
vsphere_datacenter = \"$datacenter\"
EOF
)
eval "echo \"${tfvars_file_data}\"" > "$out_file"