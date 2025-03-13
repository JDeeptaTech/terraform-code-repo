#!/bin/bash

destination_dir=$1
requestor=$2

out_file="$destination_dir/terraform.tfvars"
tfvars_file_data=$(cat <<EOF
requestor = \"$requestor\"
EOF
)
eval "echo \"${tfvars_file_data}\"" > "$out_file"