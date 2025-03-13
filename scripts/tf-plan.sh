#!/bin/bash

echo "Current directory: $(pwd)"

terraform -chdir=src plan -out=tfplan
exitcode=$?

echo "Detailed exitcode $exitcode"
if [ $exitcode -eq 0 ]; then
  echo "Succeeded with empty diff (no changes)"
  terraform -chdir=src show -json tfplan > tfplan.json
  # echo '##vso[task.setvariable variable=changesDetected]false'
  exit 0
fi
if [ $exitcode -eq 1 ]; then
  echo "Error in plan file"
  exit 1
elif [ $exitcode -eq 2 ]; then
  echo "Succeeded with non-empty diff (changes present)"
  terraform -chdir=src show -json tfplan > tfplan.json
  # echo '##vso[task.setvariable variable=changesDetected]true'
  exit 0
else
  echo "Error in plan file"
  exit 1
fi
