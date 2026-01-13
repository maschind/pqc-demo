#!/bin/bash

set -e

baseline=$(git diff --numstat $(git hash-object -t tree /dev/null) main -- \
  '*.java' '*.properties' '*.xml' '*.sh' '*.md' 'pom.xml' \
  | awk '{add+=$1} END {print add}')

changed=$(git diff --numstat main...feature/pqc-ready -- \
  '*.java' '*.properties' '*.xml' '*.sh' '*.md' 'pom.xml' \
  | awk '{add+=$1; del+=$2} END {print add+del}')

echo "Baseline LOC (main): $baseline"
echo "Changed LOC: $changed"
echo "Churn: $(echo "scale=2; ($changed/$baseline)*100" | bc)%"