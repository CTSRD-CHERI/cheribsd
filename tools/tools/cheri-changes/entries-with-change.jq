# Output a list of entries containing the change $change
# usage: jq --argjson change '"<change>"' -f entries-with-change.jq
. | map(select(.changes[] | contains ($change)))
