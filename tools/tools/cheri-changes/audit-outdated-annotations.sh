#!/bin/sh

if [ $# -gt 1 ]; then
	usage
elif [ $# -eq 1 ]; then
	path=$1
else
	path=.
fi

today=$(env TZ=UTC date +%Y%m%d)

for file in $(cd $path; git grep -l "CHERI CHANGES"); do
	if [ $(dirname $file) = "tools/tools/cheri-changes" ]; then
		continue
	fi
	last_commit=$(env TZ=UTC date -r $(git log -1 --format=%ct $file) +%Y%m%d)
	last_annotated=$(${path}/tools/tools/cheri-changes/extract-cheri-changes.awk $file | jq '.[0]|.updated')
	if [ $last_commit -le $last_annotated ]; then
		continue
	fi
	echo "$file needs updating"
	git diff $(cat .last_merge) $file
	${path}/tools/tools/cheri-changes/extract-cheri-changes.awk $file
	while read -p "Action (d)one, (e)dit, (s)how, (u)pdate, e(x)it: " answer; do
		case $answer in
		d)
			break
			;;
		e)
			${EDITOR:-vi} $file
			;;
		s)
			git diff $(cat .last_merge) $file
			;;
		u)
			echo "Updating $file"
			sed -i "" -e "s/\"updated\": $last_annotated,/\"updated\": $today,/" $file
			;;
		x)
			exit
			;;
		esac
		last_annotated=$(${path}/tools/tools/cheri-changes/extract-cheri-changes.awk $file | jq '.[0]|.updated')
		if [ $last_commit -le $last_annotated ]; then
			break
		fi
		echo "$file needs updating"
	done

done
