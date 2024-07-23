/* Commit: 50eb31d10390f638be2a99f3b064afcd090c08ea
 * File: applypatch
 * Line: 69
 * Code: 
 */

#!/bin/sh
##
## applypatch takes four file arguments, and uses those to
## apply the unpacked patch (surprise surprise) that they
## represent to the current tree.
##
## The arguments are:
##	$1 - file with commit message
##	$2 - file with the actual patch
##	$3 - file with list of filenames the patch touches
##	$4 - "info" file with Author, email and subject
##	$5 - optional file containing signoff to add
##
signoff="$5"
final=.dotest/final-commit
##
## If this file exists, we ask before applying
##
query_apply=.dotest/.query_apply
MSGFILE=$1
PATCHFILE=$2
FILES=$3
INFO=$4
EDIT=${VISUAL:-$EDITOR}
EDIT=${EDIT:-vi}

export AUTHOR_NAME="$(sed -n '/^Author/ s/Author: //p' .dotest/info)"
export AUTHOR_EMAIL="$(sed -n '/^Email/ s/Email: //p' .dotest/info)"
export SUBJECT="$(sed -n '/^Subject/ s/Subject: //p' .dotest/info)"

if [ -n "$signoff" -a -f "$signoff" ]; then
	cat $signoff >> $MSGFILE
fi

(echo "[PATCH] $SUBJECT" ; echo ; cat $MSGFILE ) > $final

f=0
[ -f $query_apply ] || f=1

while [ $f -eq 0 ]; do
	echo "Commit Body is:"
	echo "--------------------------"
	cat $final
	echo "--------------------------"
	echo -n "Apply? [y]es/[n]o/[e]dit/[a]ccept all "
	read reply
	case $reply in
		y|Y) f=1;;
		n|N) exit 2;;	# special value to tell dotest to keep going
		e|E) $EDIT $final;;
		a|A) rm -f $query_apply
		     f=1;;
	esac
done

echo
echo Applying "'$SUBJECT'"
echo

check-files $(cat $FILES) || exit 1
checkout-cache -q $(cat $FILES) || exit 1
patch -u --no-backup-if-mismatch -f -p1 --fuzz=0 --input=$PATCHFILE || exit 1
update-cache --add --remove $(cat $FILES) || exit 1
tree=$(write-tree) || exit 1
echo Wrote tree $tree
commit=$(commit-tree $tree -p $(cat .git/HEAD) < $final) || exit 1
echo Committed: $commit
echo $commit > .git/HEAD
