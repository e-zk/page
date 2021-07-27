#!/bin/sh
# fzypage
# (c) e-zk (2021) wtfpl

LINES=${LINES:-$(tput lines)}
SEL="$(page ls | fzy -l $LINES)"

# no selection, die
[ -z "$SEL" ] && exit 0

# edit if requested, open otherwise
case "$1" in
	"edit") page edit "$SEL" ;;
	*)      page open "$SEL" ;;
esac
