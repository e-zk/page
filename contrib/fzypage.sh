#!/bin/sh
# fzypage
# (c) e-zk (2021) wtfpl

LINES=${LINES:-$(tput lines)}
SEL="$(page ls | fzy -l $LINES)"

[ -z "$SEL" ] && exit 0

case "$1" in
	"edit")
		page open $SEL
	;;
	*)
		page open $SEL
	;;
esac
