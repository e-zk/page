#!/bin/sh
# fzypage
# (c) e-zk (2021) wtfpl

LINES=${LINES:-$(tput lines)}
SEL="$(page ls | fzy -l $LINES)"

# no selection, die
[ -z "$SEL" ] && exit 0

# do what is requested, open otherwise
page "${1:-open}" "$SEL" ;;
