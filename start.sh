#!/bin/bash
X=$(xrandr --current | grep '*' | uniq | awk '{print $1}' | cut -d 'x' -f1)
Y=$(xrandr --current | grep '*' | uniq | awk '{print $1}' | cut -d 'x' -f2)
KITTY=$(kitty -v|grep created)
if [ "${KITTY}" != "" ]; then
	echo "Kitty installé"
	if [ ${X} -ge 1920 ]; then
		kitty --start-as fullscreen ./ia86 $1
		exit
	fi
fi
if [ ${X} -ge 1920 ]; then
	SIZE=11
elif [ ${X} -ge 1680 ]; then
	SIZE=10
elif [ ${X} -ge 1440 ]; then
	SIZE=9
elif [ ${X} -ge 1368 ]; then
	SIZE=8
elif [ ${X} -ge 1280 ]; then
	SIZE=7
else
	SIZE=6
fi
xterm -fullscreen -fa monaco -fs ${SIZE} -bg black -fg green -e "sleep 0.4;./ia86 $1"
