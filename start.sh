#!/bin/bash
X=$(xrandr --current | grep '*' | uniq | awk '{print $1}' | cut -d 'x' -f1)
Y=$(xrandr --current | grep '*' | uniq | awk '{print $1}' | cut -d 'x' -f2)
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
xterm -fullscreen -fa monaco -fs ${SIZE} -bg black -fg green -e bash -c "docker run -it -e COLUMNS=213 -e LINES=58 --name maker --rm -v $(pwd):/data maker ./ia86"
