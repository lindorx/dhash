#
# Regular cron jobs for the dhash package
#
0 4	* * *	root	[ -x /usr/bin/dhash_maintenance ] && /usr/bin/dhash_maintenance
