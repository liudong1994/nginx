#!/bin/sh

user=`whoami`
if [ $user != 'homework' ]; then
	echo "user is $user, not homework"
	exit 1
fi 

PWD=`dirname $0`/../
PWD=$(cd $PWD; pwd)

#stop
$PWD/bin/stop.sh

#start
$PWD/bin/start.sh $1
