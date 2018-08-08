#!/bin/sh

user=`whoami`
if [ $user != 'homework' ]; then
	echo "user is $user, not homework"
	exit 1
fi 

LOCAL=0
if [ $# -gt 0 ]; then
    if [ $1 == "local" ]; then
        LOCAL=1;
    fi
fi

PWD=`dirname $0`/../
PWD=$(cd $PWD; pwd)
CONF=$PWD/conf/nginx.conf
MY_NGINX=/home/homework/bin/my_nginx/sbin/nginx

PID=`ps -ef |grep $CONF | grep -v grep | grep -v rsync | awk '{print $2}'`
if [ -n "$PID" ]; then
    echo "already is running. pid: "$PID
    exit 1;
fi

cd $PWD
$MY_NGINX -p ./ -c $CONF 2>&1

sleep 1
PID=`ps -ef|grep $CONF | grep -v grep|grep -v rsync | awk '{print $2}'`
if [ -n "$PID" ]; then
    echo "start success, pid: "$PID
else
    echo "start failure"
fi
