#!/bin/sh

PWD=`dirname $0`/../
PWD=$(cd $PWD; pwd)
CONF=$PWD/conf/nginx.conf
NGINX=/home/homework/bin/my_nginx/sbin/nginx

PID=`ps -ef |grep $CONF | grep -v grep | grep -v rsync | awk '{print $2}'`
if [ -z "$PID" ]; then
    echo "process was not running."
    exit 1
fi

echo "stopping process..."
cd $PWD
$NGINX -p ./ -c $CONF -s stop
sleep 1
success=0
for ((i=0; i<5; i++))
do
    PID=`ps -ef |grep $CONF | grep -v grep | grep -v rsync | awk '{print $2}'`
    if [ -z "$PID" ]; then
        success=1
        echo "stop success."
        break
    fi
    sleep 1
done
if [ $success -eq 0 ]; then
    echo "stop timeout."
    exit 1
fi
