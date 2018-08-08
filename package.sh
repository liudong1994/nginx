if [ $# != 2 ];then
	echo "use : ./package.sh 1.0.0 1"
	exit -1
fi

rm *.rpm
make clean
./run.sh
/home/homework/script/rpmbuild2  my_nginx.spec $1 $2 /home/homework/

