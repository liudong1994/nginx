if [ $# != 2 ];then
	echo "use : ./package.sh 1.0.0 1"
	exit -1
fi

rm -rf *.rpm
make clean;make
/home/homework/script/rpmbuild2  process.spec $1 $2 /home/homework/

