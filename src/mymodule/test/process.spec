##############################################################
# http://www.rpm.org/max-rpm/ch-rpm-inside.html              #
##############################################################

Name:%(echo server${SUFFIX})
#

Version:%{_version}
Release:%{_release}
Summary:server
URL: %{_svn_path}
Group: my_nginx
License: my_nginx
AutoReq: no
Requires: libuuid-devel >= 2.17.2 openssl-devel >= 1.0.1e-16 my_nginx >= 1.0.0-1 
BuildRequires: libuuid-devel >= 2.17.2 openssl-devel >= 1.0.1e-16 my_nginx >= 1.0.0-1 

#%post
#/sbin/ldconfig

%description
# if you want publish current svn URL or Revision use these macros
cpmplugin
%{_svn_path}
%{_svn_revision}

# prepare your files
%install
# OLDPWD is the dir of rpm_create running
# _prefix is an inner var of rpmbuild,
# can set by rpm_create, default is "/home/homework"
# _lib is an inner var, maybe "lib" or "lib64" depend on OS
# create dirs

mkdir -p $PWD/%{_prefix}/server/bin/
mkdir -p $PWD/%{_prefix}/server/plugin/
mkdir -p $PWD/%{_prefix}/server/logs/
mkdir -p $PWD/%{_prefix}/server/conf/

# copy files
cp -rf $OLDPWD/bin/*                    $PWD/%{_prefix}/server/bin/
cp -rf $OLDPWD/plugin/*                 $PWD/%{_prefix}/server/plugin/
cp -rf $OLDPWD/conf/*                 	$PWD/%{_prefix}/server/conf/

# package infomation
%files

# set file attribute here
# need not list every file here, keep it as this
%defattr(755,homework,homework)
%attr(755,homework,homework) %{_prefix}/server/bin/*
%attr(755,homework,homework) %{_prefix}/server/plugin/*

#%dir
# need not list every file here, keep it as this
%{_prefix}

# create an empy dir
# need bakup old config file, so indicate here
# indicate the dir for crontab


%changelog 
