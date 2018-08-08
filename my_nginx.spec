##############################################################
# http://www.rpm.org/max-rpm/ch-rpm-inside.html              #
##############################################################

Name:%(echo my_nginx${SUFFIX})
#

Version:%{_version}
Release:%{_release}
Summary:my_nginx
URL: %{_svn_path}
Group: adplatform
License: adplatform
AutoReq: no
#Requires: 
BuildRequires: pcre-devel >= 7.8 

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


mkdir -p $PWD/%{_prefix}/include/my_nginx/
mkdir -p $PWD/%{_prefix}/bin/my_nginx/sbin


# copy files
cp -rf $OLDPWD/src/mymodule/module_common/plugin.h $PWD/%{_prefix}/include/my_nginx/
cp -rf $OLDPWD/objs/nginx $PWD/%{_prefix}/bin/my_nginx/sbin

# package infomation
%files

# set file attribute here
%defattr(755,homework,homework)
# need not list every file here, keep it as this
%attr(755,homework,homework) %{_prefix}/include/my_nginx/*
%attr(755,homework,homework) %{_prefix}/bin/my_nginx/sbin/*

#%dir
# need not list every file here, keep it as this
%{_prefix}

# create an empy dir
# need bakup old config file, so indicate here
# indicate the dir for crontab


%changelog 
