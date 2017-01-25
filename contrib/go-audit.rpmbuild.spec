# Update this commit hash to the desired release hash to package
%global commit 56a1a65a67038849223779fa53611809a832ac0d
%global shortcommit %(c=%{commit}; echo ${c:0:7})
%global debug_package %{nil}

%if 0%{?fedora} >= 15 || 0%{?rhel} >= 7
%define use_systemd 1
%else
%define use_systemd 0
%endif

Name:             go-audit
Version:          0
Release:          1.git%{shortcommit}%{?dist}
Summary:          go-audit is an alternative to the auditd daemon that ships with many distros.

License:          MIT
URL:              https://github.com/slackhq/go-audit
Source0:          https://github.com/slackhq/go-audit/archive/%{commit}/go-audit-%{shortcommit}.tar.gz

# Golang 1.7 or higher is currently a requirement to build. However, there is not currently a package for golang 1.7 on
# CentOS 7. Instead, the official release can be installed manually, however please ensure that it is in your PATH.
#BuildRequires:    golang >= 1.7

Requires:         /sbin/auditctl

%if %{use_systemd}
BuildRequires:    systemd
Requires(post):   systemd
Requires(preun):  systemd
Requires(postun): systemd
%else
Requires(post):   chkconfig
Requires(preun):  chkconfig, initscripts
%endif

%description
go-audit is an alternative to the auditd daemon that ships with many distros.

%prep
%setup -q -n go-audit-%{commit}

%build
mkdir -p ./_build/src/github.com/slackhq
ln -s $(pwd) ./_build/src/github.com/slackhq/go-audit
export GOPATH=$(pwd)/_build
export PATH=$PATH:$(pwd)/_build/bin

go get -u github.com/kardianos/govendor
pushd _build/src/github.com/slackhq/go-audit
make
popd

%install
install -d %{buildroot}/usr/local/bin
install -d %{buildroot}%{_sysconfdir}
install -d %{buildroot}%{_sysconfdir}/logrotate.d
install -m 0750 -d %{buildroot}%{_localstatedir}/log/go-audit
install -m 0755 ./go-audit %{buildroot}/usr/local/bin/go-audit
install -m 0644 ./go-audit.yaml.example %{buildroot}%{_sysconfdir}/go-audit.yaml.example
install -m 0644 ./contrib/logrotate.go-audit.conf %{buildroot}%{_sysconfdir}/logrotate.d/go-audit

%if %{use_systemd}
install -d %{buildroot}%{_unitdir}
install -m 0644 ./contrib/systemd.go-audit.service %{buildroot}%{_unitdir}/go-audit.service
%else
install -d %{buildroot}%{_initddir}
install -m 0755 ./contrib/rh-sysv.go-audit.init %{buildroot}%{_initddir}/go-audit
%endif

%post
%if %{use_systemd}
%systemd_post go-audit.service
%else
if [ $1 -eq 1 ]
then
    /sbin/chkconfig --add go-audit
fi
%endif

%preun
%if %{use_systemd}
%systemd_preun go-audit.service
%else
if [ $1 -eq 0 ]
then
    /sbin/service go-audit stop >/dev/null 2>&1
    /sbin/chkconfig --del go-audit
fi
%endif

%postun
%if %{use_systemd}
%systemd_postun go-audit.service
%endif

%files
%defattr(-,root,root,-)
%doc README.md
%dir %{_localstatedir}/log/go-audit
/usr/local/bin/go-audit
%{_sysconfdir}/go-audit.yaml.example
%{_sysconfdir}/logrotate.d/go-audit
%if %{use_systemd}
%{_unitdir}/go-audit.service
%else
%{_initddir}/go-audit
%endif
