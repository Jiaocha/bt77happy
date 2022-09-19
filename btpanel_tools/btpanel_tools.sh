#!/bin/bash
#全局变量
download_url=https://gitee.com/gacjie/btpanel_tools/raw/master
panel_path=/www/server/panel
btdown_url=http://download.bt.cn
tools_version='220516'
#检查是否安装面板
if [ ! -f "/etc/init.d/bt" ] || [ ! -d "/www/server/panel" ]; then
	echo -e "此服务器没有安装宝塔！"
	exit;
fi
p_version=$(cat ${panel_path}/class/common.py|grep "version = "|awk '{print $3}'|tr -cd [0-9.])
btpanel_version=${p_version:0:5}
#获取包管理器
if [ -f "/usr/bin/yum" ] && [ -f "/etc/yum.conf" ]; then
	PM="yum"
elif [ -f "/usr/bin/apt-get" ] && [ -f "/usr/bin/dpkg" ]; then
	PM="apt-get"		
fi

#检测新版本
new_version(){
    new_version=$(curl -Ss --connect-timeout 100 -m 300 ${download_url}/version.txt)
    if [ "$new_version" = '' ];then
	    echo -e "获取版本号失败正在尝试更新......"
	    wget -O btpanel_tools.sh ${download_url}/btpanel_tools.sh && bash btpanel_tools.sh
	    exit 0
	    
    fi
    if [ "${new_version}" != ${tools_version} ];then
        echo -e "检测到已发布新版本正在尝试更新......"
	    wget -O btpanel_tools.sh ${download_url}/btpanel_tools.sh && bash btpanel_tools.sh
	    exit 0
    fi
    echo -e "还没有发布新版本"
    back_home
}
#清理垃圾
cleaning_garbage(){
    echo -e "正在清理官方版残留文件......"
    rm -f www/server/panel/data/bind.pl
    rm -rf ${panel_path}/adminer
    rm -rf /www/server/adminer
    rm -rf /www/server/phpmyadmin/pma
    rm -rf ${panel_path}/data/home_host.pl
    echo -e "正在清理破解版残留文件......"
    rm -f ${panel_path}/plugin/shoki_cdn
    echo -e "正在清理面板缓存......"
    rm -f ${panel_path}/*.pyc
    rm -f ${panel_path}/class/*.pyc
    rm -rf /tmp/*.pl
    rm -rf /tmp/*.sh
    rm -rf /tmp/*.log
    rm -f ${panel_path}/data/auth_list.json
    rm -rf ${panel_path}/data/check_domain/*.pl
    echo -e "正在清理PHP_SESSION......"
    rm -rf /tmp/sess_*
    echo -e "正在清理面板日志......"
    rm -rf ${panel_path}/logs/*.log
    rm -rf ${panel_path}/logs/*.gz
    rm -rf ${panel_path}/logs/request/*
    echo -e "正在清理邮件日志......"
    rm -rf /var/spool/plymouth/*
    rm -rf /var/spool/postfix/*
    rm -rf /var/spool/lpd/*
    echo -e "正在清理系统使用痕迹..."
    cat /dev/null > /var/log/boot.log
    cat /dev/null > /var/log/btmp
    cat /dev/null > /var/log/cron
    cat /dev/null > /var/log/dmesg
    cat /dev/null > /var/log/firewalld
    cat /dev/null > /var/log/grubby
    cat /dev/null > /var/log/lastlog
    cat /dev/null > /var/log/mail.info
    cat /dev/null > /var/log/maillog
    cat /dev/null > /var/log/messages
    cat /dev/null > /var/log/secure
    cat /dev/null > /var/log/spooler
    cat /dev/null > /var/log/syslog
    cat /dev/null > /var/log/tallylog
    cat /dev/null > /var/log/wpa_supplicant.log
    cat /dev/null > /var/log/wtmp
    cat /dev/null > /var/log/yum.log
    history -c
    read -p "是否要清理网站日志文件（y：确认/n：取消）:" function
	if [ "${function}" == "y" ]; then
        echo -e "正在清理网站日志......"
        rm -rf /www/wwwlogs/*.log
        rm -rf /www/wwwlogs/*.gz
	fi
    echo -e "垃圾文件清理完毕！您的服务器身轻如燕！"
    back_home
}
#面板优化
panel_optimization(){
    echo -e "正在去除创建网站自动创建的默认文件......"
    sed -i "/htaccess = self.sitePath+'\/.htaccess'/, /public.ExecShell('chown -R www:www ' + htaccess)/d" ${panel_path}/class/panelSite.py
    sed -i "/index = self.sitePath+'\/index.html'/, /public.ExecShell('chown -R www:www ' + index)/d" ${panel_path}/class/panelSite.py
    sed -i "/doc404 = self.sitePath+'\/404.html'/, /public.ExecShell('chown -R www:www ' + doc404)/d" ${panel_path}/class/panelSite.py
    echo -e "正在关闭未绑定域名提示页面......"
    sed -i "s/root \/www\/server\/nginx\/html/return 400/" ${panel_path}/class/panelSite.py
    if [ -f ${panel_path}/vhost/nginx/0.default.conf ]; then
    	sed -i "s/root \/www\/server\/nginx\/html/return 400/" ${panel_path}/vhost/nginx/0.default.conf
    fi
    echo -e "正在关闭安全入口登录提示页面......"
    sed -i "s/return render_template('autherr.html')/return abort(404)/" ${panel_path}/BTPanel/__init__.py
    echo -e "正在去除消息推送与文件校验......"
    sed -i "/p = threading.Thread(target=check_files_panel)/, /p.start()/d" ${panel_path}/task.py
    sed -i "/p = threading.Thread(target=check_panel_msg)/, /p.start()/d" ${panel_path}/task.py
    echo -e "正在去除自动验证云端状态......"
    sed -i "/p = threading.Thread(target=update_software_list)/, /p.start()/d" ${panel_path}/task.py
    sed -i '/self.get_cloud_list_status/d' ${panel_path}/class/panelPlugin.py
    echo -e "正在关闭活动推荐与在线客服......"
    if [ ! -f ${panel_path}/data/not_recommend.pl ]; then
    	echo "True" > ${panel_path}/data/not_recommend.pl
    fi
    if [ ! -f ${panel_path}/data/not_workorder.pl ]; then
    	echo "True" > ${panel_path}/data/not_workorder.pl
    fi
    echo -e "正在关闭首页软件推荐与广告......"
    sed -i '/def get_pay_type(self,get):/a \ \ \ \ \ \ \ \ return [];' ${panel_path}/class/ajax.py
    echo -e "正在关闭宝塔拉黑检测与提示......"
    sed -i '/self._check_url/d' ${panel_path}/class/panelPlugin.py
    echo -e "正在关闭面板日志与绑定域名上报."
    sed -i "/^logs_analysis()/d" ${panel_path}/script/site_task.py
    sed -i "s/run_thread(cloud_check_domain,(domain,))/return/" ${panel_path}/class/public.py
    echo -e "正在关闭自动强制面板升级更新."
    sed -i "/#是否执行升级程序/a \ \ \ \ \ \ \ \ \ \ \ \ updateInfo[\'force\'] = False;" ${panel_path}/class/ajax.py
    rm -f ${panel_path}/data/autoUpdate.pl
    echo -e "关闭自动更新软件列表."
    sed -i 's/plugin_timeout = 86400/plugin_timeout = 0/g' ${panel_path}/class/public.py
    read -p "是否需要去除计算验证（y：确认/n：取消）:" function
	if [ "${function}" == "y" ]; then
        echo -e "正在去除计算验证......"
        Layout_file="/www/server/panel/BTPanel/templates/default/layout.html";
        JS_file="/www/server/panel/BTPanel/static/bt.js";
        if [[ "${btpanel_version}" == "7.7.0" ]]; then
            if [ `grep -c "<script src=\"/static/bt.js\"></script>" $Layout_file` -eq '0' ];then 
                sed -i '/{% block scripts %} {% endblock %}/a <script src="/static/bt.js"></script>' $Layout_file; 
            fi;
            wget ${download_url}/bt.js -O $JS_file;
        fi;
        if [[ "${btpanel_version}" == "7.9.0" ]]; then
            if [ `grep -c "<script src=\"/static/bt.js\"></script>" $Layout_file` -eq '0' ];then
            	sed -i '/<\/body>/i <script src="/static/bt.js"></script>' $Layout_file;
            fi;
            wget ${download_url}/bt_new.js -O $JS_file;
        fi;
	fi
    /etc/init.d/bt restart
    echo -e "在面板首页“修复面板”即可恢复原样"
    back_home
}
#漏洞修复
bug_fix(){
    echo -e "正在检查宝塔面板PMA漏洞......"
    pma_bug=/www/server/phpmyadmin/pma
    if [ ! -d ${pma_bug} ]; then
        echo -e "发现宝塔面板PMA漏洞正在处理......"
        rm -rf ${pma_bug}
    else
        echo -e "未发现宝塔面板PMA漏洞......"
    fi;
    echo -e "漏洞检查处理完毕......"
}
#去除强制登陆
mandatory_landing(){
    clear
    panel_version=${btpanel_version//./}
    if [[ "${panel_version}" > "770" ]]; then
        echo '由于7.8.0版本开始使用登陆后的数据作为通信密钥，因此无法直接去除限制。'
        read -p "是否要降级到7.7.0版本（y：确认/n：取消）:" function
    	if [ "${function}" == "y" ]; then
            version=7.7.0
            degrade_btpanel
        else
            back_home
            exit 0
    	fi
	fi
	userinfo=${panel_path}/data/userInfo.json
	if [ -f "${userinfo}" ]; then
        chattr -i ${userinfo}
        rm -f ${userinfo}
	fi
    rm -f ${panel_path}/data/bind.pl
    rm -f ${panel_path}/data/sid.pl
    back_home
}
#修复网络
_fix_node(){
    host_ip=(128.1.164.196 116.213.43.206 125.90.93.52 36.133.1.8 116.10.184.219)
    tmp_file1=/dev/shm/net_test1.pl
    [ -f "${tmp_file1}" ] && rm -f ${tmp_file1}
	touch $tmp_file1
    ser_name="api.bt.cn"

    for host in ${host_ip[@]};
	do
		NODE_CHECK=$(curl --resolv ${ser_name}:443:${host} --connect-timeout 3 -m 3 2>/dev/null -w "%{http_code} %{time_total}" https://${ser_name} -o c${ser_name}.txt|xargs)
		rm -rf c${ser_name}.txt
		NODE_STATUS=$(echo ${NODE_CHECK}|awk '{print $1}')
		TIME_TOTAL=$(echo ${NODE_CHECK}|awk '{print $2 * 1000 - 500 }'|cut -d '.' -f 1)
		if [ "${NODE_STATUS}" == "200" ];then
			if [ $TIME_TOTAL -lt 100 ];then
				echo "$host" >> $tmp_file1
			fi
		fi
	done
    NODE_URL=$(cat $tmp_file1|sort -r -g -t " " -k 1|head -n 1|awk '{print $1}')

	rm -f $tmp_file1
    echo "$NODE_URL www.bt.cn api.bt.cn download.bt.cn dg2.bt.cn dg1.bt.cn" >> /etc/hosts
}
#修复面板
update_panel(){
    echo -e "正在检查并修复与宝塔链接的网络......"
    chattr -i /etc/hosts
    sed -i "/bt.cn/d" /etc/hosts
    bt_check_01=$(curl -s -m 5 -w "%{http_code}\n" https://www.bt.cn -o cwww.bt.cn.txt)
    bt_check_02=$(curl -s -m 5 -w "%{http_code}\n" https://api.bt.cn -o capi.bt.cn.txt)
    bt_check_03=$(curl -s -m 5 -w "%{http_code}\n" http://download.bt.cn -o cdownload.bt.cn.txt)
    if [ "${bt_check_01}" != 200 ] || [ "${bt_check_02}" != 200 ] || [ "${bt_check_03}" != 200 ]; then
        _fix_node
    else
        rm -f *.bt.cn.txt
    fi
    echo -e "正在解锁清理破解版修改的文件......"
    GET_BT=$(cat ${panel_path}/pyenv/lib/python3.7/urllib/request.py | grep bt.cn)
    GET_BT01=$(cat ${panel_path}/pyenv/lib/python3.7/site-packages/requests/api.py | grep bt.cn)
	if [ "${GET_BT}" ] || [ "${GET_BT01}" ]; then
        wget -O ${panel_path}/pyenv/lib/python3.7/urllib/request.py ${download_url}/request.py -T 10
        wget -O ${panel_path}/pyenv/lib/python3.7/site-packages/requests/api.py ${download_url}/api.py -T 10
	fi
    chattr -i ${panel_path}/class/panelAuth.py
    p_path=${panel_path}/class/panelPlugin.py
    if [ ! -f "${p_path}" ];then
		chattr -R -ia /www
		cp -ri /www/backup/panel/vhost/* ${panel_path}/vhost/*
    fi
    chattr -i ${panel_path}/class/panelPlugin.py
    chattr -i ${panel_path}/class/public.py
    chattr -ia /etc/init.d/bt
    chattr -i /etc/init.d/bt
    rm -f ${panel_path}/init.sh
    rm -f /etc/init.d/bt
    wget -O /etc/init.d/bt http://download.bt.cn/install/src/bt6.init -T 10
    chmod +x /etc/init.d/bt
    rm -f ${panel_path}/plugin/shoki_cdn
    rm -rf ${panel_path}/adminer
    rm -rf /www/server/adminer
    rm -rf /www/server/phpmyadmin/pma
    rm -f ${panel_path}/data/home_host.pl
    chattr -i ${panel_path}/data/plugin.json
    rm -f ${panel_path}/data/plugin.json
    chattr -i ${panel_path}/install/check.sh
    rm -f ${panel_path}/install/check.sh
    chattr -i ${panel_path}/install/public.sh
    rm -f ${panel_path}/install/public.sh
    wget -O ${panel_path}/install/public.sh http://download.bt.cn/install/public.sh -T 10
    chattr -i ${panel_path}/data/auth_list.json
    rm -f ${panel_path}/data/auth_list.json
    chattr -i ${panel_path}/data/plugin_bin.pl
    rm -f ${panel_path}/data/plugin_bin.pl
    chattr -i ${panel_path}/data/userInfo.json
    rm -f ${panel_path}/data/userInfo.json
    rm -f ${panel_path}/class/*.so
    config=${panel_path}/config/config.json
    home=$(grep -Po 'home[" :]+\K[^"]+' ${config})
    home=$(echo ${home} | awk -F'[/:]' '{print $4}')
    if [ "${home}" != "www.bt.cn" ];then
        sed -i "s!${home}!www.bt.cn!g" ${config}
    fi
    download=$(grep -Po 'download[" :]+\K[^"]+' ${config})
    download=$(echo ${download} | awk -F'[/:]' '{print $4}')
    if [[ "${download}" != "" ]]&&[[ "${download}" != "download.bt.cn" ]];then
    	sed -i "s#${download}#download.bt.cn#g" ${config}
    fi 
    chattr -R -ia /www/server/panel
    chattr -ia /dev/shm/session.db
    rm -f /dev/shm/session.db
    echo "False" > /etc/bt_crack.pl
    echo -e "正在修复宝塔所需依赖软件包......"
    ${PM} -y install make cmake gcc gcc-c++ gcc-g77 flex bison file libtool libtool-libs autoconf kernel-devel patch wget libjpeg libjpeg-devel libpng libpng-devel libpng10 libpng10-devel gd gd-devel libxml2 libxml2-devel zlib zlib-devel glib2 glib2-devel tar bzip2 bzip2-devel libevent libevent-devel ncurses ncurses-devel curl curl-devel libcurl libcurl-devel e2fsprogs e2fsprogs-devel krb5 krb5-devel libidn libidn-devel openssl openssl-devel vim-minimal gettext gettext-devel ncurses-devel gmp-devel pspell-devel libcap diffutils ca-certificates net-tools libc-client-devel psmisc libXpm-devel git-core c-ares-devel libicu-devel libxslt libxslt-devel zip unzip glibc.i686 libstdc++.so.6 cairo-devel bison-devel ncurses-devel libaio-devel perl perl-devel perl-Data-Dumper lsof pcre pcre-devel vixie-cron crontabs expat-devel readline-devel libsodium-dev automake perl-ExtUtils-Embed GeoIP GeoIP-devel GeoIP-data freetype freetype-devel libffi-devel libmcrypt-devel epel-release libsodium-devel sqlite-devel tk-devel gdbm-devel db4-devel libpcap-devel xz-devel
    echo -e "正在修复宝塔并清理缓存文件......"
    curl https://download.bt.cn/install/update_panel.sh|bash
    rm -rf www/server/panel/data/bind.pl
    #修复拉黑
    echo -e "正在修复宝塔拉黑限制......"
    sed -i '/self._check_url/d' ${panel_path}/class/panelPlugin.py
    rm -f ${panel_path}/*.pyc
    rm -f ${panel_path}/class/*.pyc
    back_home
}
#停止服务
stop_btpanel(){
	SERVICE_NAME=(bt nginx httpd mysqld pure-ftpd php-fpm-52 php-fpm-53 php-fpm-54 php-fpm-55 php-fpm-56 php-fpm-70 php-fpm-71 php-fpm-72 php-fpm-73 php-fpm-74 php-fpm-80 php-fpm-81 redis memcached);
	for service in ${SERVICE_NAME[@]};
	do 	
	    service_path=/etc/init.d/${service}
	    if [ -e "${service_path}" ];then
            ${service_path} stop
		fi
	done
}
#卸载面板
uninstall_btpanel(){
    read -p "是否要卸载运行环境（y：确认/n：取消）:" function
	if [ "${function}" == "y" ]; then
        echo -e "正在卸载运行环境......"
        if [ -f "/usr/bin/yum" ] && [ -f "/usr/bin/rpm" ]; then
			Remove_Rpm
		fi
		Remove_Service
	fi
    echo -e "正在卸载宝塔面板......"
	/etc/init.d/bt stop
	if [ -f "/usr/sbin/chkconfig" ];then
		chkconfig --del bt
	elif [ -f "/usr/sbin/update-rc.d" ];then
		update-rc.d -f bt remove
	fi
	rm -rf /www/server/panel
	rm -f /etc/init.d/bt 
}
#清理rpm包
Remove_Rpm(){
	echo -e "正在查询并清理已安装rpm包.."
	for lib in bt-nginx bt-httpd bt-mysql bt-curl bt-AliSQL AliSQL-master bt-mariadb bt-php-5.2 bt-php-5.3 bt-php-5.4 bt-php-5.5 bt-php-5.6 bt-php-7.0 bt-php-7.1
	do
		rpm -qa |grep ${lib} > ${lib}.pl
		libRpm=`cat ${lib}.pl`
		if [ "${libRpm}" != "" ]; then
			rpm -e ${libRpm} --nodeps > /dev/null 2>&1
			echo -e ${lib} "\033[32mclean\033[0m"
		fi
		rm -f ${lib}.pl
	done
	yum remove bt-openssl* -y
	yum remove bt-php* -y
}
Remove_Service(){
    echo -e "正在清除面板运行环境"
	servicePath="/www/server"
	for service in nginx httpd mysqld pure-ftpd tomcat redis memcached mongodb pgsql tomcat tomcat7 tomcat8 tomcat9 php-fpm-52 php-fpm-53 php-fpm-54 php-fpm-55 php-fpm-56 php-fpm-70 php-fpm-71 php-fpm-72 php-fpm-73
	do
		if [ -f "/etc/init.d/${service}" ]; then
			/etc/init.d/${service} stop
			if [ -f "/usr/sbin/chkconfig" ];then
				chkconfig  --del ${service}
			elif [ -f "/usr/sbin/update-rc.d" ];then
				update-rc.d -f ${service} remove
			fi

			if [ "${service}" = "mysqld" ]; then
			 	rm -rf ${servicePath}/mysql
			 	rm -f /etc/my.cnf
			elif [ "${service}" = "httpd" ]; then
				rm -rf ${servicePath}/apache
			elif [ "${service}" = "memcached" ]; then
				rm -rf /usr/local/memcached
			elif [ -d "${servicePath}/${service}" ]; then
				rm -rf ${servicePath}/${service}
			fi 
			rm -f /etc/init.d/${service}
			echo -e ${service} "\033[32mclean\033[0m"
		fi
	done
	[ -d "${servicePath}/php" ] && rm -rf ${servicePath}/php
	if [ -d "${servicePath}/phpmyadmin" ]; then
		rm -rf ${servicePath}/phpmyadmin
		echo -e "phpmyadmin" "\033[32mclean\033[0m"
	fi

	if [ -d "${servicePath}/nvm" ]; then
		source /www/server/nvm/nvm.sh
		pm2 stop all
		rm -rf ${servicePath}/nvm
		sed -i "/NVM/d" /root/.bash_profile
		sed -i "/NVM/d" /root/.bashrc
		echo -e "node.js" "\033[32mclean\033[0m"
	fi
}
#宝塔磁盘挂载
mount_disk(){
	echo -e "注意：本工具会将数据盘挂载到www目录。15秒后跳转到挂载脚本。"
    sleep 15s
	wget -O auto_disk.sh http://download.bt.cn/tools/auto_disk.sh && sudo bash auto_disk.sh
	rm -rf /auto_disk.sh
    rm -rf auto_disk.sh
    back_home
}
#降级版本
degrade_btpanel(){
    if [ ! -d ${panel_path}/BTPanel ];then
    	echo "============================================="
    	echo "错误, 5.x不可以使用此命令升级!"
    	echo "5.9平滑升级到6.0的命令：curl http://download.bt.cn/install/update_to_6.sh|bash"
    	exit 0;
    fi
    wget -T 5 -O panel.zip https://raw.githubusercontent.com/gacjie/btpanel_tools/main/update/LinuxPanel-${version}.zip
    unzip -o panel.zip -d /www/server/ > /dev/null
    rm -f panel.zip
    rm -f ${panel_path}/*.pyc
    rm -f ${panel_path}/class/*.pyc
    sleep 1 && service bt restart > /dev/null 2>&1 &
    echo "====================================="
    echo "你已降级为${version}版";
    back_home
}
#升级腾讯专享版
Install_tencent()
{
	pip install tencentcloud-sdk-python
	btpip install tencentcloud-sdk-python
    echo -n 'tencent' > ${panel_path}/data/o.pl
    echo '正在安装腾讯云专享版...'
    mkdir -p ${panel_path}/plugin/tencent
    wget -O ${panel_path}/plugin/tencent/tencent_main.py $btdown_url/install/plugin/tencent/tencent_main.py -T 5
    mkdir -p ${panel_path}/BTPanel/static/other/js
    wget -O ${panel_path}/BTPanel/static/other/js/tencent.js $btdown_url/install/plugin/tencent/js/tencent.js -T 5
    mkdir -p ${panel_path}/BTPanel/static/other/css
    wget -O ${panel_path}/BTPanel/static/other/css/tencent.css $btdown_url/install/plugin/tencent/css/tencent.css -T 5
    sed -i "s/宝塔Linux面板/宝塔面板·腾讯云专享版/g" /www/server/panel/config/config.json
    sed -i "s/\"Linux面板\"/\"·腾讯云专享版\"/g" /www/server/panel/config/config.json
    sed -i "s/\"webssh\",\"linuxsys\"/\"txcdn\",\"cosfs\",\"dnspod\"/g" /www/server/panel/config/index.json
	mkdir -p ${panel_path}/plugin/tencent
	echo  -e '安装腾讯云专享版完成'
	back_home
}
#恢复宝塔官方版
Uninstall_tencent()
{
	rm -rf /www/server/panel/plugin/tencent
    rm -rf /www/server/panel/BTPanel/static/other/js/tencent.js
    rm -rf /www/server/panel/BTPanel/static/other/css/tencent.css
    rm -rf /www/server/panel/data/o.pl
    echo -e "恢复官方版成功"
    back_home
}
#升级查杀库
update_wafrule(){
    wget -O /root/rule.json ${download_url}/rule.json
	PLUGIN_NAME=(free_waf btwaf btwaf_httpd hm_shell_san webshell);
	for name in ${PLUGIN_NAME[@]};
	do
		PLUGIN_PATH=${panel_path}/plugin/${name}/rule.json
		if [ -e "${PLUGIN_PATH}" ];then
		    \cp -rf /root/rule.json  ${PLUGIN_PATH}
		    echo -e "完成升级${name}的查杀库"
		fi
	done
	rm -rf /root/rule.json
	back_home
}
#开启完全离线服务
open_offline(){
    read -p "请在执行前更新下软件商店，确保软件列表缓存文件存在。（y：确认/n：取消）:" function
	if [ "${function}" == "y" ]; then
        sed -i 's/plugin_timeout = 86400/plugin_timeout = 0/g' ${panel_path}/class/public.py
        rm -f ${panel_path}/data/home_host.pl
        echo 'True' >${panel_path}/data/not_network.pl
        \cp -rf ${panel_path}/config/hosts.json  ${panel_path}/config/hosts.json.bk
        echo '[ "127.0.0.1" ]' >${panel_path}/config/hosts.json
        chattr -i /etc/hosts
        sed -i "/bt.cn/d" /etc/hosts
        echo '192.168.88.188 bt.cn www.bt.cn api.bt.cn download.bt.cn dg2.bt.cn dg1.bt.cn' >>/etc/hosts
	fi
    back_home
}
#关闭完全离线服务
close_offline(){
    rm -f ${panel_path}/data/home_host.pl
    rm -f ${panel_path}/data/not_network.pl
    \cp -rf ${panel_path}/config/hosts.json.bk  ${panel_path}/config/hosts.json
    chattr -i /etc/hosts
    sed -i "/bt.cn/d" /etc/hosts
    back_home
}
#快捷启动
quick_start(){
    clear
    btt=/usr/bin/btt
    echo -e "功能说明：将本工具写入到系统使用 btt 命令即可快速启动"
    echo -e "y：安装，u：更新，d：卸载，n：退出"
    read -p "请输入上面指定代码继续操作:" function
	if [ "${function}" == "y" ]; then
	    wget -O ${btt} ${download_url}/btpanel_tools.sh
        chmod +x ${btt}
        echo -e "已将本工具写入到系统请使用 btt 命令即可快速启动"
	elif [ "${function}" == "u" ]; then
	    rm -rf ${btt}
	    wget -O ${btt} ${download_url}/btpanel_tools.sh
        chmod +x ${btt}
        echo -e "已完成更新请使用btt命令验证是否可用"
	elif [ "${function}" == "d" ]; then
	    rm -rf ${btt}
	    echo -e "卸载已完成欢迎下次使用"
	    back_home
	elif [ "${function}" == "n" ]; then
	    clear
		main
	fi
}

#封装工具
package_btpanel(){
    clear
    python ${panel_path}/tools.py package
    back_home
}
#返回首页
back_home(){
	read -p "请输入0返回首页:" function
	if [ "${function}" == "0" ]; then
	    clear
		main
	else
		clear
		exit 0
	fi
}
# 退出脚本
delete(){
    clear
    echo -e "感谢使用筱杰宝塔工具箱"
    rm -rf /btpanel_tools.sh
    rm -rf btpanel_tools.sh
}
main(){
    clear
	echo -e "
#====================================================#
#  脚本名称: BTPanel_tools Version Build ${tools_version}      #
#  脚本官网：www.btpanel.cm  宝塔教程：www.baota.me  #
#  QQ交流群：365208828       TG交流群：t.me/btfans   #
#----------------------------------------------------#
#  面板版本:${btpanel_version}                                    #
#--------------------[面板工具]----------------------#
# (1)[垃圾清理]清理系统、面板、网站产生的缓存日志等  #
# (2)[面板优化]优化面板、去除广告、计算题与延时等    #
# (3)[漏洞修复]检测并修复已知宝塔面板漏洞            #
# (4)[修复面板]修复面板文件、环境、网络、破解残留等  #
# (5)[去除强登]去除宝塔linux面板强制登陆的限制       #
# (6)[停止服务]停止面板LNMP,Redis,Memcached服务      #
# (7)[卸载面板]本功能会清空所有数据卸载网站环境      #
# (8)[挂载磁盘]BT-Panel Linux自动磁盘挂载工具1.8     #
#--------------------[降级版本]----------------------#
# (10)7.9.0 (11)7.8.0 (12)7.7.0 (13)7.6.0 (14)7.5.2  #
#--------------------[腾讯专版]----------------------#
#    (15)升级腾讯专享版      (16)恢复宝塔官方版      #
#-------------------[升级查杀库]---------------------#
#    版本号:Build 210829     (17)一键自动智能升级    #
#--------------------[离线宝塔]----------------------#
#    (18)开启完全离线服务    (19)关闭完全离线服务    #
#   离线功能会完全断开与宝塔的通讯部分功能无法使用   #
#--------------------[赞助广告]----------------------#
# FUNCDN(funcdn.com),高防高速高性价比CDN加速服务。   #
#--------------------[其他功能]----------------------#
# (a)更新脚本  (b)快捷启动  (c)封装工具  (0)退出脚本 #
#====================================================#
	"
	read -p "请输入需要输入的选项:" function
	case $function in
    1)  cleaning_garbage
    ;;
    2)  panel_optimization
    ;;
    3)  bug_fix
    ;;
    4)  update_panel
    ;;
    5)  mandatory_landing
    ;;
    6)  stop_btpanel
    ;;
    7)  uninstall_btpanel
    ;;
    8)  mount_disk
    ;;
    10) version=7.9.0
        degrade_btpanel
    ;;
    11) version=7.8.0
        degrade_btpanel
    ;;
    12) version=7.7.0
        degrade_btpanel
    ;;
    13) version=7.6.0
        degrade_btpanel
    ;;
    14) version=7.5.2
        degrade_btpanel
    ;;
    15) Install_tencent
    ;;
    16) Uninstall_tencent
    ;;
    17) update_wafrule
    ;;
    18) open_offline
    ;;
    19) close_offline
    ;;
    a)  new_version
    ;;
    b)  quick_start
    ;;
    c)  package_btpanel
    ;;
    *)  delete
    ;;
    esac
}
main