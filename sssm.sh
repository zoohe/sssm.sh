#!/bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

dir=/home/sssm
this_dir=$(dirname $(readlink -f "$0"))
[ "${this_dir}" != "${dir}" ] && echo "请把本脚本移动到${dir}中运行，确保本脚本的路径是 ${dir}/sssm.sh" && exit 1
cat /etc/issue | grep -q "Debian" && [ $? -eq 0 ] && environment_debian=1
cat /etc/issue | grep -q "Ubuntu" && [ $? -eq 0 ] && environment_debian=1
[ -z "${environment_debian}" ] && echo "错误！您的系统不是Debian，本脚本只适用于Debian！" && exit 1
uname -a | grep -q "x86_64" && [ $? -eq 0 ] && environment_x64=1
[ -z "${environment_x64}" ] && echo "错误！您的系统不是x86_64，本脚本(暂时)只适用于x86_64！" && exit 1

check_ipv4() {
    IP=$1
    if [[ $IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        FIELD1=$(echo $IP|cut -d. -f1)
        FIELD2=$(echo $IP|cut -d. -f2)
        FIELD3=$(echo $IP|cut -d. -f3)
        FIELD4=$(echo $IP|cut -d. -f4)
        if [ $FIELD1 -le 255 -a $FIELD2 -le 255 -a $FIELD3 -le 255 -a $FIELD4 -le 255 ]; then
            return 0
        else
            return 1
        fi
    else
        return 1
    fi
}

check_port() {
    port=$1
    if [[ "$port" =~ ^[1-9][0-9][0-9][0-9][0-9]$ ]] && [ $port -ge 10000 -a $port -le 65535 ]; then
        return 0
    else
        return 1
    fi
}

check_number() {
    number=$1
    [[ "$number" =~ ^[0-9]+$ ]] && return 0 || return 1
}

random_60000_port() {
[ -z "$1" ] && ne=0 || ne=$1
random_60000_port=$RANDOM
while :
do
    if [ $random_60000_port -gt 60000 -a $random_60000_port -le 65535 -a $random_60000_port -ne $ne ]; then
        return 0
    elif [ $(( $random_60000_port + $RANDOM )) -gt 65535 ]; then
        random_60000_port=$(( $random_60000_port - $RANDOM ))
    else
        random_60000_port=$(( $random_60000_port + $RANDOM ))
    fi
done
}

random_user_port() {
load_config
try_count=0
while :
do
    let try_count++
    [ $try_count -gt 99 ] && $random_60000_port=0 && return 1
    random_60000_port
    flag=0
    while read line
    do
        if [ $random_60000_port -eq $(echo -n $line | cut -d ' ' -f 1) -o $random_60000_port -eq $ss_server_port -o $random_60000_port -eq $nginx_port ]; then
            flag=1
        fi
    done < "${dir}/user"
    [ ${flag} -eq 1 ] && continue
    return 0
done

echo 1
}

first_time_run() {
    rm -f "${dir}/config_tmp"
    echo "[初次运行配置]"
    echo ""
    echo "首先：本脚本依赖Nginx，但只会自动检测您通过LNMP(lnmp.org)默认配置"
    echo "或者apt install nginx所安装的nginx。"
    echo "若您的nginx配置文件並非位于 /etc/nginx/nginx.conf"
    echo "或者 /usr/local/nginx/conf/nginx.conf，"
    echo "会无法自动识别。"
    echo ""
    [ -f "/etc/init.d/nginx" ] && nginx_installed="1"
    [ -f "/etc/nginx/nginx.conf" ] && nginx_conf_file="/etc/nginx/nginx.conf"
    [ -f "/usr/local/nginx/conf/nginx.conf" ] && nginx_conf_file="/usr/local/nginx/conf/nginx.conf"
    if [ "${nginx_installed}" = "1" ]; then
        echo "检测到已安装nginx"
        if [ -z "${nginx_conf_file}" ]; then
            echo "但是没有检测到nginx配置文件"
            echo "请在下面手动输入nginx配置文件(nginx.conf)的路径"
            read -p "nginx.conf路径: " nginx_conf_file
            if [ -z "${nginx_conf_file}" ] || [ ! -f "${nginx_conf_file}" ]; then
                echo "nginx_conf_file=${nginx_conf_file}" > "${dir}/config_tmp"
                echo "nginx_conf_file: ${nginx_conf_file}"
            else
                echo "非常抱歉，本脚本无法为您提供服务。" && exit 1
            fi
        else
            echo "检测到nginx配置文件 ${nginx_conf_file}"
            read -p "请问您认为这正确吗？(Y/n): " confirm_nginx_conf_file
            if [[ $confirm_nginx_conf_file == [Yy] ]] || [ -z "${confirm_nginx_conf_file}" ]; then
                echo "nginx_conf_file=${nginx_conf_file}" > "${dir}/config_tmp"
                echo "nginx_conf_file: ${nginx_conf_file}"
            else
                echo "非常抱歉，本脚本无法为您提供服务。" && exit 1
            fi
        fi
    else
        echo "没有检测到您安装了nginx，请使用apt install nginx或者lnmp安装nginx后重新运行本脚本。"
    fi
    echo ""
    echo "使用本脚本，您需要一张【有效的IPv4证书】，该证书的IPv4【不必须】对应您的机器IP。"
    echo "如果您这台是ipv6 only的机器，甚至可以用别的ipv4机器申请的证书呢~"
    echo "您可以通过 zerossl.com 免费申请IPv4证书。"
    echo "申请方法请自行摸索。"
    echo ""
    read -p "请问您已经成功申请到一张有效的IP证书了吗？(Y/n): " confirm_cert_ready
    [[ $confirm_cert_ready == [Nn] ]] && echo "非常抱歉，本脚本无法为您提供服务。" && exit 1
    echo ""
    while :
    do
        read -p "请输入证书使用的IPv4地址(例如 123.123.123.123): " ip_address
        check_ip $ip_address
        [ $? -eq 0 ] && break
    done
        echo "ip_address=${ip_address}" >> "${dir}/config_tmp"
        echo "ip_address: ${ip_address}"
    import_cert
    echo ""
    echo "请输入您希望nginx所使用的端口，这个端口会用于客户端连接ss。"
    random_60000_port
    while :
    do
        read -p "请输入一个【未被使用】的5位数高位端口，10000-65535，直接回车随机${random_60000_port}: " nginx_port
        [ -z "${nginx_port}" ] && nginx_port=${random_60000_port}
        check_port $nginx_port
        [ $? -eq 0 ] && break
    done
    echo "nginx_port=${nginx_port}" >> "${dir}/config_tmp"
    echo "nginx_port: ${nginx_port}"
    echo ""
    echo "以下是一些SS相关的配置，在大多数情况下您【直接按回车】【默认即可】。"
    echo ""
    echo "请输入您希望shadowsocks所使用的端口，这个端口并不暴露在公网，只监听本地。"
    random_60000_port $nginx_port
    while :
    do
        read -p "请输入一个【未被使用】的5位数高位端口，10000-65535，直接回车随机${random_60000_port}: " ss_server_port
        [ -z "${ss_server_port}" ] && ss_server_port=${random_60000_port}
        [ "${ss_server_port}" = "${nginx_port}" ] && continue
        check_port $ss_server_port
        [ $? -eq 0 ] && break
    done
    echo "ss_server_port=${ss_server_port}" >> "${dir}/config_tmp"
    echo "ss_server_port: ${ss_server_port}"
    echo ""
    echo "请输入您希望shadowsocks所使用的加密方式"
    echo "1) aes-256-gcm: 支持Windows/Android/macOS/iOS/Linux"
    echo "0) none: 不支持macOS，减少移动端的发热量与耗电量"
    read -p "请选择加密方式(1/0)，直接回车默认aes-256-gcm: " ss_method
    [ -z "${ss_method}" ] && ss_method="aes-256-gcm"
    [ "${ss_method}" = "1" ] && ss_method="aes-256-gcm"
    [ "${ss_method}" = "0" ] && ss_method="none"
    echo "ss_method=${ss_method}" >> "${dir}/config_tmp"
    echo "ss_method: ${ss_method}"
    if [ "${ss_method}" = "none" ]; then
        ss_password="0"
    else
        [ ! -f "/usr/bin/openssl" ] && apt install openssl -y
        ss_password=$(openssl rand -base64 32)
    fi
    echo "ss_password=${ss_password}" >> "${dir}/config_tmp"
    echo ""
    echo "请输入您希望shadowsocks所使用的dns服务器。"
    echo "ipv6 only机器请输入ipv6 dns地址"
    echo "以下是一些可供您快速复制粘贴填入的地址:"
    echo "1.1.1.1 8.8.8.8 2606:4700:4700::1111 2001:4860:4860::8888"
    read -p "请输入dns服务器，直接回车默认1.1.1.1: " ss_dns
    [ -z "${ss_dns}" ] && ss_dns="1.1.1.1"
    echo "ss_dns=${ss_dns}" >> "${dir}/config_tmp"
    echo "ss_dns: ${ss_dns}"
    echo ""
    echo "请问您要设置ss出口ipv6优先吗？"
    echo "Y) ipv6优先"
    echo "n) ipv4优先"
    read -p "ipv6优先？(Y/n)直接回车默认(n)ipv4优先: " ss_ipv6_first
    if [[ $ss_ipv6_first == [Yy] ]]; then
        echo "ss_ipv6_first=true" >> "${dir}/config_tmp"
        echo "ss_ipv6_first: true"
    else
        echo "ss_ipv6_first=false" >> "${dir}/config_tmp"
        echo "ss_ipv6_first: false"
    fi
    mv "${dir}/config_tmp" "${dir}/config"
    echo "恭喜您完成了初次使用配置~"
}

import_cert() {
    echo ""
    echo "请解压下载的证书的${ip_address}.zip压缩包"
    echo ""
    echo "【certificate.crt】【certificate.crt】【certificate.crt】"
    echo "【certificate.crt】【certificate.crt】【certificate.crt】"
    echo "【certificate.crt】【certificate.crt】【certificate.crt】"
    echo "请使用【记事本】或者任何文本编辑器例如VS Code打开【certificate.crt】（在文件上右键）"
    echo "【certificate.crt】【certificate.crt】【certificate.crt】"
    echo "【certificate.crt】【certificate.crt】【certificate.crt】"
    echo "【certificate.crt】【certificate.crt】【certificate.crt】"
    echo "请复制里面的【所有内容】"
    read -p "按回车后会打开编辑一个文件的窗口，请在那里粘贴(鼠标右键)所复制的内容，并按Ctrl+X, Y, 回车保存" wait
    [ ! -f "/usr/bin/nano" ] && apt install nano -y
    rm -f "${dir}/new_certificate.crt"
    nano "${dir}/new_certificate.crt"
    rm -f "${dir}/certificate.crt"
    mv "${dir}/new_certificate.crt" "${dir}/certificate.crt"
    echo ""
    echo ""
    echo ""
    echo ""
    echo ""
    echo "【ca_bundle.crt】【ca_bundle.crt】【ca_bundle.crt】"
    echo "【ca_bundle.crt】【ca_bundle.crt】【ca_bundle.crt】"
    echo "【ca_bundle.crt】【ca_bundle.crt】【ca_bundle.crt】"
    echo "请使用【记事本】或者任何文本编辑器例如VS Code打开【ca_bundle.crt】（在文件上右键）"
    echo "【ca_bundle.crt】【ca_bundle.crt】【ca_bundle.crt】"
    echo "【ca_bundle.crt】【ca_bundle.crt】【ca_bundle.crt】"
    echo "【ca_bundle.crt】【ca_bundle.crt】【ca_bundle.crt】"
    echo "请复制里面的【所有内容】"
    read -p "按回车后会打开编辑一个文件的窗口，请在那里粘贴(鼠标右键)所复制的内容，并按Ctrl+X, Y, 回车保存" wait
    rm -f "${dir}/new_ca_bundle.crt"
    nano "${dir}/new_ca_bundle.crt"
    rm -f "${dir}/ca_bundle.crt"
    mv "${dir}/new_ca_bundle.crt" "${dir}/ca_bundle.crt"
    echo ""
    echo ""
    echo ""
    echo ""
    echo ""
    echo "【private.key】【private.key】【private.key】"
    echo "【private.key】【private.key】【private.key】"
    echo "【private.key】【private.key】【private.key】"
    echo "请使用【记事本】或者任何文本编辑器例如VS Code打开【private.key】（在文件上右键）"
    echo "【private.key】【private.key】【private.key】"
    echo "【private.key】【private.key】【private.key】"
    echo "【private.key】【private.key】【private.key】"
    echo "请复制里面的【所有内容】"
    read -p "按回车后会打开编辑一个文件的窗口，请在那里粘贴(鼠标右键)所复制的内容，并按Ctrl+X, Y, 回车保存" wait
    rm -f "${dir}/new_private.key"
    nano "${dir}/new_private.key"
    rm -f "${dir}/private.key"
    mv "${dir}/new_private.key" "${dir}/private.key"
}

check_update() {
    if [ ! -f "${dir}/shadowsocks_rust_latest_version" ] || [ $(( $(date +%s) - $(stat -c %Y "${dir}/shadowsocks_rust_latest_version") )) -gt 604800 ]; then
        shadowsocks_rust_latest=$(wget -qO- -t1 -T2 "https://api.github.com/repos/shadowsocks/shadowsocks-rust/releases/latest" | grep "tag_name" | head -n 1 | awk -F ":" '{print $2}' | sed 's/\"//g;s/,//g;s/ //g' | cut -c2-)
        if [ ! -z "${shadowsocks_rust_latest}" ]; then
            echo "${shadowsocks_rust_latest}" >  "${dir}/shadowsocks_rust_latest_version"
        fi
    else
        shadowsocks_rust_latest=$(cat "${dir}/shadowsocks_rust_latest_version")
    fi
    if [ ! -f "${dir}/v2ray_plugin_latest_version" ] || [ $(( $(date +%s) - $(stat -c %Y "${dir}/v2ray_plugin_latest_version") )) -gt 604800 ]; then
        v2ray_plugin_latest=$(wget -qO- -t1 -T2 "https://api.github.com/repos/shadowsocks/v2ray-plugin/releases/latest" | grep "tag_name" | head -n 1 | awk -F ":" '{print $2}' | sed 's/\"//g;s/,//g;s/ //g' | cut -c2-)
        if [ ! -z "${v2ray_plugin_latest}" ]; then
            echo "${v2ray_plugin_latest}" >  "${dir}/v2ray_plugin_latest_version"
        fi
    else
        v2ray_plugin_latest=$(cat "${dir}/v2ray_plugin_latest_version")
    fi
}

check_installed() {
    unset nginx_version && [ -f "/etc/init.d/nginx" ] && nginx_version=$(nginx -v 2>&1 | cut -c22-) || nginx_version="未安装"
    unset shadowsocks_rust_version && [ -f "${dir}/ssserver" ] && shadowsocks_rust_version=$("${dir}/ssserver" --version | awk '{print $2}') || shadowsocks_rust_version="未安装"
    unset v2ray_plugin_version && [ -f "${dir}/v2ray-plugin" ] && v2ray_plugin_version=$("${dir}/v2ray-plugin" -version | head -n 1 | awk '{print $2}' | cut -c2-) || v2ray_plugin_version="未安装"
    unset nginx_running
    nginx_pid=$(ps -ef | grep "nginx" | grep -v grep | awk '{print $2}')
    if [ ! -z "${nginx_pid}" ] && [ "$(ps -p ${nginx_pid})" > /dev/null ]; then
        nginx_running="运行中"
    else
        nginx_running="未运行"
    fi
    unset ss_server_running
    ss_server_pid=$(ps -ef | grep "ssserver" | grep -v grep | awk '{print $2}')
    if [ ! -z "${ss_server_pid}" ] && [ "$(ps -p ${ss_server_pid})" > /dev/null ]; then
        ss_server_running="运行中"
    else
        ss_server_running="未运行"
    fi
    unset v2ray_plugin_running
    v2ray_plugin_pid=$(ps -ef | grep "v2ray-plugin" | grep -v grep | awk '{print $2}')
    if [ ! -z "${v2ray_plugin_pid}" ] && [ "$(ps -p ${v2ray_plugin_pid})" > /dev/null ]; then
        v2ray_plugin_running="运行中"
    else
        v2ray_plugin_running="未运行"
    fi
}

load_config(){
    ip_address=`cat "${dir}/config" | grep "ip_address" | awk -F "=" '{print $NF}'`

    if [ ! -f "${dir}/certificate.crt" ]; then
        cert_certificate_crt="${dir}/certificate.crt 文件不存在"
    elif [ "$(cat ${dir}/certificate.crt | head -n 1)" = "-----BEGIN CERTIFICATE-----" ] &&
    [ "$(cat ${dir}/certificate.crt | tail -n 1)" = "-----END CERTIFICATE-----" ]; then
        cert_certificate_crt="ok"
    else
        cert_certificate_crt="错误"
    fi

    if [ ! -f "${dir}/ca_bundle.crt" ]; then
        cert_ca_bundle_crt="${dir}/ca_bundle.crt 文件不存在"
    elif [ "$(cat ${dir}/ca_bundle.crt | head -n 1)" = "-----BEGIN CERTIFICATE-----" ] &&
    [ "$(cat ${dir}/ca_bundle.crt | tail -n 1)" = "-----END CERTIFICATE-----" ]; then
        cert_ca_bundle_crt="ok"
    else
        cert_ca_bundle_crt="错误"
    fi

    if [ ! -f "${dir}/private.key" ]; then
        cert_private_key="${dir}/private.key 文件不存在"
    elif [ "$(cat ${dir}/private.key | head -n 1)" = "-----BEGIN RSA PRIVATE KEY-----" ] &&
    [ "$(cat ${dir}/private.key | tail -n 1)" = "-----END RSA PRIVATE KEY-----" ]; then
        cert_private_key="ok"
    else
        cert_private_key="错误"
    fi

    nginx_conf_file=`cat "${dir}/config" | grep "nginx_conf_file" | awk -F "=" '{print $NF}'`

    nginx_port=`cat "${dir}/config" | grep "nginx_port" | awk -F "=" '{print $NF}'`

    ss_server_port=`cat "${dir}/config" | grep "ss_server_port" | awk -F "=" '{print $NF}'`
    ss_method=`cat "${dir}/config" | grep "ss_method" | awk -F "=" '{print $NF}'`
    ss_password=`cat "${dir}/config" | grep "ss_password" | awk -F "=" '{print $NF}'`
    ss_dns=`cat "${dir}/config" | grep "ss_dns" | awk -F "=" '{print $NF}'`
    ss_ipv6_first=`cat "${dir}/config" | grep "ss_ipv6_first" | awk -F "=" '{print $NF}'`
}

load_single_user_from_line(){
    unset user_port
    unset user_name
    unset user_traffic_limit
    user_port=$1
    user_name=$2
    user_traffic_limit=$3
    user_hash=$(echo -n "${user_port}${user_name}" | md5sum | cut -d ' ' -f 1)

    [ ! -d "${dir}/user_traffic" ] && mkdir "${dir}/user_traffic"
    [ ! -f "${dir}/user_traffic/${user_port}" ] && echo "0" > "${dir}/user_traffic/${user_port}"
    unset user_traffic_in_bytes
    unset user_traffic_in_mb
    unset user_traffic_in_gb
    user_traffic_in_bytes=$(cat "${dir}/user_traffic/${user_port}")
    [ "${user_traffic_in_bytes}" == "" ] && user_traffic_in_bytes="0"
    user_traffic_in_mb=$(( ${user_traffic_in_bytes} / 1048576 ))
    user_traffic_in_gb=$(( ${user_traffic_in_bytes} / 1073741824 ))

    unset user_traffic_last_month_in_bytes
    unset user_traffic_last_month_in_mb
    unset user_traffic_last_month_in_gb
    [ -f "${dir}/user_traffic/${user_port}_last_month" ] && user_traffic_last_month_in_bytes=$(cat "${dir}/user_traffic/${user_port}_last_month") || user_traffic_last_month_in_bytes=0
    [ "${user_traffic_last_month_in_bytes}" == "" ] && user_traffic_last_month_in_bytes="0"
    user_traffic_last_month_in_mb=$(( ${user_traffic_last_month_in_bytes} / 1048576 ))
    user_traffic_last_month_in_gb=$(( ${user_traffic_last_month_in_bytes} / 1073741824 ))
}

install_shadowsocks() {
    if [ -z ${shadowsocks_rust_latest} ]; then
        echo "shadowsocks-rust 安装/更新失败。原因: 最新版本号获取失败。"
    elif [ "${shadowsocks_rust_latest}" = "${shadowsocks_rust_version}" ]; then
        echo "shadowsocks-rust 已安装，无更新，跳过。"
    else
        rm -f ${dir}/sslocal ${dir}/ssmanager ${dir}/ssserver ${dir}/ssservice ${dir}/ssurl
        wget -q -t1 -T2 -O ${dir}/shadowsocks-v${shadowsocks_rust_latest}.x86_64-unknown-linux-gnu.tar.xz "https://github.com/shadowsocks/shadowsocks-rust/releases/download/v${shadowsocks_rust_latest}/shadowsocks-v${shadowsocks_rust_latest}.x86_64-unknown-linux-gnu.tar.xz"
        [ ! -f "${dir}/shadowsocks-v${shadowsocks_rust_latest}.x86_64-unknown-linux-gnu.tar.xz" ] && echo "Download Error! shadowsocks-v${shadowsocks_rust_latest}.x86_64-unknown-linux-gnu.tar.xz Not Found!" && exit 1
        tar Jxf ${dir}/shadowsocks-v${shadowsocks_rust_latest}.x86_64-unknown-linux-gnu.tar.xz -C "${dir}"
        rm -r ${dir}/shadowsocks-v${shadowsocks_rust_latest}.x86_64-unknown-linux-gnu.tar.xz
        [ ! -f "${dir}/ssserver" ] && echo "Download Error! ${dir}/ssserver Not Found!" && exit 1
        chmod +x ${dir}/sslocal ${dir}/ssmanager ${dir}/ssserver ${dir}/ssservice ${dir}/ssurl
        echo "shadowsocks-rust 安装/更新成功。"
    fi

    if [ -z ${v2ray_plugin_latest} ]; then
        echo "v2ray-plugin 安装/更新失败。原因: 最新版本号获取失败。"
    elif [ "${v2ray_plugin_latest}" = "${v2ray_plugin_version}" ]; then
        echo "v2ray-plugin 已安装，无更新，跳过。"
    else
        rm -f ${dir}/v2ray-plugin
        wget -q -t1 -T2 -O ${dir}/v2ray-plugin-linux-amd64-v${v2ray_plugin_latest}.tar.gz "https://github.com/shadowsocks/v2ray-plugin/releases/download/v${v2ray_plugin_latest}/v2ray-plugin-linux-amd64-v${v2ray_plugin_latest}.tar.gz"
        [ ! -f "${dir}/v2ray-plugin-linux-amd64-v${v2ray_plugin_latest}.tar.gz" ] && echo "Download Error! ${dir}/v2ray-plugin-linux-amd64-v${v2ray_plugin_latest}.tar.gz Not Found!" && exit 1
        tar zxf ${dir}/v2ray-plugin-linux-amd64-v${v2ray_plugin_latest}.tar.gz -C "${dir}"
        rm -f ${dir}/v2ray-plugin-linux-amd64-v${v2ray_plugin_latest}.tar.gz
        [ ! -f "${dir}/v2ray-plugin_linux_amd64" ] && echo "Download Error! ${dir}/v2ray-plugin_linux_amd64 Not Found!" && exit 1
        mv ${dir}/v2ray-plugin_linux_amd64 ${dir}/v2ray-plugin
        chmod +x ${dir}/v2ray-plugin
        echo "v2ray-plugin 安装/更新成功。"
    fi
}

generate_ss_conf() {
    load_config
    cat > "${dir}/config.json" << EOF
{
    "server":"127.0.0.1",
    "server_port":${ss_server_port},
    "method":"${ss_method}",
    "password":"${ss_password}",
    "mode":"tcp_only",
    "plugin":"${dir}/v2ray-plugin",
    "plugin_opts":"server;path=/;loglevel=none",
    "dns":"${ss_dns}",
    "timeout":300,
    "fast_open":false,
    "ipv6_first":${ss_ipv6_first}
}
EOF
}

generate_nginx_conf() {
    load_config

    cat "${nginx_conf_file}" | grep -q "${dir}/sssm_nginx_vhost.conf"
    [ $? -eq 1 ] && sed -i "/http {/a\include ${dir}/sssm_nginx_vhost.conf;" "${nginx_conf_file}"

    if [ ! -f "${dir}/certificate.crt" ] || [ ! -f "${dir}/ca_bundle.crt" ] || [ ! -f "${dir}/private.key" ]; then
        echo "错误！证书文件不存在！" && exit 1
    elif [ ! -f "${dir}/fullchain.crt" ] || [ $(stat -c %Y "${dir}/certificate.crt") -gt $(stat -c %Y "${dir}/fullchain.crt") ]; then
        cat "${dir}/certificate.crt" > "${dir}/fullchain.crt"
        cat "${dir}/ca_bundle.crt" >> "${dir}/fullchain.crt"
    fi

    [ ! -f "/usr/bin/openssl" ] && apt install openssl -y
    [ ! -f "${dir}/dhparam.pem" ] && openssl dhparam -out ${dir}/dhparam.pem 2048

    [ ! -d "${dir}/wwwroot" ] && mkdir "${dir}/wwwroot"
    [ ! -f "${dir}/wwwroot/index.html" ] && touch "${dir}/wwwroot/index.html"

    cat > "${dir}/tmp_sssm_nginx_vhost.conf" << EOF
server {
    listen ${nginx_port} ssl http2;
    listen [::]:${nginx_port} ipv6only=on ssl http2;
    server_name ${ip_address};
    index index.html;
    root ${dir}/wwwroot;

    ssl_certificate ${dir}/fullchain.crt;
    ssl_certificate_key ${dir}/private.key;
    ssl_session_timeout 5m;
    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers "TLS13-AES-256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256:TLS13-AES-128-CCM-8-SHA256:TLS13-AES-128-CCM-SHA256:EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5";
    ssl_session_cache builtin:1000 shared:SSL:10m;
    ssl_dhparam ${dir}/dhparam.pem;

EOF
    while read line
    do
        load_single_user_from_line $line

        if [ "${user_traffic_limit}" = "0" ] || [ "${user_traffic_limit}" -gt "${user_traffic_in_gb}" ]; then
            cat >> "${dir}/tmp_sssm_nginx_vhost.conf" << EOF
    # ${user_name}
    location ^~ /${user_hash} {
        proxy_pass http://127.0.0.1:${user_port}/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }

EOF
        fi

    done < "${dir}/user"
    cat >> "${dir}/tmp_sssm_nginx_vhost.conf" << EOF
    location ~ /.well-known {
        allow all;
    }

    location ~ /\. {
        deny all;
    }
}

server {
EOF
    while read line
    do
        load_single_user_from_line $line
        echo "    listen 127.0.0.1:${user_port} default_server;" >> "${dir}/tmp_sssm_nginx_vhost.conf"
    done < "${dir}/user"
    cat >> "${dir}/tmp_sssm_nginx_vhost.conf" << EOF
    # v2ray-plugin
    location / {
        proxy_pass http://127.0.0.1:${ss_server_port}/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}

EOF

    file1="${dir}/sssm_nginx_vhost.conf"
    file2="${dir}/tmp_sssm_nginx_vhost.conf"
    if [ -f "${file1}" ] && [ -f "${file2}" ]; then
        diff "${file1}" "${file2}" > /dev/null
        if [ $? != 0 ]; then
            rm -f "${file1}"
            mv "${file2}" "${file1}"
            [ "${nginx_running}" = "运行中" ] && /etc/init.d/nginx reload
        else
            rm -f "${file2}"
        fi
    else
        mv "${file2}" "${file1}"
        [ "${nginx_running}" = "运行中" ] && /etc/init.d/nginx reload
    fi
}

service_restart() {
    if [ ! -f "/etc/systemd/system/sssm_shadowsocks.service" ]; then
        cat > /etc/systemd/system/sssm_shadowsocks.service << EOF
[Unit]
Description=Shadowsocks Server Manager
After=network.target

[Service]
ExecStart=${dir}/ssserver -c ${dir}/config.json

Restart=on-abort

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
    fi
    [ ! -f "/etc/systemd/system/multi-user.target.wants/sssm_shadowsocks.service" ] && systemctl enable sssm_shadowsocks

    generate_ss_conf
    generate_nginx_conf

    systemctl restart sssm_shadowsocks
    /etc/init.d/nginx restart

    [ ! -f "/usr/sbin/iptables" ] && apt install iptables -y
    while read line
    do
        load_single_user_from_line $line
        add_traffic
    done < "${dir}/user"

    crontab -l | grep -q "bash ${dir}/sssm.sh cron"
    [ $? -eq 1 ] && (crontab -l ; echo "*/5 * * * * bash ${dir}/sssm.sh cron") | crontab -
    crontab -l | grep -q "bash ${dir}/sssm.sh monthly_cron"
    [ $? -eq 1 ] && (crontab -l ; echo "1 0 1 * * bash ${dir}/sssm.sh monthly_cron") | crontab -
}

service_stop() {
    systemctl stop sssm_shadowsocks

    while read line
    do
        load_single_user_from_line $line
        add_traffic
        delete_port_from_iptables ${user_port}
    done < "${dir}/user"
}

add_port_to_iptables() {
    iptables -A OUTPUT -p tcp --sport $1 > /dev/null 2>&1
}

delete_port_from_iptables() {
    iptables -D OUTPUT -p tcp --sport $1 > /dev/null 2>&1
}

add_traffic() {
    [ ! -d "${dir}/user_traffic" ] && mkdir "${dir}/user_traffic"
    previous_traffic=$(cat "${dir}/user_traffic/${user_port}")
    [ "${previous_traffic}" = "" ] && previous_traffic="0"
    new_traffic=$(iptables -nvx -L OUTPUT | grep spt:${user_port} | awk '{print $2}')
    delete_port_from_iptables ${user_port}
    add_port_to_iptables ${user_port}
    [ "${new_traffic}" = "" ] && new_traffic="0"
    total_traffic=$(( ${previous_traffic} + ${new_traffic} ))
    echo "${total_traffic}" > "${dir}/user_traffic/${user_port}"
}

add_user() {
    echo "${add_user_port} ${add_user_name} ${add_user_traffic_limit}" >> ${dir}/user
    add_port_to_iptables ${add_user_port}
}

delete_user() {
    line=$( cat "${dir}/user" | sed -n ${choose_an_option}p )
    [ -z "${line}" ] && return
    user_port=$(echo -n $line | cut -d ' ' -f 1)
    sed -i "${choose_an_option}d" ${dir}/user
    delete_port_from_iptables ${user_port}
    rm -f "${dir}/user_traffic/${user_port}"
    rm -f "${dir}/user_traffic/${user_port}_last_month"
}

show_user_ss_config() {
    load_config
    line=$( cat "${dir}/user" | sed -n ${choose_an_option}p )
    [ -z "${line}" ] && return
    load_single_user_from_line ${line}
    ss_link_generator
    output="服务器地址 ${ip_address}
    服务器端口 ${nginx_port}
    密码 ${ss_password}
    加密 ${ss_method}
    插件程序 ${v2ray-plugin}
    插件选项 tls;host=${ip_address};path=/${user_hash}"
    echo "$output" | column -t
    echo "Windows导入链接"
    echo "${ss_link_windows}"
    echo "macOS导入链接"
    echo "${ss_link_macos}"
    echo "Android导入链接"
    echo "${ss_link_android}"
    echo "iOS导入链接"
    echo "${ss_link_ios}"

    read -p "以上是用户${user_port}:${user_name}的配置信息，按回车键返回。" return
}

ss_link_generator() {
    tmp_base64=$(echo -n "${ss_method}:${ss_password}" | base64 -w 0 | sed s/=//g)
    ss_link_windows="ss://${tmp_base64}@${ip_address}:${nginx_port}/?plugin=v2ray-plugin%3btls%3bhost%3d${ip_address}%3bpath%3d%2f${user_hash}"
    tmp_base64=$(echo -n "${ss_method}:${ss_password}" | base64 -w 0)
    ss_link_macos="ss://${tmp_base64}@${ip_address}:${nginx_port}/?plugin=v2ray-plugin;tls;host%3D${ip_address};path%3D/${user_hash}"
    tmp_base64=$(echo -n "${ss_method}:${ss_password}" | base64 -w 0 | sed s/=//g)
    ss_link_android="ss://${tmp_base64}@${ip_address}:${nginx_port}?plugin=v2ray%3Bloglevel%3Dnone%3Bpath%3D%2F${user_hash}%3Bhost%3D${ip_address}%3Btls"
    tmp_base64=$(echo -n "${ss_method}:${ss_password}@${ip_address}:${nginx_port}" | base64 -w 0 | sed s/=//g)
    tmp_base64_2=$(echo -n "{\"address\":\"${ip_address}\",\"port\":\"${nginx_port}\",\"mode\":\"websocket\",\"host\":\"${ip_address}\",\"tls\":true,\"allowInsecure\":false,\"mux\":true,\"path\":\"\\/${user_hash}\"}" | base64 -w 0 | sed s/=//g)
    ss_link_ios="ss://${tmp_base64}?v2ray-plugin=${tmp_base64_2}"
}

main_do_option() {
    case "$1" in
        1)
            service_restart
            ;;
        2)
            service_stop
            ;;
        3)
            systemctl status sssm_shadowsocks
            ;;
        4)
            download_client_option
            ;;
        5)
            user_manager
            ;;
        6)
            install_shadowsocks
            ;;
        7)
            import_cert
            ;;
        8)
            nano ${dir}/config
            ;;
        9)
            [ -f "/etc/systemd/system/multi-user.target.wants/sssm_shadowsocks.service" ] && systemctl disable sssm_shadowsocks
            if [ -f "/etc/systemd/system/sssm_shadowsocks.service" ]; then
                systemctl stop sssm_shadowsocks
                rm -f "/etc/systemd/system/sssm_shadowsocks.service"
            fi
            sed -i "/sssm_nginx_vhost.conf/d" "${nginx_conf_file}"

            crontab -l > ${dir}/crontab_tmp
            sed -i "/\/sssm.sh cron/d" ${dir}/crontab_tmp
            crontab ${dir}/crontab_tmp
            rm -f ${dir}/crontab_tmp

            echo "清理完毕，现在您可以执行 rm -rf ${dir} 完全删除本脚本文件夹啦！"
            exit 0
    esac
}

user_do_option() {
    case "$1" in
        a)
            echo "+----------+" &&
            echo "| 新增用户 |" &&
            echo "+----------+"

            unset add_user_port
            unset add_user_name
            unset add_user_traffic_limit

            echo "请输入一个【未被使用】的5位数高位端口用于该用户的流量监控"
            echo "请输入用户名，仅限英数字"
            echo "请输入该用户月流量限制，每月1号重置，GB为单位，整数，输入0或者留空为不限制"
            random_user_port
            while :
            do
                read -p "用户端口(10000-65535)，直接回车随机${random_60000_port}: " add_user_port
                [ -z "${add_user_port}" ] && add_user_port=${random_60000_port}
                [ "${add_user_port}" = "0" ] && return
                check_port $add_user_port
                [ $? -eq 1 ] && continue
                flag=0
                while read line
                do
                    if [ $add_user_port -eq $(echo -n $line | cut -d ' ' -f 1) -o $add_user_port -eq $ss_server_port -o $add_user_port -eq $nginx_port ]; then
                        flag=1
                    fi
                done < "${dir}/user"
                [ ${flag} -eq 1 ] && echo "端口重复" && continue
                break
            done
            read -p "用户名(英数字): " add_user_name
            [ -z "${add_user_name}" ] && return
            add_user_name=$(echo -n ${add_user_name} | sed s/\ //g)
            while :
            do
                read -p "用户流量(GB为单位整数): " add_user_traffic_limit
                [ -z "${add_user_traffic_limit}" ] && add_user_traffic_limit=0
                check_number $add_user_traffic_limit
                [ $? -eq 0 ] && break
            done
            add_user
            ;;
        d)
            while :
            do
            echo "+----------+" &&
            echo "| 删除用户 |" &&
            echo "+----------+"

            list_user
            echo "0) 返回上一级"
            unset choose_an_option
            while :
            do
                read -p "选择删除一个用户(数字): " choose_an_option
                [ -z "${choose_an_option}" ] && continue
                check_number $choose_an_option
                [ $? -eq 0 ] && break
            done
            [ "${choose_an_option}" = "0" ] && break
            delete_user
            done
            ;;
        *)
            show_user_ss_config
            ;;
    esac

}

main() {
    check_update
    while :
    do
    check_installed
    load_config

    echo "+----------+" &&
    echo "|  主菜单  |" &&
    echo "+----------+"

    echo "IP ${ip_address}"
    echo "certificate.crt: ${cert_certificate_crt} | ca_bundle.crt: ${cert_ca_bundle_crt} | private.key: ${cert_private_key}"
    echo "nginx ${nginx_version} ${nginx_running} ${nginx_conf_file}" 
    echo "shadowsocks-rust ${shadowsocks_rust_version} ${ss_server_running} 最新版: ${shadowsocks_rust_latest}"
    echo "v2ray-plugin ${v2ray_plugin_version} ${v2ray_plugin_running} 最新版: ${v2ray_plugin_latest}"

    echo "请问您今天要来点兔子吗？"
    if [ "${shadowsocks_rust_version}" != "未安装" ] && [ "${v2ray_plugin_version}" != "未安装" ]; then
        if [ "${ss_server_running}" = "未运行" ]; then
            echo "1) 启动 shadowsocks-rust"
        elif [ "${ss_server_running}" = "运行中" ]; then
            echo "1) 重新生成 shadowsocks 和 nginx 配置 并" &&
            echo "   重启 Shadowsocks 和 nginx"
            echo "2) 停止 shadowsocks-rust"
        fi
        echo "3) 显示 shadowsocks-rust 状态"
        echo "4) 下载适配的Shadowsocks客户端"
        echo "5) 用户管理面板"
    fi
    if [ "${shadowsocks_rust_version}" = "未安装" ] || [ "${v2ray_plugin_version}" = "未安装" ]; then
        echo "6) 安装 shadowsocks-rust 及 v2ray-plugin"
    elif [ "${shadowsocks_rust_version}" != "${shadowsocks_rust_latest}" ] || [ "${v2ray_plugin_version}" != "${v2ray_plugin_latest}" ]; then
        echo "6) 更新 shadowsocks-rust 及 v2ray-plugin"
    fi
    echo "7) 导入新的IP证书"
    echo "8) 手动编辑脚本配置文件"
    echo "9) 完全停止 并且打算移除本脚本"
    echo "0) 退出脚本。"

    unset choose_an_option
    read -p "选择一个选项: " choose_an_option
    [ -z "${choose_an_option}" ] && continue
    [ "${choose_an_option}" = "0" ] && break
    main_do_option $choose_an_option
    done
}

list_user() {
    if [ ! -f "${dir}/user" ]; then
        touch "${dir}/user"
    fi
    count=0
    output="　/用户端口/用户名/流量限制(GB)/已使用流量/上个月使用流量"
    while read line
    do
        let count++
        load_single_user_from_line $line
        output="${output}
${count})/${user_port}/${user_name}/${user_traffic_limit}/${user_traffic_in_mb} MB | ${user_traffic_in_gb} GB/${user_traffic_last_month_in_mb} MB | ${user_traffic_last_month_in_gb} GB"
    done < "${dir}/user"
    [ ! -f "/usr/bin/column" ] && apt install bsdmainutils -y
    echo "$output" | column -t -s "/"
}

user_manager() {
    while :
    do

    echo "+----------+" &&
    echo "| 用户面板 |" &&
    echo "+----------+"

    echo "提示: 选择一个用户查看该用户的SS配置。"
    list_user
    echo "a) 新增用户"
    echo "d) 删除用户"
    echo "0) 返回上一级"
    unset choose_an_option
    while :
    do
        read -p "选择一个选项: " choose_an_option
        [ -z "${choose_an_option}" ] && continue
        [ "${choose_an_option}" = "a" ] || [ "${choose_an_option}" = "d" ] && break
        check_number $choose_an_option
        [ $? -eq 0 ] && break
    done
    [ "${choose_an_option}" = "0" ] && break
    user_do_option $choose_an_option
    done
}

download_client_option() {
    while :
    do
    echo "+----------+" &&
    echo "|下载客户端|" &&
    echo "+----------+"

    echo "1) Windows: shadowsocks-windows + v2ray-plugin"
    echo "2) macOS: ShadowsocksX-NG (不支持none加密方式)"
    echo "3) Android: shadowsocks-android + v2ray-plugin-android"
    echo "4) iOS: Shadowrocket (需外区账号自己花钱购买)"
    echo "0) 返回上一级"
    unset choose_an_option
    while :
    do
        read -p "选择一个选项: " choose_an_option
        [ -z "${choose_an_option}" ] && continue
        [ "${choose_an_option}" = "1" ] || [ "${choose_an_option}" = "2" ] || [ "${choose_an_option}" = "3" ] || [ "${choose_an_option}" = "4" ] || [ "${choose_an_option}" = "0" ] && break
    done
    [ "${choose_an_option}" = "0" ] && break
    download_client $choose_an_option
    done
}

download_client() {
    case "$1" in
        1)
            [ ! -f "/usr/bin/unzip" ] && apt install unzip -y
            [ ! -f "/usr/bin/zip" ] && apt install zip -y
            shadowsocks_windows_latest=$(wget -qO- -t1 -T2 "https://api.github.com/repos/shadowsocks/shadowsocks-windows/releases/latest" | grep "tag_name" | head -n 1 | awk -F ":" '{print $2}' | sed 's/\"//g;s/,//g;s/ //g')
            [ ! -d "${dir}/wwwroot/tmp" ] && mkdir "${dir}/wwwroot/tmp" -p
            wget -O "${dir}/wwwroot/tmp/Shadowsocks-${shadowsocks_windows_latest}.zip" "https://github.com/shadowsocks/shadowsocks-windows/releases/download/${shadowsocks_windows_latest}/Shadowsocks-${shadowsocks_windows_latest}.zip"
            wget -O "${dir}/wwwroot/tmp/v2ray-plugin-windows-amd64-v${v2ray_plugin_latest}.tar.gz" "https://github.com/shadowsocks/v2ray-plugin/releases/download/v${v2ray_plugin_latest}/v2ray-plugin-windows-amd64-v${v2ray_plugin_latest}.tar.gz"
            [ ! -d "${dir}/wwwroot/tmp/Shadowsocks" ] && mkdir "${dir}/wwwroot/tmp/Shadowsocks"
            unzip "${dir}/wwwroot/tmp/Shadowsocks-${shadowsocks_windows_latest}.zip" -d "${dir}/wwwroot/tmp/Shadowsocks"
            tar zxvf "${dir}/wwwroot/tmp/v2ray-plugin-windows-amd64-v${v2ray_plugin_latest}.tar.gz" -C "${dir}/wwwroot/tmp/Shadowsocks"
            mv "${dir}/wwwroot/tmp/Shadowsocks/v2ray-plugin_windows_amd64.exe" "${dir}/wwwroot/tmp/Shadowsocks/v2ray-plugin.exe"
            rm -f "${dir}/wwwroot/tmp/windows.zip"
            cd "${dir}/wwwroot/tmp"
            zip -r "${dir}/wwwroot/tmp/windows.zip" "Shadowsocks"
            cd "${dir}"
            rm -rf "${dir}/wwwroot/tmp/Shadowsocks" "${dir}/wwwroot/tmp/Shadowsocks-${shadowsocks_windows_latest}.zip" "${dir}/wwwroot/tmp/v2ray-plugin-windows-amd64-v${v2ray_plugin_latest}.tar.gz"
            echo "Windows客户端打包完成"
            echo "请访问 https://${ip_address}:${nginx_port}/tmp/windows.zip 下载"
            echo "下载完成后请 rm -rf \"${dir}/wwwroot/tmp\" 删除缓存文件"
            read -p "按回车键返回。" return
            return 0
            ;;
        2)
            shadowsocksx_ng_latest=$(wget -qO- -t1 -T2 "https://api.github.com/repos/shadowsocks/ShadowsocksX-NG/releases/latest" | grep "tag_name" | head -n 1 | awk -F ":" '{print $2}' | sed 's/\"//g;s/,//g;s/ //g' | cut -c2-)
            [ ! -d "${dir}/wwwroot/tmp" ] && mkdir "${dir}/wwwroot/tmp" -p
            wget -O "${dir}/wwwroot/tmp/macos.dmg" "https://github.com/shadowsocks/ShadowsocksX-NG/releases/download/v${shadowsocksx_ng_latest}/ShadowsocksX-NG.dmg"
            echo "macOS客户端"
            echo "请访问 https://${ip_address}:${nginx_port}/tmp/macos.dmg 下载"
            echo "下载完成后请 rm -rf \"${dir}/wwwroot/tmp\" 删除缓存文件"
            read -p "按回车键返回。" return
            return 0
            ;;
        3)
            [ ! -d "${dir}/wwwroot/tmp" ] && mkdir "${dir}/wwwroot/tmp" -p
            shadowsocks_android_url=$(wget -qO- -t1 -T2 "https://api.github.com/repos/shadowsocks/shadowsocks-android/releases" | grep "browser_download_url" | grep "universal" | head -n 1 | awk -F "\"" '{print $4}' | sed 's/-tv//g')
            v2ray_plugin_android_url=$(wget -qO- -t1 -T2 "https://api.github.com/repos/shadowsocks/v2ray-plugin-android/releases/latest" | grep "browser_download_url" | grep "universal" | head -n 1 | awk -F "\"" '{print $4}')
            wget -O "${dir}/wwwroot/tmp/android.apk" "${shadowsocks_android_url}"
            wget -O "${dir}/wwwroot/tmp/android_plugin.apk" "${v2ray_plugin_android_url}"
            echo "Android客户端"
            echo "请访问 https://${ip_address}:${nginx_port}/tmp/android.apk 下载"
            echo "请访问 https://${ip_address}:${nginx_port}/tmp/android_plugin.apk 下载"
            echo "两个都需要安装"
            echo "下载完成后请 rm -rf \"${dir}/wwwroot/tmp\" 删除缓存文件"
            read -p "按回车键返回。" return
            return 0
            ;;
        4)
            echo "iOS: Shadowrocket"
            echo "需要一个外区账号付费购买。"
            echo "请访问 https://apps.apple.com/app/shadowrocket/id932747118 下载"
            read -p "按回车键返回。" return
            return 0
            ;;
    esac
}

case "$1" in
    cron)
        [ ! -f "${dir}/config" ] && exit 1
        check_installed
        load_config
        if [ "${ss_server_running}" = "运行中" ] && [ "${v2ray_plugin_running}" = "运行中" ] && [ "${nginx_running}" = "运行中" ]; then
            while read line
            do
                load_single_user_from_line $line
                add_traffic
            done < "${dir}/user"
            generate_nginx_conf
        fi
    ;;
    monthly_cron)
        while read line
        do
            load_single_user_from_line $line
            add_traffic
            rm -f "${dir}/user_traffic/${user_port}_last_month"
            mv "${dir}/user_traffic/${user_port}" "${dir}/user_traffic/${user_port}_last_month"
        done < "${dir}/user"
    ;;
    *)
        echo "+----------------------------------+" &&
        echo "|               夜桜               |" &&
        echo "|  ss+v2ray-plugin 多用户管理脚本  |" &&
        echo "|         2023-09-11 v0.1          |" &&
        echo "+----------------------------------+"
        [ ! -f "${dir}/config" ] && first_time_run
        [ -f "${dir}/config" ] && main
    ;;
esac
exit