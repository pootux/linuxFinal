function getQuestions() {
	echo "Kurulum aşamasında aşağıdaki soruları cevaplamanız ve işlemler bittikten sonra addVpnUser.sh dosyasını çalıştırarak kullanıcı adı ve şifre tanımlamanız gerekmektedir."

	# Detect public IPv4 address and pre-fill for the user
	IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)

	if [[ -z $IP ]]; then
		# Detect public IPv6 address
		IP=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
	fi

	APPROVE_IP=${APPROVE_IP:-n}

	if [[ $APPROVE_IP =~ n ]]; then
		read -rp "IP Adresi: " -e -i "$IP" IP
	fi

	# If $IP is a private IP address, the server must be behind NAT
	if echo "$IP" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		PUBLICIP=$(curl -s https://api.ipify.org)
		until [[ $ENDPOINT != "" ]]; do
			read -rp "Public IPv4 adresi veya hostname: " -e -i "$PUBLICIP" ENDPOINT
		done
	fi

	echo ""
	echo "IPv6 bağlantısı kontrol ediliyor..."
	echo ""
	# "ping6" and "ping -6" availability varies depending on the distribution
	if type ping6 >/dev/null 2>&1; then
		PING6="ping6 -c3 ipv6.google.com > /dev/null 2>&1"
	else
		PING6="ping -6 -c3 ipv6.google.com > /dev/null 2>&1"
	fi
	if eval "$PING6"; then
		echo "Your host appears to have IPv6 connectivity."
		SUGGESTION="y"
	else
		echo "Your host does not appear to have IPv6 connectivity."
		SUGGESTION="n"
	fi
	echo ""

	$IPV6_SUPPORT = "y"

	echo ""
	echo "Birinci Soru: Yayın yapılacak port numarasını seçiniz:"
	echo "   1) Varsayılan Port - 1194"
	echo "   2) Farklı Port"

	until [[ $PORT_CHOICE =~ ^[1-2]$ ]]; do
		read -rp "Lütfen seçiniz [1-2]: " -e -i 1 PORT_CHOICE
	done

	case $PORT_CHOICE in
	1)
		PORT="1194"
		;;
	2)
		until [[ $PORT =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ]; do
			read -rp "Port numarası [1-65535]: " -e -i 1194 PORT
		done
		;;
	esac

	$PROTOCOL_CHOICE = 1
	PROTOCOL="udp"
	$COMPRESSION_ENABLED = "n"
	$CUSTOMIZE_ENC = "n"

	echo ""
	echo "Hangi DNS çözücüyü kullanmak istersiniz?"
	echo "   1) Mevcut sistem çözücüsü (from /etc/resolv.conf)"
	echo "   2) Cloudflare"
	echo "   3) OpenDNS"
	echo "   4) Google"
	echo "   5) Yandex"

	# Use default, sane and fast parameters
	CIPHER="AES-128-GCM"
	CERT_TYPE="1" # ECDSA
	CERT_CURVE="prime256v1"
	CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"
	DH_TYPE="1" # ECDH
	DH_CURVE="prime256v1"
	HMAC_ALG="SHA256"
	TLS_SIG="1" # tls-crypt

	until [[ $DNS =~ ^[0-9]+$ ]] && [ "$DNS" -ge 1 ] && [ "$DNS" -le 6 ]; do
		read -rp "DNS [1-5]: " -e -i 11 DNS
	done

	echo ""
	echo "VPN ayarları hazır.."
	read -n1 -r -p " Kurulum işlemine geçmek için herhangi bir tuşa basınız..."
}

function installOpenVPN() {

	getQuestions

	# ip -4 route ls: Ipv4 yönlendirme tablosunu listeler.
	# grep default: default kelimesini içeren satırları filtreler. Varsayılan ağ geçidini temsil eder.
	# grep -Po '(?<=dev )(\S+)' : dev kelimesinden sonra gelen ve boşluk olmayan karakter dizisini yani ağ arabirim adını alır. Ağ arabiriminin adını döndürür.
	# head -1: Birden fazla varsayılan ağ geçici varsa, yalnızca ilkini seçer.
	# NIC: Bu değişkene varsayılan ağ arabiriminin adını atar.
	NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)

	# Bu ifade $NIC değişkeninin boş olup olmadığını kontrol eder. Eğer boşsa ve IPV6_SUPPORT değişkeni y olarak ayarlanmışsa bu koşul doğru olur.
	# ip -6 route show default: Bu komut, IPv6 varsayılan ağ geçidini gösteren çıktıyı verir.
	# sed -ne 's/^default .* dev \([^ ]*\) .*$/\1/p : Ipv6 varsayılan ağ geçidi çıktısından ağ arabirimi adını alır.
	if [[ -z $NIC ]] && [[ $IPV6_SUPPORT == 'y' ]]; then
		NIC=$(ip -6 route show default | sed -ne 's/^default .* dev \([^ ]*\) .*$/\1/p')
	fi

	#EPEL depolarını sisteme ekler. Bu depolar ek yazılım paketlerini kurmaya izin verir.	
	yum install -y epel-release

	#OpenVPN, iptables, openssl, wget, ca-certificates, curl, tar ve policycoreutils-python paketlerini kurar. OpenVPN sunucusunun çalışması için gereken bileşenlerdir.
	yum install -y openvpn iptables openssl wget ca-certificates curl tar 'policycoreutils-python*'

	# Eski bir sürümün easy-rsa'inin varsayılan olarak kurulu olduğu durumları temizlemek için kullanılır.
	rm -rf /etc/openvpn/easy-rsa/
	

	# Find out if the machine uses nogroup or nobody for the permissionless group
	if grep -qs "^nogroup:" /etc/group; then
		NOGROUP=nogroup
	else
		NOGROUP=nobody
	fi

	# İndirilecek easy-rsa sürümünü belirler. Bu durumda sürüm 3.1.2 olarak ayarlanmış.
	local version="3.1.2"
	# Belirtilen sürümdeki easy-rsa'yı GitHub'dan indirir.
	wget -O ~/easy-rsa.tgz https://github.com/OpenVPN/easy-rsa/releases/download/v${version}/EasyRSA-${version}.tgz
	# Easy-rsa için dizini oluşturur.
	mkdir -p /etc/openvpn/easy-rsa
	# İndirilen easy-rsa arşivini çıkarır ve /etc/openvpn/easy-rsa dizinine yerleştirir.
	tar xzf ~/easy-rsa.tgz --strip-components=1 --no-same-owner --directory /etc/openvpn/easy-rsa
	# İndirilen arşivi siler.
	rm -f ~/easy-rsa.tgz

	# Çalışma dizinini easy-rsa'nın kurulu olduğu dizine değiştirir.
	cd /etc/openvpn/easy-rsa/ || return

	echo "set_var EASYRSA_ALGO ec" >vars
	echo "set_var EASYRSA_CURVE $CERT_CURVE" >>vars
	;;
	

	# Sunucu sertifikası için rastgele bir isim oluşturur.
	SERVER_CN="cn_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
	# Oluşturulan sunucu adını ekrana yazdırır.
	echo "$SERVER_CN" >SERVER_CN_GENERATED

	# Benzer şekilde, başka bir rasgele sunucu adı oluşturulur ve SERVER_NAME değişkenine atanır.
	SERVER_NAME="server_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
	# Oluşturulan sunucu adını ekrana yazdırır.
	echo "$SERVER_NAME" >SERVER_NAME_GENERATED

	./easyrsa init-pki
	./easyrsa --batch --req-cn="$SERVER_CN" build-ca nopass
	./easyrsa --batch build-server-full "$SERVER_NAME" nopass

	EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl

	openvpn --genkey --secret /etc/openvpn/tls-crypt.key
		;;

	cp pki/ca.crt pki/private/ca.key "pki/issued/$SERVER_NAME.crt" "pki/private/$SERVER_NAME.key" /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn

	chmod 644 /etc/openvpn/crl.pem

	echo "port $PORT" >/etc/openvpn/server.conf
	echo "proto ${PROTOCOL}6" >>/etc/openvpn/server.conf

	echo "dev tun
	user nobody
	group $NOGROUP
	persist-key
	persist-tun
	keepalive 10 120
	topology subnet
	server 10.8.0.0 255.255.255.0
	ifconfig-pool-persist ipp.txt" >>/etc/openvpn/server.conf

	case $DNS in
	1) 
		if grep -q "127.0.0.53" "/etc/resolv.conf"; then
			RESOLVCONF='/run/systemd/resolve/resolv.conf'
		else
			RESOLVCONF='/etc/resolv.conf'
		fi
		# Obtain the resolvers from resolv.conf and use them for OpenVPN
		sed -ne 's/^nameserver[[:space:]]\+\([^[:space:]]\+\).*$/\1/p' $RESOLVCONF | while read -r line; do
			# Copy, if it's a IPv4 |or| if IPv6 is enabled, IPv4/IPv6 does not matter
			if [[ $line =~ ^[0-9.]*$ ]] || [[ $IPV6_SUPPORT == 'y' ]]; then
				echo "push \"dhcp-option DNS $line\"" >>/etc/openvpn/server.conf
			fi
		done
		;;
	2) 
		# Cloudflare
		echo 'push "dhcp-option DNS 1.0.0.1"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 1.1.1.1"' >>/etc/openvpn/server.conf
		;;
	3) 
		# OpenDNS
		echo 'push "dhcp-option DNS 208.67.222.222"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 208.67.220.220"' >>/etc/openvpn/server.conf
		;;
	4) 
		# Google
		echo 'push "dhcp-option DNS 8.8.8.8"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 8.8.4.4"' >>/etc/openvpn/server.conf
		;;
	5) 
		# Yandex Basic
		echo 'push "dhcp-option DNS 77.88.8.8"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 77.88.8.1"' >>/etc/openvpn/server.conf
		;;
	esac

	echo 'push "redirect-gateway def1 bypass-dhcp"' >>/etc/openvpn/server.conf

	# IPv6 network settings if needed

	echo 'server-ipv6 fd42:42:42:42::/112
	tun-ipv6
	push tun-ipv6
	push "route-ipv6 2000::/3"
	push "redirect-gateway ipv6"' >>/etc/openvpn/server.conf
	echo "dh none" >>/etc/openvpn/server.conf
	echo "ecdh-curve $DH_CURVE" >>/etc/openvpn/server.conf

	echo "tls-crypt tls-crypt.key" >>/etc/openvpn/server.conf
		;;

	echo "crl-verify crl.pem
	ca ca.crt
	cert $SERVER_NAME.crt
	key $SERVER_NAME.key
	auth $HMAC_ALG
	cipher $CIPHER
	ncp-ciphers $CIPHER
	tls-server
	tls-version-min 1.2
	tls-cipher $CC_CIPHER
	client-config-dir /etc/openvpn/ccd
	status /var/log/openvpn/status.log
	verb 3" >>/etc/openvpn/server.conf

	mkdir -p /etc/openvpn/ccd
	mkdir -p /var/log/openvpn

	echo 'net.ipv4.ip_forward=1' >/etc/sysctl.d/99-openvpn.conf
	echo 'net.ipv6.conf.all.forwarding=1' >>/etc/sysctl.d/99-openvpn.conf

	sysctl --system

	if hash sestatus 2>/dev/null; then
		if sestatus | grep "Current mode" | grep -qs "enforcing"; then
			if [[ $PORT != '1194' ]]; then
				semanage port -a -t openvpn_port_t -p "$PROTOCOL" "$PORT"
			fi
		fi
	fi

	# Don't modify package-provided service
	cp /usr/lib/systemd/system/openvpn-server@.service /etc/systemd/system/openvpn-server@.service

	# Workaround to fix OpenVPN service on OpenVZ
	sed -i 's|LimitNPROC|#LimitNPROC|' /etc/systemd/system/openvpn-server@.service
	# Another workaround to keep using /etc/openvpn/
	sed -i 's|/etc/openvpn/server|/etc/openvpn|' /etc/systemd/system/openvpn-server@.service

	systemctl daemon-reload
	systemctl enable openvpn-server@server
	systemctl restart openvpn-server@server

	mkdir -p /etc/iptables

	echo "#!/bin/sh
iptables -t nat -I POSTROUTING 1 -s 10.8.0.0/24 -o $NIC -j MASQUERADE
iptables -I INPUT 1 -i tun0 -j ACCEPT
iptables -I FORWARD 1 -i $NIC -o tun0 -j ACCEPT
iptables -I FORWARD 1 -i tun0 -o $NIC -j ACCEPT
iptables -I INPUT 1 -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >/etc/iptables/add-openvpn-rules.sh

	echo "ip6tables -t nat -I POSTROUTING 1 -s fd42:42:42:42::/112 -o $NIC -j MASQUERADE
ip6tables -I INPUT 1 -i tun0 -j ACCEPT
ip6tables -I FORWARD 1 -i $NIC -o tun0 -j ACCEPT
ip6tables -I FORWARD 1 -i tun0 -o $NIC -j ACCEPT
ip6tables -I INPUT 1 -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >>/etc/iptables/add-openvpn-rules.sh

	echo "#!/bin/sh
iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o $NIC -j MASQUERADE
iptables -D INPUT -i tun0 -j ACCEPT
iptables -D FORWARD -i $NIC -o tun0 -j ACCEPT
iptables -D FORWARD -i tun0 -o $NIC -j ACCEPT
iptables -D INPUT -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >/etc/iptables/rm-openvpn-rules.sh

	echo "ip6tables -t nat -D POSTROUTING -s fd42:42:42:42::/112 -o $NIC -j MASQUERADE
ip6tables -D INPUT -i tun0 -j ACCEPT
ip6tables -D FORWARD -i $NIC -o tun0 -j ACCEPT
ip6tables -D FORWARD -i tun0 -o $NIC -j ACCEPT
ip6tables -D INPUT -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >>/etc/iptables/rm-openvpn-rules.sh

	chmod +x /etc/iptables/add-openvpn-rules.sh
	chmod +x /etc/iptables/rm-openvpn-rules.sh

	echo "[Unit]
Description=iptables rules for OpenVPN
Before=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/etc/iptables/add-openvpn-rules.sh
ExecStop=/etc/iptables/rm-openvpn-rules.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target" >/etc/systemd/system/iptables-openvpn.service

	systemctl daemon-reload
	systemctl enable iptables-openvpn
	systemctl start iptables-openvpn

	if [[ $ENDPOINT != "" ]]; then
		IP=$ENDPOINT
	fi

	echo "client" >/etc/openvpn/client-template.txt
	echo "proto udp" >>/etc/openvpn/client-template.txt
	echo "explicit-exit-notify" >>/etc/openvpn/client-template.txt

	echo "remote $IP $PORT
dev tun
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verify-x509-name $SERVER_NAME name
auth $HMAC_ALG
auth-nocache
cipher $CIPHER
tls-client
tls-version-min 1.2
tls-cipher $CC_CIPHER
ignore-unknown-option block-outside-dns
setenv opt block-outside-dns # Prevent Windows 10 DNS leak
verb 3" >>/etc/openvpn/client-template.txt

	newClient
}

function newClient() {
	echo ""
	echo "Kullanıcı adı:"

	until [[ $CLIENT =~ ^[a-zA-Z0-9_-]+$ ]]; do
		read -rp "Client Adı: " -e CLIENT
	done

	echo ""
	echo "Kullanıcıya şifre tanımlaması yapmak ister misiniz?"
	echo "   1) Hayır."
	echo "   2) Evet"

	until [[ $PASS =~ ^[1-2]$ ]]; do
		read -rp "Lütfen seçiniz: [1-2]: " -e -i 1 PASS
	done

	CLIENTEXISTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c -E "/CN=$CLIENT\$")
	if [[ $CLIENTEXISTS == '1' ]]; then
		echo ""
		echo "Bu kullanıcı daha önce tanımlandı. Lütfen yeni bir kullanıcı girişi yapınız."
		exit
	else
		cd /etc/openvpn/easy-rsa/ || return
		case $PASS in
		1)
			./easyrsa --batch build-client-full "$CLIENT" nopass
			;;
		2)
			echo "Lütfen şifreyi giriniz."
			./easyrsa --batch build-client-full "$CLIENT"
			;;
		esac
		echo "Client $CLIENT eklendi."
	fi

	if [ -e "/home/${CLIENT}" ]; then
		homeDir="/home/${CLIENT}"
	elif [ "${SUDO_USER}" ]; then
		if [ "${SUDO_USER}" == "root" ]; then
			homeDir="/root"
		else
			homeDir="/home/${SUDO_USER}"
		fi
	else
		homeDir="/root"
	fi

	cp /etc/openvpn/client-template.txt "$homeDir/$CLIENT.ovpn"
	{
		echo "<ca>"
		cat "/etc/openvpn/easy-rsa/pki/ca.crt"
		echo "</ca>"

		echo "<cert>"
		awk '/BEGIN/,/END CERTIFICATE/' "/etc/openvpn/easy-rsa/pki/issued/$CLIENT.crt"
		echo "</cert>"

		echo "<key>"
		cat "/etc/openvpn/easy-rsa/pki/private/$CLIENT.key"
		echo "</key>"

		echo "<tls-crypt>"
		cat /etc/openvpn/tls-crypt.key
		echo "</tls-crypt>"
		;;
		esac
	} >>"$homeDir/$CLIENT.ovpn"

	echo ""
	echo "Yapılandırma dosyası tamamlandı: $homeDir/$CLIENT.ovpn."

	exit 0
}

function revokeClient() {
	NUMBEROFCLIENTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c "^V")
	if [[ $NUMBEROFCLIENTS == '0' ]]; then
		echo ""
		echo "Henüz oluşturulmuş bir hesap bulunamadı."
		exit 1
	fi

	echo ""
	echo "İptal etmek istediğiniz istemci sertifikasını seçiniz."
	tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ')'
	until [[ $CLIENTNUMBER -ge 1 && $CLIENTNUMBER -le $NUMBEROFCLIENTS ]]; do
		if [[ $CLIENTNUMBER == '1' ]]; then
			read -rp "Müşteri seçiniz [1]: " CLIENTNUMBER
		else
			read -rp "Müşteri seçiniz [1-$NUMBEROFCLIENTS]: " CLIENTNUMBER
		fi
	done

	CLIENT=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$CLIENTNUMBER"p)
	cd /etc/openvpn/easy-rsa/ || return

	./easyrsa --batch revoke "$CLIENT"
	EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl

	rm -f /etc/openvpn/crl.pem
	cp /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/crl.pem
	chmod 644 /etc/openvpn/crl.pem
	find /home/ -maxdepth 2 -name "$CLIENT.ovpn" -delete
	rm -f "/root/$CLIENT.ovpn"
	sed -i "/^$CLIENT,.*/d" /etc/openvpn/ipp.txt
	cp /etc/openvpn/easy-rsa/pki/index.txt{,.bk}

	echo ""
	echo "Certificate for client $CLIENT revoked."
}

function manageMenu() {
	echo "potuX VPN Kurulum Aracı v1.1 | Hoşgeldiniz..."
	echo "Lütfen aşağıdaki menüden yapmak istediğiniz işlemi seçin. "
	echo ""
	echo "Lütfen yapmak istediğiniz işlemi seçiniz."
	echo "   1) Yeni Kullanıcı Oluştur"
	echo "   2) Kullanıcıyı Yasakla"
	echo "   2) VPN Server Kur"
	echo "   4) Çıkış Yap"

	until [[ $MENU_OPTION =~ ^[1-4]$ ]]; do
		read -rp "Lütfen seçiniz: [1-4]: " MENU_OPTION
	done

	case $MENU_OPTION in
	1)
		newClient
		;;
	2)
		revokeClient
		;;
	3)
		installOpenVPN
		;;
	4)
		exit 0
		;;
	esac
}

manageMenu