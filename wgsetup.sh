#!/bin/bash
#
# Express setup of WireGuard server
# for Ubuntu 20.x and Later
# by r3bers https://github.com/r3bers
#
# Version 0.1  Apr 2021
#
# Script is licensed under the GNU General Public License v3.0
#
# Usage: just run wgsetup.sh :)
#

NET4="192.168.212.0/24" # Network  IPv4 for wg clients
NET6="fd60:1:1:1::/64"  # Network  IPv4 for wg clients
DNS1="8.8.8.8"
DNS2="8.8.4.4"

# Uncomment some options for less asking from console
PORT=63665
IPV6E=1

# check for root
IAM=$(whoami)
if [[ ${IAM} != "root" ]]; then
  echo "You must be root to use this script"
  exit 1
fi

WG_DIR="/etc/wireguard"
INSTALLED=1

if ! [ -d "/$WG_DIR" ]; then
  INSTALLED=0
  echo "No WireGuard folder. Creating..."
  mkdir -m 700 "$WG_DIR"
fi

if ! [ -d "/$WG_DIR/keys" ]; then
  INSTALLED=0
  echo "No Keys folder. Creating..."
  mkdir -m 700 "/$WG_DIR/keys"
fi

if ! [ -d "/$WG_DIR/clients" ]; then
  INSTALLED=0
  echo "No Clients folder. Creating..."
  mkdir -m 700 "/$WG_DIR/clients"
fi

if ! [ -d "/$WG_DIR/qr" ]; then
  INSTALLED=0
  echo "No QRCode folder. Creating..."
  mkdir -m 700 "/$WG_DIR/qr"
fi

if ! [ -f "/$WG_DIR/wg0.conf" ]; then
  INSTALLED=0
  echo "No wg0.conf. Creating..."
  touch "/$WG_DIR/wg0.conf"
  chmod 600 "/$WG_DIR/wg0.conf"
fi

if ! ip -6 a show scope global | grep inet6 >/dev/null; then IPV6E=0; fi

if [[ -z ${IPV6E+x} ]]; then
  echo "Enable IPv6? (ensure that your machine have IPv6 support):
    1) Yes
    2) No"
  read -r n
  case ${n} in
  1) IPV6E=1 ;;
  2) IPV6E=0 ;;
  *) echo "invalid option" && exit 1 ;;
  esac
fi

# External IPv4
EIPv4=$(curl -s checkip.dyndns.org | sed -e 's/.*Current IP Address: //' -e 's/<.*$//')
DEVv4=$(ip -oneline -4 a | grep "$EIPv4" | awk '{print$2}')
ENETv4=$(ip -4 a show scope global | grep "$EIPv4" | awk '{print$2}')

echo "External IPv4: $EIPv4"
echo "Device IPv4: $DEVv4"

# External IPv6
if [ $IPV6E -eq 1 ]; then
  EIPv6=$(ip -6 a show scope global | grep inet6 | awk -F '[ \t]+|/' '{print $3}')
  DEVv6=$(ip -oneline -6 a | grep "$EIPv6" | awk '{print$2}')
  ENETv6=$(ip -6 a show scope global | grep "$EIPv6" | awk '{print$2}')

  echo "External IPv6: $EIPv6"
  echo "Device IPv6: $DEVv6"
fi

if [ $INSTALLED -eq 0 ]; then
  # Enable IPv4 forwarding
  if ! sysctl net.ipv4.ip_forward | grep 1 >/dev/null; then
    sysctl -w net.ipv4.ip_forward=1
    echo "net.ipv4.ip_forward = 1" >>/etc/sysctl.conf
  fi
  if ! sysctl net.ipv4.conf.all.rp_filter | grep 1 >/dev/null; then
    sysctl -w net.ipv4.conf.all.rp_filter=1
    echo "net.ipv4.conf.all.rp_filter = 1" >>/etc/sysctl.conf
  fi
  if ! sysctl net.ipv4.conf.default.proxy_arp | grep 0 >/dev/null; then
    sysctl -w net.ipv4.conf.default.proxy_arp=0
    echo "net.ipv4.conf.default.proxy_arp = 0" >>/etc/sysctl.conf
  fi
  if ! sysctl net.ipv4.conf.default.send_redirects | grep 1 >/dev/null; then
    sysctl -w net.ipv4.conf.default.send_redirects=1
    echo "net.ipv4.conf.default.send_redirects = 1" >>/etc/sysctl.conf
  fi
  if ! sysctl net.ipv4.conf.all.send_redirects | grep 0 >/dev/null; then
    sysctl -w net.ipv4.conf.all.send_redirects=0
    echo "net.ipv4.conf.all.send_redirects = 0" >>/etc/sysctl.conf
  fi

  if [ $IPV6E -eq 1 ]; then
    # Enable IPv6 forwarding
    if ! sysctl net.ipv6.conf.default.forwarding | grep 1 >/dev/null; then
      sysctl -w net.ipv6.conf.default.forwarding=1
      echo "net.ipv6.conf.default.forwarding = 1" >>/etc/sysctl.conf
    fi
    if ! sysctl net.ipv6.conf.all.forwarding | grep 1 >/dev/null; then
      sysctl -w net.ipv6.conf.all.forwarding=1
      echo "net.ipv6.conf.all.forwarding = 1" >>/etc/sysctl.conf
    fi
  fi

  #package install
  deb_packages=(wireguard qrencode subnetcalc)

  if cat /etc/*release | grep ^NAME | grep "Debian\|Ubuntu" >/dev/null; then
    if dpkg -l "${deb_packages[@]}" 1>/dev/null 2>/dev/null; then
      echo "All Packages Installed..."
    else
      echo "Installing packages..."
      if ! apt-get install -y "${deb_packages[@]}" 1>/dev/null 2>/dev/null; then
        echo "Something wrong with installing packages: " "${deb_packages[@]}"
      fi
    fi
    if hash ufw 2>/dev/null; then
      ufw disable
    else
      echo "UFW not installed"
    fi
  else
    echo "Unsupported distro, sorry"
    exit 1
  fi

  # Server settings
  if [[ -z ${PORT+x} ]]; then
    echo "Select server PORT to listen on:
    1) 443
    2) 63665 (default)
    3) Enter manually port"
    read -r n
    case ${n} in
    1) PORT=443 ;;
    2) PORT=63665 ;;
    3)
      echo -n "Enter port (like 80 or 53): " &
      read -re PORT
      ;;
    *) PORT=63665 ;;
    esac
  fi

  if [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ]; then
    echo "Port: $PORT"
  else
    echo "Port out of range 1-65535."
    exit 1
  fi

  ExternalADDR=$ENETv4

  wg genkey | sudo tee $WG_DIR/keys/server.key | wg pubkey | sudo tee $WG_DIR/keys/server.key.pub >/dev/null
  server_key=$(cat $WG_DIR/keys/server.key)

  POST_UP="iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o $DEVv4 -j MASQUERADE"
  POST_DOWN="iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o $DEVv4 -j MASQUERADE"

  if [ $IPV6E -eq 1 ]; then
    ExternalADDR=$ExternalADDR",$ENETv6"
    POST_UP=$POST_UP"; ip6tables -A FORWARD -i wg0 -j ACCEPT; ip6tables -t nat -A POSTROUTING -o $DEVv6 -j MASQUERADE"
    POST_DOWN=$POST_DOWN"; ip6tables -D FORWARD -i wg0 -j ACCEPT; ip6tables -t nat -D POSTROUTING -o $DEVv6 -j MASQUERADE"
  fi

  echo "[Interface]
Address = $ExternalADDR
ListenPort = $PORT
PrivateKey = $server_key
PostUp = $POST_UP
PostDown = $POST_DOWN
" >"$WG_DIR/wg0.conf"

  # wg-quick up wg0
  # systemctl enable wg-quick@wg0

else
  PORT=$(grep "ListenPort" $WG_DIR/wg0.conf | awk '{print$3}')
fi

if [ $# -eq 0 ]; then
  echo "Usage wgsetup <username>"
else

  # WireGuard IPv4 Calculation
  if subnetcalc $NET4 -nocolor -n >/dev/null; then
    WG_IP4=$(subnetcalc $NET4 -nocolor -n | grep "Host Range" | awk '{print $5}')
    WG_NET4=$(echo "${WG_IP4//\./ }" | awk '{print$1"."$2"."$3"."}')
    WG_NEXT4=$(echo "${WG_IP4//\./ }" | awk '{print$4}')
    WG_PREFIX4=$(subnetcalc $NET4 -nocolor -n | grep "Network" | awk '{print$5}')
  else
    echo "IPv4 network have bad Address"
    exit 1
  fi

  # WireGuard IPv6 Calculation
  if [ $IPV6E -eq 1 ]; then
    if subnetcalc $NET6 -nocolor -n >/dev/null; then
      DELIM="::"
      WG_IP6=$(subnetcalc $NET6 -nocolor -n | grep "Host Range" | awk '{print$5}')
      WG_NET6=$(echo "${WG_IP6//$DELIM/ }" | awk '{print$1}')"$DELIM"
      WG_NEXT6=$(echo "${WG_IP6//$DELIM/ }" | awk '{print$2}')
      WG_PREFIX6=$(subnetcalc $NET6 -nocolor -n | grep "Network" | awk '{print$5}')
    else
      echo "IPv6 network have bad Address"
      exit 1
    fi
  fi

  wg genkey | tee "$WG_DIR/keys/$1.key" | wg pubkey | tee "$WG_DIR/keys/$1.key.pub" >/dev/null

  priv_key=$(cat "$WG_DIR/keys/$1.key")
  pub_key=$(cat "$WG_DIR/keys/$1.key.pub")
  server_pubkey=$(cat $WG_DIR/keys/server.key.pub)
  exist_clients=$(cd $WG_DIR/clients && find . -maxdepth 1 -type f | wc -l)

  next_ip=$((WG_NEXT4 + exist_clients))
  ClientAddr="$WG_NET4$next_ip/$WG_PREFIX4"
  if [ $IPV6E -eq 1 ]; then
    next_ip6=$((WG_NEXT6 + exist_clients))
    ClientAddr=$ClientAddr",$WG_NET6$next_ip6/$WG_PREFIX6"
  fi
  AllowIP="0.0.0.0/0"
  if [ $IPV6E -eq 1 ]; then
    AllowIP=$AllowIP",::/0"
  fi

  echo "[Interface]
PrivateKey = $priv_key
Address = $ClientAddr
DNS = $DNS1, $DNS2

[Peer]
PublicKey = $server_pubkey
AllowedIPs = $AllowIP
Endpoint = $EIPv4:$PORT
" >"$WG_DIR/clients/$1.conf"

  qrencode -t png32 -o "$WG_DIR/qr/$1.png" <"$WG_DIR/clients/$1.conf"
  qrencode -t ansiutf8 <"$WG_DIR/clients/$1.conf"

  ClientIP="$WG_NET4$next_ip/32"
  if [ $IPV6E -eq 1 ]; then
    ClientIP=$ClientIP",$WG_NET6$next_ip6/128"
  fi

  echo "[Peer]
PublicKey = $pub_key
AllowedIPs = $ClientIP
" >>$WG_DIR/wg0.conf

  # wg-quick down wg0
  # wg-quick up wg0
fi
