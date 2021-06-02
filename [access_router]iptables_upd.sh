#!/bin/sh

# ** Variables
IPTABLES="/sbin/iptables"

ACCESS_ROUTER="192.168.0.1"  #sits between the dmz and internet
CHOKE_ROUTER="192.168.1.1" # sits between the dmz and lan
PRIVATE_NETWORK="192.168.1.1/24"
DMZ_NETWORK="192.168.1.0/24"
WEB_SERVER="192.168.1.2"
EMAIL_SERVER="192.168.1.3"
APP_GATEWAY="192.168.1.4"

DMZ_INTERFACE="eth1"
LAN_INTERFACE="eth0"
PUBLIC_INTERFACE="ppp0"

PROVIDER_IP_RANGE="11.11.11.0/24"

echo "Starting Firewall..."
echo ""

# Delete all of the iptables rules that was created before
$IPTABLES -F

# Set default iptables chaines to block everything except what is allowed
$IPTABLES -P INPUT DROP
$IPTABLES -P OUTPUT DROP
$IPTABLES -P FORWARD DROP

# Enable IPv4 forwarding
echo "1" > /proc/sys/net/ipv4/ip_forward

# Blocking IP Spoofing attacks.
echo "1" > /proc/sys/net/ipv4/conf/all/rp_filter
echo "1" > /proc/sys/net/ipv4/conf/default/rp_filter
echo "1" > /proc/sys/net/ipv4/conf/eth0/rp_filter
echo "1" > /proc/sys/net/ipv4/conf/ppp0/rp_filter
echo "1" > /proc/sys/net/ipv4/conf/eth1/rp_filter


# INPUT chain

# DNS client
$IPTABLES -A INPUT -i $PUBLIC_INTERFACE -s 0/0 -p udp --sport 53 -m state --state ESTABLISHED -j ACCEPT
$IPTABLES -A INPUT -i $DMZ_INTERFACE -s $DMZ_NETWORK -p udp --sport 53 -m state --state ESTABLISHED -j ACCEPT

# Allow incoming echo reply
$IPTABLES -A INPUT -i $PUBLIC_INTERFACE -p icmp --icmp-type 0 -s 0/0 -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPTABLES -A INPUT -i $DMZ_INTERFACE -p icmp --icmp-type 0 -s $DMZ_NETWORK -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow traceroute only from provider to firewall public interface
$IPTABLES -A INPUT -i $PUBLIC_INTERFACE -p icmp --icmp-type 8 -s $PROVIDER_IP_RANGE -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT


# Drop all of the incoming fragmented packets
$IPTABLES -A INPUT -f -j DROP

# Drop all SMTP packets from 15.1.23.22 (spamer)
$IPTABLES -A INPUT -i $PUBLIC_INTERFACE -s 15.1.23.22 -p tcp --dport 25 -m state --state NEW -j DROP

# Drop all packets from 160.25.0.0/24
$IPTABLES -A INPUT -i $PUBLIC_INTERFACE -s 160.25.0.0/24 -m state --state NEW -j DROP


# SMTP server incoming SYN and ACK
$IPTABLES -A INPUT -i $PUBLIC_INTERFACE --dport 25 -s 0/0 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPTABLES -A INPUT -i $DMZ_INTERFACE --dport 25 -s $DMZ_NETWORK -m state --state NEW,ESTABLISHED -j ACCEPT

# SSH server incoming SYN and ACK
$IPTABLES -A INPUT -i $PUBLIC_INTERFACE -s 0/0 -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPTABLES -A INPUT -i $DMZ_INTERFACE -s $DMZ_NETWORK -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT

# FTP server incoming SYN and ACK
$IPTABLES -A INPUT -i $PUBLIC_INTERFACE -s 0/0 -p tcp --dport 21 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
$IPTABLES -A INPUT -i $DMZ_INTERFACE -s $DMZ_NETWORK -p tcp --dport 21 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

# WWW server incoming SYN and ACK (for HTTP)
$IPTABLES -A INPUT -i $PUBLIC_INTERFACE -s 0/0 -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPTABLES -A INPUT -i $DMZ_INTERFACE -s $DMZ_NETWORK -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
# WWW server incoming SYN and ACK (for HTTPS)
$IPTABLES -A INPUT -i $PUBLIC_INTERFACE -s 0/0 -p tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPTABLES -A INPUT -i $DMZ_INTERFACE -s $DMZ_NETWORK -p tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT

# SMTP client incoming SYN-ACK
$IPTABLES -A INPUT -i $PUBLIC_INTERFACE -s 0/0 --sport 25 -m state --state ESTABLISHED -j ACCEPT

# SSH client incoming SYN-ACK
$IPTABLES -A INPUT -i $PUBLIC_INTERFACE -s 0/0 -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT
$IPTABLES -A INPUT -i $DMZ_INTERFACE -s $DMZ_NETWORK -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT

# FTP client incoming SYN-ACK
$IPTABLES -A INPUT -i $PUBLIC_INTERFACE -s 0/0 -p tcp --sport 21 -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPTABLES -A INPUT -i $DMZ_INTERFACE -s $DMZ_NETWORK -p tcp --sport 21 -m state --state ESTABLISHED,RELATED -j ACCEPT

# WWW client (for HTTP) incoming SYN-ACK
$IPTABLES -A INPUT -i $PUBLIC_INTERFACE -s 0/0 -p tcp --sport 80 -m state --state ESTABLISHED -j ACCEPT
$IPTABLES -A INPUT -i $DMZ_INTERFACE -s $DMZ_NETWORK -p tcp --sport 80 -m state --state ESTABLISHED -j ACCEPT
# WWW client (for HTTPS) incoming SYN-ACK
$IPTABLES -A INPUT -i $PUBLIC_INTERFACE -s 0/0 -p tcp --sport 443 -m state --state ESTABLISHED -j ACCEPT
$IPTABLES -A INPUT -i $DMZ_INTERFACE -s $DMZ_NETWORK -p tcp --sport 443 -m state --state ESTABLISHED -j ACCEPT


# Allow POP3S for dmz
$IPTABLES -A INPUT -i $PUBLIC_INTERFACE -s $DMZ_NETWORK -p tcp --dport 995 -m state –state NEW,ESTABLISHED -j ACCEPT

# Allow IMAP4 for DMZ
$IPTABLES -A INPUT -i $PUBLIC_INTERFACE -s $DMZ_NETWORK -p tcp --dport 143 -j ACCEPT


# OUTPUT chain


# SMTP server outgoing SYN-ACK
$IPTABLES -A OUTPUT -o $PUBLIC_INTERFACE --sport 25 -d 0/0 -m state --state ESTABLISHED -j ACCEPT
$IPTABLES -A OUTPUT -o $DMZ_INTERFACE --sport 25 -d $DMZ_NETWORK -m state --state ESTABLISHED -j ACCEPT

# SSH server outgoing SYN-ACK
$IPTABLES -A OUTPUT -o $PUBLIC_INTERFACE -d 0/0 -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT
$IPTABLES -A OUTPUT -o $DMZ_INTERFACE -d $DMZ_NETWORK -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT

# FTP server outgoing SYN-ACK
$IPTABLES -A OUTPUT -o $PUBLIC_INTERFACE -d 0/0 -p tcp --sport 21 -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPTABLES -A OUTPUT -o $DMZ_INTERFACE -d $DMZ_NETWORK -p tcp --sport 21 -m state --state ESTABLISHED,RELATED -j ACCEPT

# WWW server (for HTTP) outgoing SYN-ACK
$IPTABLES -A OUTPUT -o $PUBLIC_INTERFACE -d 0/0 -p tcp --sport 80 -m state --state ESTABLISHED -j ACCEPT
$IPTABLES -A OUTPUT -o $DMZ_INTERFACE -d $DMZ_NETWORK -p tcp --sport 80 -m state --state ESTABLISHED -j ACCEPT
# WWW server (for HTTPS) outgoing SYN-ACK
$IPTABLES -A OUTPUT -o $PUBLIC_INTERFACE -d 0/0 -p tcp --sport 443 -m state --state ESTABLISHED -j ACCEPT
$IPTABLES -A OUTPUT -o $DMZ_INTERFACE -d $DMZ_NETWORK -p tcp --sport 443 -m state --state ESTABLISHED -j ACCEPT

# SMTP client incoming SYN and ACK
$IPTABLES -A OUTPUT -o $PUBLIC_INTERFACE -d 0/0 --dport 25 -m state --state NEW,ESTABLISHED -j ACCEPT

# SSH client incoming SYN and ACK
$IPTABLES -A OUTPUT -o $PUBLIC_INTERFACE -d 0/0 -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPTABLES -A OUTPUT -o $DMZ_INTERFACE -d $DMZ_NETWORK -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT

# FTP client incoming SYN and ACK
$IPTABLES -A OUTPUT -o $PUBLIC_INTERFACE -d 0/0 -p tcp --dport 21 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
$IPTABLES -A OUTPUT -o $DMZ_INTERFACE -d $DMZ_NETWORK -p tcp --dport 21 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

# WWW client (for HTTP) incoming SYN and ACK
$IPTABLES -A OUTPUT -o $PUBLIC_INTERFACE -d 0/0 -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPTABLES -A OUTPUT -o $DMZ_INTERFACE -d $DMZ_NETWORK -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
# WWW client (for HTTPS) incoming SYN and ACK
$IPTABLES -A OUTPUT -o $PUBLIC_INTERFACE -d 0/0 -p tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPTABLES -A OUTPUT -o $DMZ_INTERFACE -d $DMZ_NETWORK -p tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT

# DNS client
$IPTABLES -A OUTPUT -o $PUBLIC_INTERFACE -d 0/0 -p udp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPTABLES -A OUTPUT -o $DMZ_INTERFACE -d $DMZ_NETWORK -p udp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT

# Allow outgoing echo requests
$IPTABLES -A OUTPUT -o $PUBLIC_INTERFACE -p icmp --icmp-type 8 -d 0/0 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
$IPTABLES -A OUTPUT -o $DMZ_INTERFACE -p icmp --icmp-type 8 -d $DMZ_NETWORK -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

# Allow incoming echo reply only to provider
$IPTABLES -A OUTPUT -o $PUBLIC_INTERFACE -p icmp --icmp-type 0 -d $PROVIDER_IP_RANGE -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow POP3 for DMZ network
$IPTABLES -A OUTPUT -o $DMZ_INTERFACE -d $DMZ_NETWORK -p tcp --sport 110 -j ACCEPT

# Allow IMAP4 for public network
$IPTABLES -A OUTPUT -o $PUBLIC_INTERFACE -d 0/0 -p tcp --sport 143 -j ACCEPT

# PREROUTING chain 

# Route WWW (HTTP) trafic from Internet to web server in DMZ using DNAT
$IPTABLES -t nat -A PREROUTING -i $PUBLIC_INTERFACE -p tcp --dport 80 -j DNAT --to-destination "$INFO_SERVER:80"
# Route WWW (HTTPS) trafic from Internet to the web server in DMZ network 
$IPTABLES -t nat -A PREROUTING -i $PUBLIC_INTERFACE -p tcp --dport 443 -j DNAT --to-destination "$INFO_SERVER:443"


# POSTROUTING chain


# Route WWW trafic from the web-server in DMZ network to the Internet
$IPTABLES -t nat -A POSTROUTING -o $PUBLIC_INTERFACE -s $MY_SERVER_IP -p tcp --sport 80 -j SNAT --to-source $MY_FIREWALL_IP
$IPTABLES -t nat -A POSTROUTING -o $PUBLIC_INTERFACE -s $MY_SERVER_IP -p tcp --sport 443 -j SNAT --to-source $MY_FIREWALL_IP


# FORWARDING chain


# Forward SSH trafic to the Internet from and back to SSH client in DMZ network 
$IPTABLES -A FORWARD -i $DMZ_INTERFACE -o $PUBLIC_INTERFACE -s $DMZ_NETWORK --dport 22 -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT 
$IPTABLES -A FORWARD -i $PUBLIC_INTERFACE -o $DMZ_INTERFACE -s 0/0 --sport 22 -p tcp -m state --state ESTABLISHED -j ACCEPT 

# Forward FTP trafic to the Internet from and back to FTP client in DMZ network 
$IPTABLES -A FORWARD -i $DMZ_INTERFACE -o $PUBLIC_INTERFACE -s $DMZ_NETWORK --dport 21 -p tcp -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT 
$IPTABLES -A FORWARD -i $PUBLIC_INTERFACE -o $DMZ_INTERFACE -s 0/0 --sport 21 -p tcp -m state --state ESTABLISHED -j ACCEPT 

# Forward WWW (HTTP) trafic to the Internet from and back to WWW client in DMZ network 
$IPTABLES -A FORWARD -i $DMZ_INTERFACE -o $PUBLIC_INTERFACE -s $DMZ_NETWORK --dport 80 -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT 
$IPTABLES -A FORWARD -i $PUBLIC_INTERFACE -o $DMZ_INTERFACE -s 0/0 --sport 80 -p tcp -m state --state ESTABLISHED -j ACCEPT 
# Forward WWW (HTTPS) trafic to the Internet from and back to WWW client in DMZ network 
$IPTABLES -A FORWARD -i $DMZ_INTERFACE -o $PUBLIC_INTERFACE -s $DMZ_NETWORK --dport 443 -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT 
$IPTABLES -A FORWARD -i $PUBLIC_INTERFACE -o $DMZ_INTERFACE -s 0/0 --sport 443 -p tcp -m state --state ESTABLISHED -j ACCEPT 

# Forward WWW (HTTP) trafic to the Internet from and to the web server in DMZ network
$IPTABLES -A FORWARD -i $PUBLIC_INTERFACE -o $DMZ_INTERFACE -s 0/0 -d $MY_SERVER_IP --dport 80 -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT 
$IPTABLES -A FORWARD -i $DMZ_INTERFACE -o $PUBLIC_INTERFACE -s $MY_SERVER_IP -d 0/0  --sport 80 -p tcp -m state --state ESTABLISHED -j ACCEPT 
# Forward WWW (HTTPS) trafic to the Internet from and to the web server in DMZ network
$IPTABLES -A FORWARD -i $PUBLIC_INTERFACE -o $DMZ_INTERFACE -s 0/0 -d $MY_SERVER_IP --dport 443 -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT 
$IPTABLES -A FORWARD -i $DMZ_INTERFACE -o $PUBLIC_INTERFACE -s $MY_SERVER_IP -d 0/0  --sport 443 -p tcp -m state --state ESTABLISHED -j ACCEPT 

# Forward DNS trafic to the Internet from and back to DNS client in DMZ network 
$IPTABLES -A FORWARD -i $DMZ_INTERFACE -o $PUBLIC_INTERFACE -s $DMZ_NETWORK --dport 53 -p udp -m state --state NEW,ESTABLISHED -j ACCEPT 
$IPTABLES -A FORWARD -i $PUBLIC_INTERFACE -o $DMZ_INTERFACE -s 0/0 --sport 53 -p udp -m state --state ESTABLISHED -j ACCEPT 

# Forward outgoing echo requests and replies
$IPTABLES -A FORWARD -i $DMZ_INTERFACE -o $PUBLIC_INTERFACE -s $DMZ_NETWORK -p icmp --icmp-type 8 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT 
$IPTABLES -A FORWARD -i $PUBLIC_INTERFACE -o $DMZ_INTERFACE -s 0/0 -p icmp --icmp-type 0 -m state --state ESTABLISHED -j ACCEPT 

# Forward traffic from DMZ network to the provider web proxy
$IPTABLES -A FORWARD -i $DMZ_INTERFACE -o $PUBLIC_INTERFACE -s $DMZ_NETWORK -d $PROVIDER_IP_RANGE -m state --state NEW,ESTABLISHED --dport 3128 -j ACCEPT 
$IPTABLES -A FORWARD -i $PUBLIC_INTERFACE -o $DMZ_INTERFACE -s $PROVIDER_IP_RANGE --sport 3128 -m state --state ESTABLISHED -j ACCEPT 

# Forward outgoing traceroute to the provider from DMZ network
$IPTABLES -A FORWARD -i $DMZ_INTERFACE -o $PUBLIC_INTERFACE -d $PROVIDER_IP_RANGE -p udp --dport 33434:33474 -m state --state NEW,ESTABLISHED -j ACCEPT 
$IPTABLES -A FORWARD -i $PUBLIC_INTERFACE -o $DMZ_INTERFACE -s $PROVIDER_IP_RANGE -p udp --sport 33434:33474 -m state --state ESTABLISHED -j ACCEPT 
# Forward incoming traceroute from the provider to DMZ network
$IPTABLES -A FORWARD -i $DMZ_INTERFACE -o $PUBLIC_INTERFACE -d $PROVIDER_IP_RANGE -p udp --dport 33434:33474 -m state --state NEW,ESTABLISHED -j ACCEPT 
$IPTABLES -A FORWARD -i $PUBLIC_INTERFACE -o $DMZ_INTERFACE -s $PROVIDER_IP_RANGE -p udp --sport 33434:33474 -m state --state ESTABLISHED -j ACCEPT 
