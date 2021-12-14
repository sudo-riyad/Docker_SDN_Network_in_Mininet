############################################################
# Dockerfile to build a simple vsFTPd server for the eBioKit
# Based on alpine linux
# Version 0.1 October 2017
############################################################

FROM ubuntu:18.04

WORKDIR /chat
COPY server.py /chat


RUN useradd -rm -d /home/ftpuser ftpuser  -p 123


RUN apt-get update &&  apt-get install -y vsftpd\
 net-tools \
    iputils-ping \
    iproute2 \
 curl \
    iperf \
    python3\
    nano

RUN rm /etc/vsftpd.conf 
RUN touch /etc/vsftpt.conf


COPY configs/entrypoint.sh /usr/sbin/

ENV FTP_USER=ftpuser \
    FTP_PASS=123 \
    FTP_HOME=default \
    FTP_UID=1000 \
    ONLY_UPLOAD=NO \
    ONLY_DOWNLOAD=NO \
    PASV_ENABLE=NO \
    PASV_ADDRESS=10.0.0.251 \
    PASV_MIN=21100 \
    PASV_MIN=21100 \
    UMASK=022

RUN echo "local_enable=YES" >> /etc/vsftpd.conf \
  && echo "chroot_local_user=YES" >> /etc/vsftpd.conf \
&& echo "listen=YES" >> /etc/vsftpd.conf \
  && echo "allow_writeable_chroot=YES" >> /etc/vsftpd.conf \
  && echo "background=NO" >> /etc/vsftpd.conf \
  && echo "dirmessage_enable=YES" >> /etc/vsftpd.conf \
  && echo "max_clients=10" >> /etc/vsftpd.conf \
  && echo "max_per_ip=5" >> /etc/vsftpd.conf \
  && echo "write_enable=YES" >> /etc/vsftpd.conf \
  && echo "passwd_chroot_enable=yes" >> /etc/vsftpd.conf \
  && echo "listen_ipv6=NO" >> /etc/vsftpd.conf \
  && echo "seccomp_sandbox=NO" >> /etc/vsftpd.conf \
  && sed -i "s/anonymous_enable=YES/anonymous_enable=NO/" /etc/vsftpd.conf \
  && cp /etc/vsftpd.conf /etc/vsftpd.conf_or \
  && chmod +x /usr/sbin/entrypoint.sh
RUN mkdir -p /var/run/vsftpd/empty
RUN mkdir  /home/ftpuser/files
COPY server.py /home/ftpuser/files
ENTRYPOINT ["/bin/bash"]


