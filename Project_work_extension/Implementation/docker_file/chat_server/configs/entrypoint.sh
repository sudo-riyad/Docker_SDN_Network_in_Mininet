#!/bin/sh

#CREATE THE USER AND THE HOME FOLDER
addgroup -g $FTP_UID -S $FTP_USER
if [[ "$FTP_HOME" != "default" ]]; then
  adduser -u $FTP_UID -D -G $FTP_USER -h $FTP_HOME -s /bin/false  $FTP_USER
  chown $FTP_USER:$FTP_USER $FTP_HOME -R
else
  adduser -u $FTP_UID -D -G $FTP_USER -h /home/$FTP_USER -s /bin/false  $FTP_USER
  chown $FTP_USER:$FTP_USER /home/$FTP_USER/ -R
fi

#UPDATE PASSWORD
echo "$FTP_USER:$FTP_PASS" | /usr/sbin/chpasswd

cp /etc/vsftpd.conf_or /etc/vsftpd.conf

if [[ "$PASV_ENABLE" == "YES" ]]; then
  echo "PASV is enabled"
  echo "pasv_enable=YES" >> /etc/vsftpd.conf
  echo "pasv_max_port=$PASV_MAX" >> /etc/vsftpd.conf
  echo "pasv_min_port=$PASV_MIN" >> /etc/vsftpd.conf
  echo "pasv_address=$PASV_ADDRESS" >> /etc/vsftpd.conf
else
  echo "pasv_enable=NO" >> /etc/vsftpd.conf
fi

if [[ "$ONLY_UPLOAD" == "YES" ]]; then
  echo "This FTP server only accepts upload."
  echo "download_enable=NO" >> /etc/vsftpd.conf
  echo "ftpd_banner=Welcome to FTP Server. Note: this FTP server only accepts upload." >> /etc/vsftpd.conf
elif [[ "$ONLY_DOWNLOAD" == "YES" ]]; then
  echo "This FTP server only accepts download."
  echo "ftpd_banner=Welcome to FTP Server. Note: this FTP server only accepts download." >> /etc/vsftpd.conf
  sed -i 's/write_enable=YES/write_enable=NO/g' /etc/vsftpd.conf
else
  echo "ftpd_banner=Welcome to FTP Server" >> /etc/vsftpd.conf
fi

echo "local_umask=$UMASK" >> /etc/vsftpd.conf

/usr/sbin/vsftpd /etc/vsftpd.conf &
