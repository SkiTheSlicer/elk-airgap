#!/bin/bash
#
# ELK (Elasticsearch, Logstash, Kibana) Stack Offline Installation Script
# by SkiTheSlicer
#
# Ref: https://www.digitalocean.com/community/tutorials/how-to-install-elasticsearch-logstash-and-kibana-4-on-ubuntu-14-04
#
# 20151109 Created from ELK_Install_Guide_v2.5.2.txt
# 20151117 Renamed from elk-install to elk-airgap-install. Changed logstash/etc conditional.

check_root() {
  if [[ $EUID != 0 ]]; then
    echo "This script must be run as root"
    exit 1
  fi
}

change_timezone() {
  if [[ ! $(cat /etc/timezone) == 'Etc/UTC' ]]; then
    echo Changing Timezone from $(cat /etc/timezone) to UTC.
    echo "Etc/UTC" | sudo tee /etc/timezone
  else
    echo Timezone already correct.
  fi
}

get_arch_type() {
  if [[ $(uname -m) == 'x86_64' ]]; then
    ARCH="amd64"
  else
    ARCH="i386"
  fi
  echo Your architecture is $ARCH.
}

checks() {
  check_root
  change_timezone
  get_arch_type
  if [[ $(pwd) =~ "ELK_Stack" ]]; then
    #echo Doing Stuff in $(pwd)
    echo
    main
  else
    for folder in ELK_Stack*; do
      if [[ -e $folder ]]; then
        cd $folder
        #echo Doing Stuff in $(pwd)
        echo
        main
      else
        echo "Directory $(pwd)/ELK_Stack*/ doesn't exist".
      fi
      break
    done
    cd ~
  fi
}

check_java() {
  if [ $(uname -m) == 'x86_64' ]; then
    java_file=$(ls -r java/*tar.gz | grep x64 --max-count=1 | cut -d/ -f2)
  else
    java_file=$(ls -r java/*tar.gz | grep -v x64 --max-count=1 | cut -d/ -f2)
  fi
  if [[ ! -d /usr/lib/jvm/ ]]; then
    echo Java not installed.
    install_java "$java_file"
  else
    java_current=$(java -version 2>&1 | grep version | cut -d\" -f2)
    #echo Java $java_current currently installed.
    java_toinstall="1."$(cut -d- -f2 <<< $java_file | sed 's/u/.0_/')
    if [[ $(cut -d. -f2 <<< $java_current) -lt $(cut -d. -f2 <<< $java_toinstall) ]] || \
      ([[ $(cut -d. -f2 <<< $java_current) -eq $(cut -d. -f2 <<< $java_toinstall) ]] && [[ $(cut -d_ -f2 <<< $java_current) -lt $(cut -d_ -f2 <<< $java_toinstall) ]]); then
      echo Updating Java from $java_current to $java_toinstall.
      install_java "$java_file"
    else
      echo Java $java_current is already current.
    fi
  fi
}

install_java() {
  java_file="$1"
  if [[ ! -d /usr/lib/jvm/ ]]; then
    sudo mkdir -p /usr/lib/jvm
  fi
  java_build=$(cut -d- -f1 <<< $java_file)"1."$(cut -d- -f2 <<< $java_file | sed 's/u/.0_/')
  sudo tar -C /usr/lib/jvm -zxf java/$java_file
  sudo update-alternatives --install "/usr/bin/java" "java" "/usr/lib/jvm/"$java_build"/bin/java" 1
  sudo update-alternatives --install "/usr/bin/javaws" "javaws" "/usr/lib/jvm/"$java_build"/bin/javaws" 1
  sudo chmod a+x /usr/bin/java
  sudo chmod a+x /usr/bin/javaws
  sudo chown -R root:root /usr/lib/jvm/$java_build
  sudo update-alternatives --config java
  sudo update-alternatives --config javaws
  #java -version
}

check_elasticsearch() {
  elasticsearch_file=$(ls -r elasticsearch/ | grep deb$ --max-count=1)
  if [[ ! -d /usr/share/elasticsearch/ ]]; then
    echo Elasticsearch not installed.
    install_elasticsearch "$elasticsearch_file"
  else
    elasticsearch_current=$(dpkg -s elasticsearch | grep Version | cut -d" " -f2)
    elasticsearch_toinstall=$(cut -d- -f2 <<< $elasticsearch_file | sed 's/.deb//')
    elasticsearch_current_major=$(cut -d. -f1 <<< $elasticsearch_current)
    elasticsearch_current_minor1=$(cut -d. -f2 <<< $elasticsearch_current)
    elasticsearch_current_minor2=$(cut -d. -f3 <<< $elasticsearch_current)
    elasticsearch_toinstall_major=$(cut -d. -f1 <<< $elasticsearch_toinstall)
    elasticsearch_toinstall_minor1=$(cut -d. -f2 <<< $elasticsearch_toinstall)
    elasticsearch_toinstall_minor2=$(cut -d. -f3 <<< $elasticsearch_toinstall)
    if [[ $elasticsearch_current_major -lt $elasticsearch_toinstall_major ]] || \
      ([[ $elasticsearch_current_major -eq $elasticsearch_toinstall_major ]] && [[ $elasticsearch_current_minor1 -lt $elasticsearch_toinstall_minor1 ]]) || \
      ([[ $elasticsearch_current_major -eq $elasticsearch_toinstall_major ]] && [[ $elasticsearch_current_minor1 -eq $elasticsearch_toinstall_minor1 ]] && [[ $elasticsearch_current_minor2 -lt $elasticsearch_toinstall_minor2 ]]); then
      echo Updating Elasticsearch from $elasticsearch_current to $elasticsearch_toinstall.
      install_elasticsearch "$elasticsearch_file"
    else
      echo Elasticsearch $elasticsearch_current is already current.
    fi
  fi
}

install_elasticsearch() {
  elasticsearch_file="$1"
  sudo dpkg -i elasticsearch/$elasticsearch_file
  sudo sed -i.bak 's/# cluster.name: my-application/cluster.name: skitheslicer/' /etc/elasticsearch/elasticsearch.yml
  sudo sed -i "s/# node.name: node-1/node.name: $(hostname)/" /etc/elasticsearch/elasticsearch.yml
  sudo sed -i 's/# network.host: 192.168.0.1/network.host: localhost/' /etc/elasticsearch/elasticsearch.yml
  #sudo sed -i 's/# bootstrap.mlockall: true/bootstrap.mlockall: true/' /etc/elasticsearch/elasticsearch.yml
  sudo update-rc.d elasticsearch defaults 95 10
  sudo service elasticsearch start
  #elasticsearch/ref/template-bro_http_20151113.json.sh
}

check_logstash() {
  logstash_file=$(ls -r logstash/ | grep deb$ --max-count=1)
  if [[ ! -d /opt/logstash/ ]]; then
    echo Logstash not installed.
    install_logstash "$logstash_file"
  else
    logstash_current=$(dpkg -s logstash | grep Version | rev | cut -d: -f1 | rev)
      # $(dpkg -s logstash | grep Version | rev | cut -d: -f1 | rev)
      # $(dpkg -s logstash | grep Version | cut -d" " -f2)
    logstash_toinstall=$(cut -d_ -f2 <<< $logstash_file)
    logstash_current_major=$(cut -d. -f1 <<< $logstash_current)
    logstash_current_minor1=$(cut -d. -f2 <<< $logstash_current)
    logstash_current_minor2=$(cut -d. -f3 <<< $logstash_current | cut -d- -f1)
    logstash_current_minor3=$(cut -d. -f3 <<< $logstash_current | cut -d- -f2)
    logstash_toinstall_major=$(cut -d. -f1 <<< $logstash_toinstall)
    logstash_toinstall_minor1=$(cut -d. -f2 <<< $logstash_toinstall)
    logstash_toinstall_minor2=$(cut -d. -f3 <<< $logstash_toinstall | cut -d- -f1)
    logstash_toinstall_minor3=$(cut -d. -f3 <<< $logstash_toinstall | cut -d- -f2)
    if [[ $logstash_current_major -lt $logstash_toinstall_major ]] || \
      ([[ $logstash_current_major -eq $logstash_toinstall_major ]] && [[ $logstash_current_minor1 -lt $logstash_toinstall_minor1 ]]) || \
      ([[ $logstash_current_major -eq $logstash_toinstall_major ]] && [[ $logstash_current_minor1 -eq $logstash_toinstall_minor1 ]] && [[ $logstash_current_minor2 -lt $logstash_toinstall_minor2 ]]) || \
      ([[ $logstash_current_major -eq $logstash_toinstall_major ]] && [[ $logstash_current_minor1 -eq $logstash_toinstall_minor1 ]] && [[ $logstash_current_minor2 -eq $logstash_toinstall_minor2 ]] && [[ $logstash_current_minor3 -lt $logstash_toinstall_minor3 ]]); then
      echo Updating Logstash from $logstash_current to $logstash_toinstall.
      install_logstash "$logstash_file"
    else
      echo Logstash $logstash_current is already current.
    fi
  fi
}

install_logstash() {
  logstash_file="$1"
  sudo dpkg -i logstash/$logstash_file
  #sudo /opt/logstash/bin/plugin install logstash-filter-translate
  #sudo /opt/logstash/bin/plugin install logstash-codec-gzip_lines
  #if ! find logstash/etc/ -maxdepth 0 -empty; then
  if [[ -d logstash/etc/ ]]; then
    sudo cp -n logstash/etc/*.conf /etc/logstash/conf.d/
  else
    #sudo -s 'cat > /etc/logstash/conf.d/10_input_generic.conf <<< EOL
    sudo bash -c 'cat << EOF > /etc/logstash/conf.d/10_input_generic_stdin.conf
input {
  stdin {
    type => "BRO_connlog"
  }
}
EOF'
    sudo bash -c 'cat << EOF > /etc/logstash/conf.d/20_filter_generic_empty.conf
filter {
}
EOF'
    sudo bash -c 'cat << EOF > /etc/logstash/conf.d/30_output_generic_es.conf
output {
  elasticsearch { hosts => localhost }
}
EOF'
  fi
  sudo chmod 644 /etc/logstash/conf.d/*.conf
  #logstash_test=$(/opt/logstash/bin/logstash -f /etc/logstash/conf.d/ --configtest | tail -n 1)
  if [[ ! $(/opt/logstash/bin/logstash -f /etc/logstash/conf.d/ --configtest | tail -n 1) == "Configuration OK" ]]; then
    echo Attempting to correct Logstash Configuration errors.
    #sudo sed -i 's/codec => "gzip_lines"/#codec => "gzip_lines"/' /etc/logstash/conf.d/10_input_file-bro_*.conf
    sudo sed -i '/translate {/,+18 s/^/# /' /etc/logstash/conf.d/20_filter_bro-*.conf
    #sudo sed -i '/translate {/,+8 s/^/# /' /etc/logstash/conf.d/20_filter_snort_*.conf
  else
    echo Logstash Configuration OK
  fi
  sudo update-rc.d logstash defaults
  sudo service logstash start
  #sudo sed -i 's/ ${LS_OPTS}//' /etc/init.d/logstash   # Correct Service Start Error
  #tail -f /var/log/logstash/logstash.log
}

configure_logstash-forwarder() {
    if [[ ! -d /etc/pki/tls/certs/ ]] || [[ ! -d /etc/pki/tls/certs ]]; then
      sudo mkdir -p /etc/pki/tls/certs
      sudo mkdir -p /etc/pki/tls/private
    fi
    #ip_eth0=$(ifconfig eth0 | grep -E 'addr:([0-9]{1,3}\.){3}([0-9]{1,3})' | cut -d: -f2 | cut -d" " -f1)  #Possibly required for SSL Key
    #sudo sed -i.bak "/\[ crl_ext \]/i subjectAltName=IP:$ip_eth0\n" /etc/ssl/openssl.cnf                   #Possibly required for SSL Key
    sudo openssl req -x509 -batch -nodes -days 90 -newkey rsa:2048 -keyout /etc/pki/tls/private/logstash-forwarder.key -out /etc/pki/tls/certs/logstash-forwarder.crt
    cp /etc/pki/tls/certs/logstash-forwarder.crt /tmp/
    #scp /tmp/logstash-forwarder.crt <Sec.Onion.Sensor.IP>:/tmp/
    #tail -f /var/log/logstash/logstash.log
}

check_kibana() {
  if [ $(uname -m) == 'x86_64' ]; then
    kibana_file=$(ls -r kibana/ | grep x64.*gz$ --max-count=1)
  else
    kibana_file=$(ls -r kibana/ | grep x86.*gz$ --max-count=1)
  fi
  if [[ ! -d /opt/kibana/ ]]; then
    echo Kibana not installed.
    install_kibana "$kibana_file"
  else
    kibana_current=$(ls -r /opt/ | grep kibana --max-count=1 | cut -d- -f2)
    kibana_toinstall=$(cut -d- -f2 <<< $kibana_file)
    kibana_current_major=$(cut -d. -f1 <<< $kibana_current)
    kibana_current_minor1=$(cut -d. -f2 <<< $kibana_current)
    kibana_current_minor2=$(cut -d. -f3 <<< $kibana_current)
    kibana_toinstall_major=$(cut -d. -f1 <<< $kibana_toinstall)
    kibana_toinstall_minor1=$(cut -d. -f2 <<< $kibana_toinstall)
    kibana_toinstall_minor2=$(cut -d. -f3 <<< $kibana_toinstall)
    if [[ $kibana_current_major -lt $kibana_toinstall_major ]] || \
      ([[ $kibana_current_major -eq $kibana_toinstall_major ]] && [[ $kibana_current_minor1 -lt $kibana_toinstall_minor1 ]]) || \
      ([[ $kibana_current_major -eq $kibana_toinstall_major ]] && [[ $kibana_current_minor1 -eq $kibana_toinstall_minor1 ]] && [[ $kibana_current_minor2 -lt $kibana_toinstall_minor2 ]]); then
      echo Updating Kibana from $kibana_current to $kibana_toinstall.
      install_kibana "$kibana_file"
    else
      echo Kibana $kibana_current is already current.
    fi
  fi
}

install_kibana() {
  kibana_file="$1"
  sudo tar -zxf kibana/$kibana_file -C /opt/
  sudo ln -s /opt/$(sed 's/.tar.gz//' <<< $kibana_file)/ /opt/kibana
  sudo sed -i.bak 's/host: "0.0.0.0"/host: "localhost"/' /opt/kibana/config/kibana.yml
  sudo cp kibana/etc/kibana4 /etc/init.d/
  sudo chmod +x /etc/init.d/kibana4
  sudo update-rc.d kibana4 defaults 96 9
  sudo service kibana4 start
}

check_nginx() {
  nginx_user="$1"
  nginx_file=$(ls -r nginx/ | grep nginx_.*all.deb$ --max-count=1)
  if [[ ! -d /etc/nginx/sites-available/ ]]; then
    echo NGINX proxy not installed.
    install_nginx "$nginx_user"
  else
    nginx_current=$(dpkg -s nginx | grep Version | cut -d" " -f2)
    nginx_toinstall=$(cut -d_ -f2 <<< $nginx_file)
    if [[ ! $nginx_current -eq $nginx_toinstall ]]; then
      echo Updating NGINX from $nginx_current to $nginx_toinstall.
      install_nginx "$nginx_user"
    else
      echo NGINX $nginx_current is already current.
    fi
  fi   
}

install_nginx() {
  nginx_user="$1"
  sudo dpkg -i nginx/*_all.deb nginx/*_$ARCH.deb
  echo Creating HTPASSWD user $nginx_user
  if [[ ! -f /etc/nginx/htpasswd.users ]]; then
    sudo htpasswd -c /etc/nginx/htpasswd.users $nginx_user
  else
    sudo htpasswd /etc/nginx/htpasswd.users $nginx_user
  fi
  sudo mv /etc/nginx/sites-available/default ~/default.bak
  if [[ -f nginx/etc/default ]]; then
    sudo cp nginx/etc/default /etc/nginx/sites-available/default
  else
    sudo bash -c 'cat << EOF > /etc/nginx/sites-available/default
server {
  listen    *:80;
  
  server_name   kibana;

  return    301 https://$host/$request_uri;
}

server {
  listen    *:443;
  
  server_name   kibana;
  access_log    /var/log/nginx/kibana.access.log;
  
  ssl                   on;
  ssl_certificate       /etc/nginx/ssl/nginx.crt;
  ssl_certificate_key   /etc/nginx/ssl/nginx.key;
  
  location / {
    auth_basic              "Restricted Access";
    auth_basic_user_file    /etc/nginx/htpasswd.users;
    
    proxy_pass  http://localhost:5601/;
  }
}
EOF'
  fi
  if [[ ! -f /etc/nginx/ssl/nginx.key ]] || [[ ! -f /etc/nginx/ssl/nginx.crt ]]; then
    sudo mkdir /etc/nginx/ssl/
    sudo openssl req -x509 -batch -nodes -days 90 -newkey rsa:2048 -keyout /etc/nginx/ssl/nginx.key -out /etc/nginx/ssl/nginx.crt
  fi
  sudo service nginx stop
  sudo service nginx start
}

configure_ufw() {
  if [[ $(sudo ufw status | cut -d" " -f2) == "inactive" ]]; then
    echo Configuring Uncomplicated FireWall \(UFW\)
    sudo ufw allow 22/tcp
    sudo ufw allow 443/tcp
    sudo ufw enable
  else
    echo Uncomplicated FireWall \(UFW\) already active. Not re-configuring for TCP ports 22 and 443.
  fi
}

main() {
  check_java && echo
  check_elasticsearch && echo
  check_logstash && echo
  #configure_logstash-forwarder && echo
  check_kibana && echo
  check_nginx "kibanaadmin" && echo
  configure_ufw && echo
  #echo Open web browser to \"http://localhost:5601/\"
  #echo Open web browser to \"http://$(ifconfig eth0 | grep -E 'addr:([0-9]{1,3}\.){3}([0-9]{1,3})' | cut -d: -f2 | cut -d" " -f1):5601/\"
  echo Open web browser to
  echo -e "\t"\"https://$(ifconfig eth0 | grep -E 'addr:([0-9]{1,3}\.){3}([0-9]{1,3})' | cut -d: -f2 | cut -d" " -f1)/\"
  echo Create additional users with
  echo -e "\t"\"sudo htpasswd /etc/nginx/htpasswd.users \<new user\>\"
  echo If you wish to enable HTTP access \(with redirect to HTTPS\), add TCP port 80 to UFW using
  echo -e "\t"\"sudo ufw allow 80/tcp \&\& sudo ufw reload\"
  echo You may need to reboot with
  echo -e "\t"\"sudo shutdown -r now\"
}

checks | tee elk-airgap-install_$(date +%Y%m%d-%H%M).log
