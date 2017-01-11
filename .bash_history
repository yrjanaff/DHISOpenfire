ls
cd ..
ls
cd yrjanaff/
ls
cd ..
cd simjes/
ls
cd ../yrjanaff/
ls
cd ..
ls
cd ..
ls
cd home/
ls
cd yrjanaff/
ls
cd Openfire-DHISAuthentication-master/
ls
cd .
cd ..
ant -version
rm -r Openfire-DHISAuthentication-master
ls
cd openfire/target/
ls
cd openfire/
ls
cd conf/
ls
nano openfire.xml 
cd ../../..
ls
cd target/
ls
cd openfire/
cd bin/
ls
sh openfire.sh 
cd ..
ls
cd simjes/
ls
cd ..
ls
cd opt/
ls
cd ..
cd dev/
ls
cd ..
ls
cd bin/
ls
cd ..
cd home/simjes/
ls
cat dhis2 
cat install.sh 
apropos dhis2
man dhis2-integrity
cd ../..
ls
cd usr/bin/
ls
./dhis2-integrity
dhis2-integrity
dhis2-integrity dhis2
dhis2-integrity dhis
psql dhis
cd ..
ls
cd etc/
ls
cd postgresql
ls
cd 9.5/
ls
cd main/
ls
cat pg_hba.conf 
cd ../../..
cd ..
psql dhis
ant
sudo apt-get install ant 
ls
cd openfire/target/openfire/bin/
sh openfire.sh 
ls
cd openfire/
ls
top
ps aux
ps aux | openfire
ps aux | grep openfire
ls
cd target/
ls
open
cd openfire/
ls
cd bin/
ls
./openfire
./openfire.sh 
./openfire.sh &
ls
cd openfire/
ls
cd build/
ls
cd ..
cd target/
ls
cd openfire/
ls
cd bin/
ls
sh openfire.sh 
cd openfire/build/
ls
cd ..
ls
cd target
ls
cd openfire/
ls
cd bin/
sh openfire.sh 
cd openfire/target/openfire/bin/
sh openfire.sh 
man openssl
openssl genrsa -des3 -passout pass:x -out server.pass.key 2048
openssl rsa -passin pass:x -in server.pass.key -out server.key
ls
rm server.pass.key
openssl req -new -key server.key -out server.csr
openssl x509 -req -sha256 -days 365 -in server.csr -signkey server.key -out server.crt
sh openfire.sh 
ls
cd ..
ls
cd ..
ls
cd ..
ls
cd target/openfire/
ls
cd conf/
ls
cd ..
cd lib/
ls
cd ..
ls
cd logs/
ls
cd ..
cd monitoring/
ls
cd search/
ls
cd ../..
ls
cd resources/
ls
cd security/
ls
nano keystore 
cd ..
ls
cd bin/
ls
keytool -import -keystore keystore -alias 80.85.87.15 -file server.csr 
sh openfire.sh 
man gzip
man bzip2
cd 
ls
tar xzvf apache-ant-1.9.7-bin.tar.gz 
ls
cd apache-ant-1.9.7/
ls
nano README 
nano INSTALL 
$JAVA_HOME
cd ..
openssl genrsa -des3 -out server.key 2048
openssl rsa -in server.key -out server.key.insecure
openssl req -new -key server.key -out server.csr
openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
sudo cp server.crt /etc/ssl/certs
cp server.crt /etc/ssl/certs
man keytool
ls
keytool -import -keystore keystore -alias 80.85.87.15 -file server.csr 
keytool -import -keystore keystore -alias 80.85.87.15 -file server.crt 
keytool -delete -keystore keystore -alias rsa
keytool -delete -keystore keystore -alias dsa
cd openfire/target/openfire/bin/
sh openfire.sh 
pidof openfire
ps ax
ps aux
wxit
exit
ls
sh openfire.sh 
logout
cd openfire/target/openfire/bin/
sh openfire.sh 
ls
logout
ls
cd ..
ls
cd simjes/
ls
cd ..
cd yrjanaff/
ls
cd openfire/target/openfire/bin/
sh openfire.sh 
ls
man ant
sudo apt-get install ant
man nat
man ant
cd ..
ls
cd simjes/
ls
cd /etc/ssl/certs/
ls
cd
ls
cd openfire/target/openfire/bin/
sh openfire.sh 
cd /etc/ssl/certs/
ls | grep .csr
ls
ls | grep .crt
cd /etc/ssl/private/
ls
keytool -list
sudo keytool -list
cd
cd ..
cd simjes/
ls
ls -a
ls
cd open
cd openfire/
ls
cd resources/
ls
$OPENFIRE_HOME
keytool -genkey -keystore keystore -alias yj-dev.dhis2.org
ls
keytool -import -keystore keystore -alias yj-dev.dhis2.org -file /etc/ssl/certs/ca-certificates.crt 
keytool -list
man keystore
man keytool
cd ..
ls
cd ..
ls
cd ope
cd openfire/
ls
cd src/java/org/jivesoftware/openfire/auth/
ls
nano DHISAuthProvider.java 
cd 
cd openfire/
ls
cd build/
ls
cd ..
l
ls
cd resources/
ls
cd ..
cd build/
ant
$JAVA_HOME
man java
echo $JAVA_HOME
cd /usr/lib/jvm/
ls
nano /etc/environment 
sudo nano /etc/environment 
cd  /usr/lib/jvm/java-8-oracle/
ls
cd bin/
ls
cd ..
source /etc/environment 
echo $JAVA_HOME
ls
nano README.html 
cd
cd openfire/
cd build/
ant
ls
cd openfire/target/openfire/bin/
sh openfire.sh 
cd openfire/target/openfire/bin/
sh openfire.sh 
ls
cd openfire/
ls
cd target/
ls
cd openfire/
ls
cd bin/
ls
sh openfire.sh 
sudo sh openfire.sh
apt-get install ant
man apt-get
sudo apt-get install ant
man ant
cd ../../..
ls
cd build/
ls
ant
ant -Xlint:deprecation
ls
cd ..
l
ls
cd src/
ls
cd java
ls
cd org/
ls
cd jivesoftware/
ls
cd openfire/
ls
cd auth/
ls
nano Base64.java 
nano AuthFactory.java 
nano AuthorizationManager.java 
nano DefaultAuthProvider.java 
nano DHISAuthProvider.java 
cp Base64.java Base64Test.java
ls
nano Base64Test.java 
rm Base64.java 
ls
cd
cd openfire/build/
ant
cd ..
cd src/java/org/jivesoftware/openfire/auth
ls
nano Base64Test.java 
cd 
cd openfire/build/
ant
cd ../src/java/org/jivesoftware/openfire/auth
nano Base64Test.java 
cd
cd openfire/build/
ant
cd ../src/java/org/jivesoftware/openfire/auth
nano Base64Test.java 
cd 
cd openfire/build/
ant
cd ../src/java/org/jivesoftware/util
ls
cp Base64.java ~/Base64util.java
cd
ls
cd openfire/src/java/org/jivesoftware/util
rm Base64.java 
cd
cd openfire/build/
ant
nano ../work/jspc/java/org/jivesoftware/openfire/admin/login_jsp.java
cd openfire/src/java/org/jivesoftware/util
cd ../src/java/org/jivesoftware/util
ls
cd ..
cd openfire/auth/
ls
cp Base64Test.java ~/Base64Test.java
rm Base64Test.java 
ls
cd
cd openfire/
ls
nano README.html 
cd build/
ls
echo $JAVA_HOME
cd ../work/jspc/java/org/jivesoftware/openfire/admin/login_jsp.java
cd ../work/jspc/java/org/jivesoftware/openfire/admin/
nano login_jsp.java 
logout
cd openfire/build/
ant
droplets
man droplets
droplet
man droplet
sudo apt-get update
java -version
wget -O openfire.deb http://www.igniterealtime.org/downloads/download-landing.jsp?file=openfire/openfire_4.1.1_all.deb
ls
cd ..
cd
wget -O openfire.deb http://www.igniterealtime.org/downloads/download-landing.jsp?file=openfire/openfire_4.1.1_all.deb
sudo dpkg --install openfire.deb
wget -O openfire.deb http://www.igniterealtime.org/downloadServlet?filename=openfire/openfire_4.1.1_all.deb
ls
sudo dpkg --install openfire.deb
cd ..
ls
cd simjes/
ls
cd dhis2
cd
wget -O openfire.tar.gz http://www.igniterealtime.org/downloadServlet?filename=openfire/openfire_4_1_1.tar.gz
ls
tar -xvzf openfire.tar.gz 
ls
cd openfire/
ls
cat README.html 
ls
cd bin/
ls
cd ../build/
ls
cd ..
ls
rm Base64util.java 
rm Base64Test.java 
rm server.crt 
rm server.csr 
rm server.key
rm server.key.insecure 
ls
rm apache-ant-1.9.7-bin.tar.gz 
rm keystore 
rm openfire.deb 
rm apache-ant-1.9.7/
sudo /etc/init.d/openfire stop
ls
rm -rf apache-ant-1.9.7/
ls
rm -rf openfire
ls
tar -xvzf openfire.tar.gz 
ls
cd openfire/
ls
cd bin/
ls
sh openfire
openfire start
sh openfire start
cd ..
ls
cd conf/
ls
nano openfire.xml 
cd ..
cd bin/
sh openfire stop
sh openfire start
sh openfire stop
dpkg --list
dpkg --list | grep openfire
sudo apt-get --purge remove openfire
cd 
ls
rm -rf openfire
ls
tar -xvzf openfire.tar.gz 
cd openfire/
cd bin/
sh openfire start
psql dhis
ls
cd ..
ls
cd conf/
ls
cat openfire.xml 
cd ..
ls
cd ..
ls
rm -rf openfire
ls
man git
sudo apt-get install git
man git
git clone https://github.com/igniterealtime/Openfire.git
ls
Openfire/
cd Openfire/
ls
cd build/
ls
ant
ls
cd ..
ls
cd target/
ls
cd openfire/
ls
cd bin/
ls
sh openfire.sh 
cd ..
ls
make
ls
cd build/
ant
cd ..
cd target/openfire/bin/
ls
sh openfire.sh 
cd
cd Openfire/
git checkout -b 4.1
ls
cd ..
rm -rf Openfire/
rm openfire.tar.gz 
wget -O openfire.tar.gz http://www.igniterealtime.org/downloadServlet?filename=openfire/openfire_src_4_1_1.tar.gz
ls
tar -xvzf openfire.tar.gz 
ls
cd openfire_src/
ls
cd build/
ls
ant
cd ..
ls
cd target/
ls
cd openfire/
ls
cd bin/
ls
sh openfire.sh 
