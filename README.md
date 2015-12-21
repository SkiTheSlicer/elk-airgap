# elk-airgap
# Goal:
The goal of this project was to create a simple, automated means to stand up an ELK (Elasticsearch, Logstash, Kibana) stack on an Ubuntu 14.04 LTS system. 
# Components:
It is comprised of 2 parts: the downloader (python) which requires an internet connection, and the installer (bash) which does not.

The downloader scrapes URLs to determine the most up-to-date packages, and then downloads them. It requires BeautifulSoup (http://www.crummy.com/software/BeautifulSoup/bs4/download/) and Requests (https://github.com/kennethreitz/requests/releases). I chose python to ensure that a user can use Windows or Linux as their online machine. 

The installer is written in bash. It iterates through the expected output of the downloader, and manipulates configurations as necessary.
