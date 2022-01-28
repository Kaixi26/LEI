FROM ubuntu:21.04

WORKDIR /DSS-Server 

COPY ./target/DSS-Server-1.0-SNAPSHOT.jar .

RUN apt-get update
RUN apt-get install openjdk-15-jre-headless -y
EXPOSE 8080
CMD java -jar ./DSS-Server-1.0-SNAPSHOT.jar
