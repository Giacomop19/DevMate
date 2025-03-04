# Build stage
FROM maven:3.6.3-jdk-8-slim AS build
COPY src /home/app/src
COPY pom.xml /home/app
RUN mvn -f /home/app/pom.xml clean package

# Package stage
FROM openjdk:17-jdk-slim
COPY target/devmate-1.0.jar devmate-1.0.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "devmate-1.0.jar"]
