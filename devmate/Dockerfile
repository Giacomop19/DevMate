FROM openjdk:17-jdk-slim
WORKDIR /src
COPY target/devmate-1.0.jar devmate-1.0.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "devmate-1.0.jar"]
