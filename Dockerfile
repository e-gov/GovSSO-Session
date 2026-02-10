FROM eclipse-temurin:17-jre
WORKDIR /app
COPY target/govsso-session.jar app.jar
CMD ["java","-jar","app.jar"]
