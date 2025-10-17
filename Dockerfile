    # Stage 1: Build the application
    FROM maven:3.8.5-openjdk-17 AS build

    WORKDIR /app
    COPY pom.xml .
    COPY src ./src
    RUN mvn clean package -DskipTests

    FROM openjdk:17-jdk-slim
    WORKDIR /app
    COPY --from=build /app/target/parker-auth-service-1.0-SNAPSHOT.jar /app/parker-auth-service.jar
    EXPOSE 8080
    ENV SPRING_PROFILES_ACTIVE=renderer
    ENTRYPOINT ["java", "-jar", "/app/service-parker.jar"]