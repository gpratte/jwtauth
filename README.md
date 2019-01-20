# OVERVIEW

Create a Spring Boot server that 
1. Has an admin user
2. Allows new non-admin users to sign up. This endpoint does not require a token
3. Allows users to login. This endpoint does not require a token but returns a token
4. Allows a user to change his/her password
5. Allows the admin user to change a user's password
6. Exercise the endpoints via curl and/or Postman.

# SETUP

Create a Spring Boot project using Spring Initialzr

https://start.spring.io/

Choose Gradle for the build tool.

Chose the following dependencies:
* Web
* JPA
* H2
* Lombok

Change the Artifact to "jwtauth".

Generate the project, unzip it and load it up in your IDE. If you are using IntelliJ then remember to install the Lombok plugin and change the settings to enable annotations. 

Run the test to make sure everything is working.

# GIT
As per usual I will build up this application on git branches. 

I created a github repository at https://github.com/gpratte/jwtauth.git

I pushed the code from the SETUP section above to the master branch and then created a 01-setup branch.

