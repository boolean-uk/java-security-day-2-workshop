# Java API Exercise

## Learning Objectives
- Use a Bearer Token/JWT to secure an API

## Instructions

1. Fork this repository
2. Clone your fork to your machine
3. Open the project in IntelliJ

## Some Theory

A common way of securing a web application is to use a Bearer token that the user obtains by logging in. Anytime authentication is then required the user submits this token as part of the Http Request, it is checked and if valid then the user is allowed to complete their process, if it isn't then an Unauthorised response is returned. The core of the process works like this:

1. A user enters their login details into a form
2. The client sends the credentials to a server in the body of a request to an API
3. The server checks the credentials are correct
4. The server creates an access token for the user and sends it back to the client
5. The client saves the token and sends it in a request header when the user tries to access protected areas of the app

We can visualise the process like this:

![A user logs in to an app](./assets/Auth_Flow.png)

## What's a Token?

> Think of a token like an employee ID badge; you can't enter the secure areas of your employer's building without one! The company verify that you are who you say you are when they hire you, and then they give you an ID badge so you can access employee-only rooms in the building.

In this analogy, verifying you are who you say you are symbolises entering a username and password into a login form. The ID badge granted to you is the token; only you have this token, and you show it to the server every time you want to make a request to a protected resource.

One of the most common types of tokens are called JSON Web Token's, a.k.a JWT's.

A JWT is comprised of 2 separate pieces of JSON and a signature hash, each of them encoded and placed into a string separated by dots.

The final token will have a structure that looks like xxxxx.yyyyy.zzzzz

The three pieces are:

1. Header (xxxxx)
2. Payload (yyyyy)
3. Signature (zzzzz)

## Building Our Secure App

We'll start off with a full version of the Books endpoints we used yesterday (but this time including the `POST`, `PUT` and `DELETE` ones too). The code for this is already included in the aprropriate folders in the project.

