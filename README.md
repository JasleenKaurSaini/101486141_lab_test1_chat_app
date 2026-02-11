# 101486141_lab_test1_chat_app

Features
- User Signup
- User Login / Logout
- JWT Authentication
- Predefined Chat Rooms
- Room-based Messaging
- Private Messaging
- Typing Indicator
- Online Users List
- Messages Stored in MongoDB

How the App Works

1. Signup 
Users create an account with username, first name, last name, and password.
Passwords are hashed before storing.

2. Login
Users log in using username and password.
A JWT token is generated after successful login.

3. Chat Rooms
Users can join predefined rooms like:
devops, cloud computing, covid19, sports, nodeJS,and news
Users can join or leave rooms anytime.

4. Room Chat
Send messages inside a room
Messages appear in real-time
Chat history loads when joining

5. Private Chat
Send direct messages to other users
Real-time delivery

6. Typing Indicator
Shows when a user is typing (private chat).

7. Database
MongoDB stores:
Users
Group Messages
Private Messages