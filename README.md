# password-strength-checker
First attempt I created this project and used AES encryption but forgot the ultimate idea of storing any kind of personal information especially passwords should always be a one way road.
  Therefore, I changed the code and installed 'bcrypt' and created a Hash instead.
  This way I can still store my passwords and see if they verify against the hash saved in the json repository without compromising myself if someone was to get their hands on my keys.

This project also showcases the ability to save password, verify password, and check strength of passwords...
  Save Passwords - that is the main point of the json file and makes this a personal password manager app.
  Verify Password - this is a quick way to type in your credentials and to check it against the Hash to see if you're typing your password incorrectly.
  Check Password Strength - this is a security protocol to make sure that the appropriate password parameters are met everytime an account is made as the longer/more complex a password is the harder it is to brute force into.
