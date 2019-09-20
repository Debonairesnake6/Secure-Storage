# Secure-Storage
My school capstone project to design a system based off online forums and recommendations, and then penetration test it to see how secure it is.
  
The program is a simple file storage system which allows a user to upload and download files as well as send echo messages to the server. Each client has their own login information, which is sent to the server and verified in the MySQL database, along with nay files and permissions that are needed to perform the desired action.
  
  ![alt text](https://puu.sh/Ejqy4/c758b5718e.png)
  
The 4 attacks that were tested on this system were;
  * Man-in-the-middle
  * SQL injection
  * Path traversal
  * Uploading malware
    
 Each of these attacks were thoroughly discussed in the attached paper, along with how successful they were and what mitigations can be put in place to prevent these types of attacks. This project will still be worked on after my schooling has finished, to add new features and test their security in order to broaden my cyber security knowledge.
