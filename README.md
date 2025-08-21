Project Scope & Roles – Phase 1
Project Scope
Our project is focused on building a log analyzer system that can:
•	Accept and parse CSV, Syslog, and EVTX log files.
•	Apply 6 detection rules (e.g., brute force, malicious keyword detection, failed login attempts, etc.).
•	Provide results in JSON format for technical users and plain text (human-readable format) for non-technical users.
•	Store and manage structured logs in MongoDB.
•	Present findings on a frontend dashboard for easy viewing and interaction.
This is Phase 1 (1.5 months):
•	Build Frontend (React), Backend (PHP), and Database (MongoDB).
•	Implement Analyzer (Python) for detection.
•	Integrate all three log types (CSV, Syslog, EVTX).
________________________________________
Guidelines
1.	If you have new ideas, improvements, or conclusions, share them with the group for discussion.
2.	Each member should regularly update progress and push code to Git.
3.	Collaboration is important — help other members if they are stuck.
4.	Focus on Phase 1 goals first (core functionality). Enhancements can be added later.
________________________________________
Assigned Roles
1. Shadab Mushtaq – Frontend (React)
•	Develop user interface and dashboard.
•	Display JSON/plain text results clearly.
•	Connect to backend APIs.
•	Assist with MongoDB integration.
2. Arbab Ahmed Khan – Backend (PHP)
•	Build backend APIs to accept uploaded logs.
•	Connect backend with MongoDB.
•	Send logs to Python analyzer and return results.
•	Ensure smooth integration between frontend and analyzer.
3. Multazim – Database (MongoDB + Helper)
•	Design and manage database schema for logs and results.
•	Help Shadab with MongoDB connection.
•	Assist Hamza in analyzer code testing.
•	Act as a support developer for both frontend and analyzer.
4. Hamza Alam – Analyzer (Python)
•	Develop the Python analyzer for detection rules.
•	Ensure analyzer can parse CSV, Syslog, EVTX files.
•	Provide results in JSON + plain text with explanations.
•	Work closely with Multazim for testing and improvements.
________________________________________

Terminologies
•	Frontend (React): The part of the project the user interacts with — a website/dashboard. React is a JavaScript library for building fast and interactive user interfaces.
•	Backend (PHP): The "middle layer" that connects the frontend with the database and analyzer. It processes user requests, runs server logic, and sends/receives data.
•	Database (MongoDB): A system to store logs and results. MongoDB is a NoSQL database that stores data in JSON-like format (documents).
•	Analyzer (Python): A Python script that processes uploaded log files, applies detection rules (e.g., brute force), and generates results.
•	Log Files:
o	CSV: Comma-Separated Values file, simple text table format.
o	Syslog: Standard logging format used in Linux/servers.
o	EVTX: Windows Event Log format (XML-based).
•	Detection Rules: Predefined conditions to find suspicious activity (e.g., multiple failed logins = brute force attack).
•	JSON (JavaScript Object Notation): A structured data format used for technical users.
•	Plain Text Explanation: A simplified, human-readable explanation of the detected issue, meant for non-technical users.
•	Git: A tool for version control, used to store and collaborate on code.
•	Cohort NIC: The incubator program (our presentation platform).
________________________________________
Presentation
•	Project scope and Phase 1 goals
•	Will be presented in Cohort NIC.
•	The focus is on clear roles, responsibilities, and early integration.

