My Project for Secure Software Design & Development course Powered by Team CODE-OF-DUTY
-----------------------------------------------------------------------------------------------------------------------------------------------------------------
follows OWASP TOP 10 for Secure Web Application

-----------------------------------------------------------------------------------------------------------------------------------------------------------------

Introduction
The Library Management System (LMS) is a web-based application designed to simplify and enhance the management of library resources and user interactions. This system caters to both admin and students which offers a seamless platform to handle tasks such as adding books, issuing and returning books, and searching the library catalog. It is built with modern web technologies, the LMS prioritizes usability, efficiency, and security, ensuring a reliable experience for all users. 

-------------------------------------------------------------------------------------------------------------------------------------------------------------------
Libraries and Dependencies
In addition to Flask, we have added varies libraries of python in our LMS to enhance its functionality and security:
•	Werkzeug: A WSGI utility library that provides tools for password hashing and secure cookie management. Werkzeug is used to securely hash user passwords before storage and verify them during login.
•	Flask-WTF: An extension for Flask that integrates WTForms, enabling form validation and CSRF (Cross-Site Request Forgery) protection. This library ensures that all form submissions are secure and legitimate.
•	Jinja2: A templating engine bundled with Flask, used to render dynamic HTML pages. Jinja2 supports secure output encoding to prevent XSS (Cross-Site Scripting) attacks by escaping user inputs.
