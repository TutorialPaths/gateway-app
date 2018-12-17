# TutorialPaths - gateway-app
The gateway-app is a python application located at [gateway.tutorialpaths.com](https://gateway.tutorialpaths.com). It receives post requests from the JavaScript front-end, and interacts with mail clients and the MySQL server to do certain things such as fetching tutorials, or authenticating users.

Using the gateway is the **preferred method** for interacting with the database and mail clients, rather than doing it on the page load. This is so that the page loads as fast as possible, and displays the loading bar in the nav until the post requests to the gateway are completed. Although it takes slightly longer, it is much preferred.
