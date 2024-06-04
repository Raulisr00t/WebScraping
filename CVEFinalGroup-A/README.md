# Group A: Project Name: CVE Report Generator

## Description of Project
The project is related to CVE generator. The main purpose of this project allows you to fetch and compile details and information about a summary, Base Score, Vector, Reference and Exploit Database to give details about a given CVE ID.

## Dependencies

- Python 3.x
- Requests library
- Urllib3 library
- Selenium 
- Click
- Warnings , signal
- Flask Library
- BeautifulSoup library
- docx library (for creating Word output reports)
- reportlab library (for creating PDF output reports)

 ## Standard Library Modules
 - os
 - re
 - time
 - signal
 - sys
 - threading
 - webbrowser
 - warnings

If you want to utilize this library, you can install the required libraries with using pip command:

```
pip install requests urllib3 click beautifulsoup4 python-docx reportlab selenium Flask

```

## Instructions for running the project

1. For running the project, firstly clone repository, download repository to your local machine and open the folder .

2. To be sure you are already install the dependencies which are so essential libraries for project

3. First Run the `flask_for_web.py`  to make data available over the web.

4. After Run the `main.py` script  with three links by executing the following command in terminal because it is console application
   so write one of these below commands
   ```
   python3 main.py https://vulmon.com
   python3 main.py https://cve.mitre.org
   python3 main.py https://nvd.nist.gov
   ```
   Because you can see the data from this three link

5. when the user enter the CVE-ID tp input after you can install the output format (word, or pdf)

6. the downloaded file will be in your folder which the code also is located in that folder

7. you can see the information also in console, web and word,pdf format

8. So, Our project have 3 forms, you can see data in three place
 - Console
 - PDF, Word, Md
 - Web

9. When you start run the project be sure all `.py` files are available and all libraries are installed.

10. In templates folder there are html files which are utilized for web

11. In assets folder there are images which show the process of project

## List of group members and their Responsibilities

- Maleyka - author of the getting output report as pdf, md, word at the code
- Raul - author of the infrastructure and getting data in console at the code
- Ilham - author of the getting data in web(selenium part) at the code
- Fuad - author of the click option(-d , -o part) at the code (part of console user friendly)

## Any additional  Instructions
you can run the code from the main part , and it is console application, you should run this code from cmd
Additionaly, our python version is python 3.11.8
   ```

   python3 main.py https://vulmon.com
   python3 main.py https://cve.mitre.org
   python3 main.py https://nvd.nist.gov
   
   ```

   ## the procedure for looking the working of project
   - For GUI, you should run `flask_for_web.py`
   - firstly you should choose one of the command at the above to run at terminal
   - after you are able to choose, graphical user interface or console
   - then if you choose console, you can exactly get report as output and etc.
