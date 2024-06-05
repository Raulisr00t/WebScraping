import os
import re
import requests
import urllib3
import click
import time
import signal
import sys
import threading
from bs4 import BeautifulSoup
from selenium import webdriver
import webbrowser
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.common.by import By
from flask import Flask, render_template, request, url_for, redirect, make_response, flash, session
from  urllib.parse import urljoin
import warnings
import report
import flask_for_web

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                  'Chrome/58.0.3029.110 Safari/537.36'
}
warnings.filterwarnings("ignore", category=DeprecationWarning)
urllib3.disable_warnings()
def signal_handler(sig, frame):
    global running
    running = False
    print('CTRL^C keyboard detected by server, connection closed')

signal.signal(signal.SIGINT, signal_handler)

@click.command()
@click.argument('url', default='https://exploit-db.com')
@click.option('-d', '--details', help='If you want to see detailed information about your cve id, please enter this argument', required=False)
@click.option('-o', '--output-format', help='Which format do you want for output', default=None, required=False)
def search_cve(url, details, output_format):
    title = """                ##########################################################
                #                                                        #
                #             GROUP(A)--JAMES FINAL PROJECT              #
                #                                                        #
                #                      Raulisr00t!                       #                 
                ##########################################################   """'\n'
    print(title)

    urls = ['https://nvd.nist.gov','https://cve.mitre.org','https://vulmon.com']
    if url not in urls:
        print('Invalid URL detected, please check --help and see valid options')
        print('your valid urls:[https://vulmon.com | https://nvd.nist.gov | https://cve.mitre.org]>>>Please enter the one of this enter the program like as arg')
        return False
    
    while True:
        print('Please write a CVE id for searching...\n')
        cve_input = input('CVE-id:')
        try:
            cve_num = int(cve_input.replace('-', ''))
            cve = f"{cve_input[:4]}-{cve_input[4:]}"
        except ValueError:
            print('Enter a valid CVE-ID (if you wanna bypass it, enter an integer)')
            break
        
        print('You can choose an option how do you see the result\n')
        print('A) Try it with Graphic user interface as WEB\n')
        print('B) Console (mainly if you choose terminal, you are a legend ahahah))')
        choose = input('Your Choose:').upper() 

        if choose == 'B':
            #default_query = f'https://exploit-db.com/search?cve={cve}'
            delay = 5
            user_agent = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0'}

            if url:
                if url == urls[0]:
                    try:
                        def html_of_site(url):
                            cve_modified = cve.replace("--","-")
                            path = f'vuln/detail/cve-{cve_modified}'
                            query1 = urljoin(urls[0], path)
                            response = requests.get(query1,headers=user_agent,verify=False)
                            if response.status_code != 200:
                                print(f'Your request is not OK:{response.status_code}')
                                pass

                            return response.content.decode()
                        html = html_of_site(url)
                        soup = BeautifulSoup(html, 'html.parser')
                        description_tag = soup.find('p', attrs={'data-testid': 'vuln-description'})
                        cvss3_panel_tag = soup.find('span', {'class': 'severityDetail'})
                        references_1 = soup.find("table", class_="table table-striped table-condensed table-bordered detail-table")
                 
                        if description_tag:
                            description_text = description_tag.get_text(strip=True)
                            print(description_text)
    
                        if cvss3_panel_tag:
                            score_tag = cvss3_panel_tag.find('a', {'class': 'label label-danger'})
                        
                        if score_tag:
                            score_text = score_tag.text.strip()
                            print("CVSS Score:", score_text)

                        if references_1:
                            links = references_1.find_all('a')
                            for link in links:
                                print(link['href'])                       

                    except UnboundLocalError:
                        print('Please enter cve id correctly...')
                        break

                elif url == urls[1]:
                    def html_of_site2(url):
                        cve_modified = cve.replace("--", "-")
                        path = f'cgi-bin/cvename.cgi?name={cve_modified}'
                        query2 = urljoin(urls[1], path)

                        response = requests.get(query2,headers=user_agent,verify=False)
                        if response.status_code != 200:
                            print(f'Your request is not OK:{response.status_code}')
                            return False
                        return response.content.decode()
                    
                    html = html_of_site2(url)
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore")
                        soup = BeautifulSoup(html,'html.parser')
                        description_tag2 = soup.find('th', text='Description')
                        try:
                            references = soup.find('td', class_='note').find_next('ul').find_all('a')
                            description = description_tag2.find_next('td').get_text(strip=True)
                            print(description)
                            for reference in references:
                                print(reference['href'])
                        except AttributeError:
                            print('Please enter cve id correctly...')
                            break

                elif url == urls[2]:
                    try:
                        def html_of_site3(url):
                            cve_modified = cve.replace("--", "-")
                            path = f'vulnerabilitydetails?qid=CVE-{cve_modified}'
                            query3 = urljoin(urls[2], path)

                            response = requests.get(query3,headers=user_agent,verify=False)
                            if response.status_code != 200:
                                print(f'Your request is not OK:{response.status_code}')
                                return None
                            return response.content.decode()
                        html = html_of_site3(url)
                        soup = BeautifulSoup(html,'html.parser')
                        description_tag = soup.find("p",{'class': 'jsdescription1'})
                        cvss = soup.find("div",{'class': 'value'})
                        references2_div = soup.find('div', class_='ui list ex5')
                        if description_tag:
                            description = description_tag.get_text(strip=True)
                            print(description)

                        if cvss:
                            score = cvss.get_text(strip=True)
                            if score == 'NA':
                                print('Please enter cve-id correctly...')
                                break
                            else:
                                print('CVSS Score is:',score)

                        if references2_div:
                            reference2 = references2_div.find_all('a')
                            for reference_2 in reference2:
                                print(reference_2['href'])
                    except Exception as e:
                        print('Please enter cve-id correctly...')
                        break
                else:
                    print('Invalid URL please enter a valid url...')
                    break
                cve_regex=r'^\d{4}-\d{4,}$'
                if re.match(cve_regex, cve_input):
            #Show the format what format do you want to download
                    print("These are references , summary, description , score at the above")
                    print("#################################################################")
                    print("However, you can download report as at the below")
                    print("#####################################################")
                    print("You can also Download the report in three format type:")
                    print("######################################################")
                    print("What report type do you want the save file?")
                    print("1: Word")
                    print("2: Markdown")
                    print("3: PDF")

                    try:
                    # Enter the suitable choice for user
                        report_choice = int(input("Please enter a suitable choice for you: "))

                    # Generate the report based on the user's choice.
                        if report_choice == 1:
                            filename = report.create_docx(cve_input)
                            print(f"Report saved as: {filename}")
                            break
                        elif report_choice == 2:
                            filename = report.create_md(cve_input)
                            print(f"Report saved as: {filename}") 
                            break
                        elif report_choice == 3:
                            filename = report.create_pdf(cve_input)
                            print(f"Report saved as: {filename}")
                            break
                        else:
                            print("Invalid input. Please enter a right choice (1, 2, or 3).")
                    except ValueError:
                        print("Invalid input. Please enter a valid choice (1, 2, or 3).")

                    #print(f"Report saved as: {filename}")
                    break
                else:
                    print("Please, enter a valid CVE ID")
                    print("For Instance: CVE-2017-0144") 
            if details:
                print('Your detailed information\n')
                def check_exploit_db(cve_id):
                    if not cve_id.startswith("CVE-"):
                        cve_id = f"CVE-{cve_id}"
                        url = f"https://www.exploit-db.com/search?cve={cve_id}&draw=1&columns%5B0%5D%5Bdata%5D=date_published&columns%5B0" \
                        f"%5D%5Bname%5D=date_published&columns%5B0%5D%5Bsearchable%5D=true&columns%5B0%5D%5Borderable%5D=true" \
                        f"&columns%5B0%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B0%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B1%5D%5Bdata" \
                        f"%5D=download&columns%5B1%5D%5Bname%5D=download&columns%5B1%5D%5Bsearchable%5D=false&columns%5B1%5D" \
                        f"%5Borderable%5D=false&columns%5B1%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B1%5D%5Bsearch%5D%5Bregex%5D=false" \
                        f"&columns%5B2%5D%5Bdata%5D=application_md5&columns%5B2%5D%5Bname%5D=application_md5&columns%5B2%5D" \
                        f"%5Bsearchable%5D=true&columns%5B2%5D%5Borderable%5D=false&columns%5B2%5D%5Bsearch%5D%5Bvalue%5D=&columns" \
                        f"%5B2%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B3%5D%5Bdata%5D=verified&columns%5B3%5D%5Bname%5D=verified" \
                        f"&columns%5B3%5D%5Bsearchable%5D=true&columns%5B3%5D%5Borderable%5D=false&columns%5B3%5D%5Bsearch%5D" \
                        f"%5Bvalue%5D=&columns%5B3%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B4%5D%5Bdata%5D=description&columns%5B4" \
                        f"%5D%5Bname%5D=description&columns%5B4%5D%5Bsearchable%5D=true&columns%5B4%5D%5Borderable%5D=false&columns" \
                        f"%5B4%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B4%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B5%5D%5Bdata%5D" \
                        f"=type_id&columns%5B5%5D%5Bname%5D=type_id&columns%5B5%5D%5Bsearchable%5D=true&columns%5B5%5D%5Borderable" \
                        f"%5D=false&columns%5B5%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B5%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B6" \
                        f"%5D%5Bdata%5D=platform_id&columns%5B6%5D%5Bname%5D=platform_id&columns%5B6%5D%5Bsearchable%5D=true" \
                        f"&columns%5B6%5D%5Borderable%5D=false&columns%5B6%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B6%5D%5Bsearch%5D" \
                        f"%5Bregex%5D=false&columns%5B7%5D%5Bdata%5D=author_id&columns%5B7%5D%5Bname%5D=author_id&columns%5B7%5D" \
                        f"%5Bsearchable%5D=false&columns%5B7%5D%5Borderable%5D=false&columns%5B7%5D%5Bsearch%5D%5Bvalue%5D=&columns" \
                        f"%5B7%5D%5Bsearch%5D%5Bregex%5D=false&order%5B0%5D%5Bcolumn%5D=0&order%5B0%5D%5Bdir%5D=desc&start=0&length" \
                        f"=15&search%5Bvalue%5D=&search%5Bregex%5D=false "

                        # this is the header which is written for retrive data when we send request
                        header = {
                            "authority": "www.exploit-db.com",
                            "accept": "application/json, text/javascript, */*; q=0.01",
                            "accept-language": "en-US,en;q=0.8",
                            "cookie": "XSRF-TOKEN"
                            "=eyJpdiI6IlJBT0RrMGlXZ0ZwOGpaT05wOWZpdUE9PSIsInZhbHVlIjoiRXVEVHcrSmdTWldBMHJlTTJhZ04zMjJOOGFvVUNKYUM4NytvQlhDRFc2eE5kb2hcL2Q5bkdnY1IxNzhmejVXVHIiLCJtYWMiOiJkZTUzYjI3mYjc4ZGNkMCJ9",
                            "referer": f"https://www.exploit-db.com/search?cve={cve_id}",
                            "sec-ch-ua": "'Brave';v='117', 'Not;A=Brand';v='8', 'Chromium';v='117'",
                            "sec-ch-ua-mobile": "?0",
                            "sec-ch-ua-platform": "'Windows'",
                            "sec-fetch-dest": "empty",
                            "sec-fetch-mode": "cors",
                            "sec-fetch-site": "same-origin",
                            "sec-gpc": "1",
                            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                            "Chrome/117.0.0.0 Safari/537.36",
                            "x-requested-with": "XMLHttpRequest"
                            }

                    response = requests.get(url, headers=header)

                #      part which is used for getting script code , script header    
                    info = response.json()
                    records_total = info.get("recordsTotal", 0)
                    if records_total != 0:
                        first_code_id = info.get("data", [])[0].get("id")
                        exploit_header = info.get("data", [])[0].get("description")[1]
                        exploit_script = fetch_exploit_script(first_code_id)
                        return records_total, exploit_header, exploit_script
                    else:
                        return "No script available", "No script available", "No script available"

                        #this function which find the script code as getting the data
                def fetch_exploit_script(exploit_id):
                    response = requests.get(f"https://www.exploit-db.com/exploits/{exploit_id}", headers=headers)
                    soup = BeautifulSoup(response.text, "html.parser")

                    scrip_element = soup.find("code")
                    script = scrip_element.text if scrip_element else "Script is not available"

                    return script

            
        elif choose == 'A':
            import webbrowser
            flask_url = "http://127.0.0.1:5000"
            webbrowser.open(flask_url)
        else:
            print('Invalid variant please look at again')

if __name__ == "__main__":
    try:
        process = threading.Thread(target=search_cve,args=())
        process.start()
        
    except OSError:
        sys.exit()
