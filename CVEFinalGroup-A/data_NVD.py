import requests
from bs4 import BeautifulSoup

def get_detail(cve_id):
    if not cve_id.startswith("CVE-"):
        cve_id = f"CVE-{cve_id}"

    # Construct the URL with the full CVE ID.
    url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

    
    response = requests.get(url)
    soup = BeautifulSoup(response.text, "html.parser")
    
   
    summary_info = soup.find("p" , {"data-testid" : "vuln-description"})
    summary = summary_info.text if summary_info else "Summary is not available"

    cvss_element = soup.find("a", {"data-testid": "vuln-cvss3-panel-score"})
    cvss_score = cvss_element.text if cvss_element else "Base score is not available"
     

    vector_element = soup.find("span", {"data-testid": "vuln-cvss3-nist-vector"})
    vector = vector_element.text if vector_element else "Vector is not available"

 
    reference_element = soup.find("td", {"data-testid": "vuln-hyperlinks-link-0"})
    reference_element1 = soup.find("td", {"data-testid": "vuln-hyperlinks-link-1"})
    reference_element2= soup.find("td", {"data-testid": "vuln-hyperlinks-link-2"})
    reference_element3 = soup.find("td", {"data-testid": "vuln-hyperlinks-link-3"})
    reference_element4 = soup.find("td", {"data-testid": "vuln-hyperlinks-link-4"})
    

    reference = reference_element.text if reference_element else "Reference is not exist"
    reference1 = reference_element1.text if reference_element1 else "Reference is not exist"
    reference2 = reference_element2.text if reference_element2 else "Reference is not exist"
    reference3 = reference_element3.text if reference_element3 else "Reference is not exist"
    reference4 = reference_element4.text if reference_element4 else "Reference is not exist"

    cve_link = soup.find('a', {'data-testid': 'vuln-cve-dictionary-entry'}).get('href')
    published_date = soup.find('span', {'data-testid': 'vuln-published-on'}).text
    last_modified_date = soup.find('span', {'data-testid': 'vuln-last-modified-on'}).text
    source = soup.find('span', {'data-testid': 'vuln-current-description-source'}).text


  



    return summary, cvss_score, vector, reference , reference1 , reference2, reference3, reference4 , cve_link, published_date, last_modified_date, source


