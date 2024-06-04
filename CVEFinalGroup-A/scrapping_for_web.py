import requests
from bs4 import BeautifulSoup
def get_detail(cve_id):
    if not cve_id.startswith("CVE-"):
        cve_id = f"CVE-{cve_id}"
        
    url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    response = requests.get(url)
    if response.status_code != 200:
        print(f'Here is the error code : {response.status_code}')
    
    soup = BeautifulSoup(response.text, "html.parser")
    
    summary_info = soup.find("p" , {"data-testid" : "vuln-description"})
    summary = summary_info.text if summary_info else "Summary is not available"
    
    cvss_element = soup.find("a", {"data-testid": "vuln-cvss3-panel-score"})
    cvss_score = cvss_element.text if cvss_element else "Base score is not available"
   
    vector_element = soup.find("span", {"data-testid": "vuln-cvss3-nist-vector"})
    vector = vector_element.text if vector_element else "Vector is not available"
   
    reference_elements = soup.find_all("tr", {"data-testid": "vuln-hyperlinks-row-0"})
    references = [ref.text for ref in reference_elements] if reference_elements else ["References are not available"]
   
    reference_elementsecond = soup.find_all("tr", {"data-testid": "vuln-hyperlinks-row-1"})
    referencesecond = [ref.text for ref in reference_elementsecond] if reference_elementsecond else ["References are not available"]
    
    reference_elementthird = soup.find_all("tr", {"data-testid": "vuln-hyperlinks-row-2"})
    referencethird = [ref.text for ref in reference_elementthird] if reference_elementthird else ["References are not available"]

    cve_link = soup.find('a', {'data-testid': 'vuln-cve-dictionary-entry'}).get('href')
   
    published_date = soup.find('span', {'data-testid': 'vuln-published-on'}).text
   
    last_modified_date = soup.find('span', {'data-testid': 'vuln-last-modified-on'}).text
   
    source = soup.find('span', {'data-testid': 'vuln-current-description-source'}).text

    return summary, cvss_score, vector, references, referencesecond, referencethird, cve_link, published_date, last_modified_date, source