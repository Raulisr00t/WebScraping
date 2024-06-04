import re
from flask import Flask, render_template, request
from scrapping_for_web import get_detail 

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/result', methods=['POST'])
def search():
    cve_id = request.form['cve_id']
    cveRegex = re.compile(r'^CVE-\d{4}-\d{4,6}$')
    if not cveRegex.match(cve_id):
        error_message = "Invalid CVE format! Please enter a valid CVE in the format CVE-YYYY-XXXX(X)."
        return render_template('result.html', error_message=error_message)

    summary, cvss_score, vector, references, referencesecond, referencethird, cve_link, published_date, last_modified_date, source = get_detail(cve_id)
    return render_template('result.html', cve_id=cve_id, summary=summary, cvss_score=cvss_score, vector=vector,
                            references=references ,referencesecond=referencesecond,
                            referencethird=referencethird, cve_link=cve_link , 
                            published_date=published_date, last_modified_date=last_modified_date, source=source)

if __name__ == "__main__":
    app.run(debug=True)
