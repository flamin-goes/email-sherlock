import re
import os
from io import BytesIO
import base64
from email import policy
from email.parser import BytesParser
from flask import Flask, request, render_template, redirect, url_for, make_response
from ipwhois import IPWhois
import matplotlib.pyplot as plt
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from virustotal_python import Virustotal, VirustotalError
import requests
import time 

app = Flask(__name__)

VT_API_KEY = '4ecc163949a29bf3484cba4aa532eba8687e81a29d96bf79901eb17e428857e3' #INSERT YOU OWN VIRUS-TOTAL API HERE
BASE_URL = 'https://www.virustotal.com/api/v3'

def scan_file_virustotal(file_data, filename):
    try:
        files = {'file': (filename, file_data)}
        headers = {
            'x-apikey': VT_API_KEY,
        }
        response = requests.post(f"{BASE_URL}/files", files=files, headers=headers)
        response.raise_for_status()

        analysis_id = response.json()['data']['id']

        while True:
            analysis_response = requests.get(f"{BASE_URL}/analyses/{analysis_id}", headers=headers)
            analysis_response.raise_for_status()
            analysis = analysis_response.json()

            if analysis['data']['attributes']['status'] == 'completed':
                stats = analysis['data']['attributes']['stats']
                total_results = sum(stats.values())
                malicious_score = stats['malicious'] / total_results if total_results > 0 else 0
                scan_results = [f"Malicious Score: {stats['malicious']} out of {total_results} ({malicious_score:.2%})"]
                return scan_results
            time.sleep(2)

    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return [f"Error: {str(e)}"]  # Return a list with error message

def parse_email_headers(raw_email):
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw_email)
    except Exception as e:
        print(f"Error parsing email headers: {e}")
        return {}, []

    headers = {
        'From': msg['From'],
        'To': msg['To'],
        'Reply-To': msg['Reply-To'],
        'Return-Path': msg['Return-Path'],
        'Subject': msg['Subject'],
        'Date': msg['Date'],
        'Message-ID': msg['Message-ID'],
        'Received': msg.get_all('Received'),
        'Received-SPF': msg.get('Received-SPF'),
        'DKIM-Signature': msg.get('DKIM-Signature'),
        'Authentication-Results': msg.get('Authentication-Results'),
        'DMARC-Results': extract_dmarc_results(msg.get('Authentication-Results')),
        'X-Headers': {key: value for key, value in msg.items() if key.startswith('X-')},
        'MIME-Version': msg.get('MIME-Version'),
        'Content-Type': msg.get('Content-Type'),
        'X-Mailer': msg.get('X-Mailer', 'Unknown')  # Default to 'Unknown' if X-Mailer is None
    }

    attachments = []
    for part in msg.iter_attachments():
        try:
            payload = part.get_payload(decode=True)
            filename = part.get_filename()
            content_type = part.get_content_type()

            if payload:
                scan_result = scan_file_virustotal(payload, filename)
            else:
                scan_result = ["Error: Empty attachment"]

            attachments.append({
                'filename': filename,
                'content_type': content_type,
                'scan_result': scan_result,
            })

        except Exception as e:
            print(f"Error processing attachment: {e}")
            attachments.append({
                'filename': filename,
                'content_type': content_type,
                'scan_result': [f"Error: {str(e)}"],
            })

    return headers, attachments


def format_vt_data(vt_data):
    """Formats VirusTotal 'data' for display."""
    formatted_data = []
    attributes = vt_data.get('attributes', {})
    last_analysis_stats = attributes.get('last_analysis_stats', {})

    formatted_data.append(f"**Last Analysis Stats:**")
    for key, value in last_analysis_stats.items():
        formatted_data.append(f"  * {key.capitalize()}: {value}")

    # Add more formatting for other attributes as needed...

    return "<br>".join(formatted_data)  # Or use a different separator 

def format_vt_meta(vt_meta):
    """Formats VirusTotal 'meta' for display."""
    formatted_meta = []
    # Add your formatting logic here based on the structure of 'meta' 
    # ...

    return "<br>".join(formatted_meta)

def extract_dmarc_results(auth_results):
    if not auth_results:
        return "None"

    dmarc_pattern = re.compile(r'dmarc=(\S+)', re.IGNORECASE)
    match = dmarc_pattern.search(auth_results)

    if match:
        return match.group(1)
    return "None"

def extract_ips(received_headers):
    ip_pattern = re.compile(r'\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?')
    ips = []
    for header in received_headers:
        match = ip_pattern.search(header)
        if match:
            ips.append(match.group(1))
    return ips

def geolocate_ip(ip):
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap(depth=1)
        city = res.get('network', {}).get('city', 'Unknown')
        region = res.get('network', {}).get('state', 'Unknown')
        country = res.get('network', {}).get('country', 'Unknown')
        loc = f"{city},{region},{country}"
        return city, region, country, loc
    except Exception as e:
        print(f"Error geolocating IP {ip}: {e}")
        return 'Unknown', 'Unknown', 'Unknown', 'Unknown'

def visualize_email_path(ips):
    if not ips:
        return None

    locations = [geolocate_ip(ip) for ip in ips]
    hops = [f'{ip} ({city}, {region}, {country})' for ip, (city, region, country, loc) in zip(ips, locations)]

    fig, ax = plt.subplots(figsize=(12, 6))
    ax.plot(range(1, len(hops) + 1), range(1, len(hops) + 1), color='lightgray', linestyle='--', linewidth=1)
    ax.plot(range(1, len(hops) + 1), range(1, len(hops) + 1), marker='o', markersize=8, color='blue', label='Email Path')

    for i, (ip, (city, region, country, loc)) in enumerate(zip(ips, locations)):
        ax.annotate(f'{ip}\n{city}, {region}, {country}', (i + 1, i + 1), textcoords="offset points", xytext=(0, 10), ha='center')

    ax.set_title('Email Path Visualization', fontsize=16)
    ax.set_xlabel('Hop Number', fontsize=14)
    ax.set_ylabel('Server (IP and Location)', fontsize=14)
    ax.set_xticks(range(1, len(hops) + 1))
    ax.set_xticklabels(range(1, len(hops) + 1))
    ax.tick_params(axis='both', which='major', labelsize=12)
    ax.grid(True, which='both', linestyle='--', linewidth=0.5)
    ax.legend(fontsize=12)

    buf = BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    img_data = base64.b64encode(buf.getvalue()).decode('utf-8')
    plt.close()

    return img_data

@app.template_filter('spoofing_color')
def spoofing_color_filter(severity):
    if severity == 'high':
        return 'red'
    elif severity == 'medium':
        return 'orange'
    else:
        return 'black'

def check_spoofing(headers):
    spf_result = headers.get('Received-SPF', '')
    dkim_result = headers.get('DKIM-Signature', '')
    dmarc_result = extract_dmarc_results(headers.get('Authentication-Results'))
    from_header = headers.get('From', '')
    return_path = headers.get('Return-Path', '')

    spoofing_details = []

    if 'pass' not in spf_result.lower():
        spoofing_details.append({
            'check': 'SPF',
            'result': spf_result,
            'description': 'SPF check failed. The sending server might not be authorized.',
            'severity': 'high'  # You can categorize severity as needed
        })

    if not dkim_result:
        spoofing_details.append({
            'check': 'DKIM',
            'result': 'Missing',
            'description': 'DKIM signature is missing. Email authenticity cannot be verified.',
            'severity': 'medium'
        })

    if 'pass' not in dmarc_result.lower():
        spoofing_details.append({
            'check': 'DMARC',
            'result': dmarc_result,
            'description': 'DMARC check failed. This could indicate a higher likelihood of spoofing.',
            'severity': 'high'
        })

    if from_header and return_path:
        # Extract the domain from the From header
        from_domain = re.search(r'@([\w.-]+)', from_header)
        from_domain = from_domain.group(1) if from_domain else None

        # Extract the domain from the Return-Path header
        return_path_domain = re.search(r'@([\w.-]+)', return_path)
        return_path_domain = return_path_domain.group(1) if return_path_domain else None

        # Check against common bounce patterns before flagging a mismatch
        common_provider_patterns = [
            r'.*\.bounces\.google\.com$',  # Google bounces
            r'.*\.mail\.yahoo\.com$',       # Yahoo bounces
            r'.*\.protection\.outlook\.com$', # Outlook bounces
            r'.*\.amazonses\.com$',          # Amazon SES
            r'.*\.sendgrid\.net$',           # SendGrid
            r'.*\.mailgun\.org$',            # Mailgun
            r'.*\.postmarkapp\.com$',        # Postmark
            # ... Add more patterns for other providers as needed ...
        ]

        if from_domain and return_path_domain and from_domain.lower() != return_path_domain.lower():
            for pattern in common_provider_patterns:
                if re.match(pattern, return_path):
                    # Likely a legitimate bounce address, skip mismatch warning
                    break 
            else:
                # No common pattern found, so the mismatch is suspicious
                spoofing_details.append({
                    'check': 'From/Return-Path Domain Mismatch',
                    'result': f'From Domain: {from_domain}, Return-Path Domain: {return_path_domain}',
                    'description': 'The "From" and "Return-Path" header domains do not match, which can be suspicious.',
                    'severity': 'medium'
                })

    return spoofing_details

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        raw_email = None
        attachments = []

        if 'file' in request.files and request.files['file'].filename:
            file = request.files['file']
            raw_email = file.read()
            headers, attachments = parse_email_headers(raw_email)
        elif 'header_text' in request.form and request.form['header_text'].strip():
            raw_email = request.form['header_text'].encode("utf-8")
            headers, attachments = parse_email_headers(raw_email)

        if raw_email:
            ips = extract_ips(headers.get('Received', []))
            img_data = visualize_email_path(ips)
            spoofing_detected = check_spoofing(headers) 
            return render_template('result.html', headers=headers, ips=ips, 
                                    img_data=img_data,
                                    spoofing_detected=spoofing_detected,
                                    attachments=attachments)
        else:
            return redirect(url_for('index'))

    return render_template('index.html')

def split_text_into_lines(text, max_width, canvas):
    lines = []
    current_line = ""
    words = text.split()

    for word in words:
        if canvas.stringWidth(current_line + " " + word) < max_width:
            current_line += " " + word
        else:
            lines.append(current_line.strip())
            current_line = word

    if current_line:
        lines.append(current_line.strip())

    return lines

if __name__ == '__main__':
    app.run(debug=True)
