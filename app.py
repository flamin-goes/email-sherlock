import email
import re
import tempfile
from flask import Flask, request, render_template, redirect, url_for, make_response
from ipwhois import IPWhois
import matplotlib.pyplot as plt
from io import BytesIO
import base64
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas

app = Flask(__name__)

def parse_email_headers(raw_email):
    msg = email.message_from_string(raw_email)
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
        'X-Mailer': msg.get('X-Mailer', 'Unknown')   # Default to 'Unknown' if X-Mailer is None
    }
    return headers

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
    obj = IPWhois(ip)
    res = obj.lookup_rdap(depth=1)
    city = res.get('network', {}).get('city', 'Unknown')
    region = res.get('network', {}).get('state', 'Unknown')
    country = res.get('network', {}).get('country', 'Unknown')
    loc = f"{city},{region},{country}"
    return city, region, country, loc

def visualize_email_path(ips):
    if not ips:
        return None

    locations = [geolocate_ip(ip) for ip in ips]
    hops = [f'{ip} ({city}, {region}, {country})' for ip, (city, region, country, loc) in zip(ips, locations)]
    
    # Prepare data for plotting
    hop_numbers = range(1, len(hops) + 1)
    ips_with_locations = [f'{ip}\n{city}, {region}, {country}' for ip, (city, region, country, loc) in zip(ips, locations)]
    
    # Plotting
    fig, ax = plt.subplots(figsize=(12, 6))
    ax.plot(hop_numbers, hop_numbers, color='lightgray', linestyle='--', linewidth=1)  # Dummy line for background grid
    ax.plot(hop_numbers, hop_numbers, marker='o', markersize=8, color='blue', label='Email Path')
    for i, txt in enumerate(ips_with_locations):
        ax.annotate(txt, (hop_numbers[i], hop_numbers[i]), textcoords="offset points", xytext=(0,10), ha='center')

    ax.set_title('Email Path Visualization', fontsize=16)
    ax.set_xlabel('Hop Number', fontsize=14)
    ax.set_ylabel('Server (IP and Location)', fontsize=14)
    ax.set_xticks(hop_numbers)
    ax.set_xticklabels(hop_numbers)
    ax.tick_params(axis='both', which='major', labelsize=12)
    ax.grid(True, which='both', linestyle='--', linewidth=0.5)
    ax.legend(fontsize=12)

    # Convert plot to base64 encoded image
    buf = BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    img_data = base64.b64encode(buf.getvalue()).decode('utf-8')
    plt.close()

    return img_data

def check_spoofing(headers):
    # Check SPF result
    spf_result = headers.get('Received-SPF', '')
    if 'pass' not in spf_result.lower():
        return True  # SPF failed

    # Check DKIM result
    dkim_result = headers.get('DKIM-Signature', '')
    if not dkim_result:
        return True  # DKIM signature not present

    return False  # No spoofing detected

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        raw_email = None
        if 'file' in request.files and request.files['file'].filename:
            file = request.files['file']
            raw_email = file.read().decode('utf-8')
        elif 'header_text' in request.form and request.form['header_text'].strip():
            raw_email = request.form['header_text']
        
        if raw_email:
            headers = parse_email_headers(raw_email)
            ips = extract_ips(headers.get('Received', []))
            img_data = visualize_email_path(ips)
            spoofing_detected = check_spoofing(headers)
            return render_template('result.html', headers=headers, ips=ips, img_data=img_data, spoofing_detected=spoofing_detected)
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

@app.route('/download_pdf', methods=['POST'])
def download_pdf():
    headers = eval(request.form.get('headers'))
    ips = eval(request.form.get('ips'))
    img_data = request.form.get('img_data')
    spoofing_detected = request.form.get('spoofing_detected') == 'True'

    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    margin = 0.75 * inch
    max_text_width = width - 2 * margin
    y = height - margin

    def draw_title(c, text, y):
        c.setFont("Helvetica-Bold", 20)
        c.setFillColor(colors.HexColor('#1A237E'))
        c.drawString(margin, y, text)
        c.setFillColor(colors.black)
        y -= 0.3 * inch
        return y

    def draw_section_title(c, text, y):
        c.setFont("Helvetica-Bold", 14)
        c.setFillColor(colors.HexColor('#0D47A1'))
        c.drawString(margin, y, text)
        c.setFillColor(colors.black)
        y -= 0.2 * inch
        return y

    def draw_text(c, text, y, indent=0):
        c.setFont("Helvetica", 12)
        lines = split_text_into_lines(text, max_text_width - indent, c)
        for line in lines:
            if y < margin:
                c.showPage()
                y = height - margin
            c.drawString(margin + indent, y, line)
            y -= 0.2 * inch
        return y

    # Title
    y = draw_title(c, "Email Header Analysis Result", y)

    # Spoofing Check
    y = draw_section_title(c, "Spoofing Check:", y)
    c.setFont("Helvetica", 12)
    if spoofing_detected:
        c.setFillColor(colors.red)
        y = draw_text(c, "Spoofing Detected!", y, indent=margin)
    else:
        c.setFillColor(colors.green)
        y = draw_text(c, "No Spoofing Detected.", y, indent=margin)
    c.setFillColor(colors.black)

    # Basic Information
    y = draw_section_title(c, "Basic Information", y)
    for key in ['From', 'To', 'Reply-To', 'Return-Path', 'Subject', 'Date', 'Message-ID']:
        y = draw_text(c, f"{key}: {headers.get(key, 'N/A')}", y, indent=margin)

    # Received Headers
    y = draw_section_title(c, "Received Headers", y)
    for received in headers.get('Received', []):
        y = draw_text(c, received, y, indent=margin)

    # Extracted IPs
    y = draw_section_title(c, "Extracted IPs", y)
    for ip in ips:
        y = draw_text(c, ip, y, indent=margin)

    # Additional Headers
    y = draw_section_title(c, "Additional Headers", y)
    for key in ['DMARC-Results', 'MIME-Version', 'Content-Type', 'X-Mailer']:
        value = headers.get(key, 'N/A')
        y = draw_text(c, f"{key}: {value}", y, indent=margin)

    for key, value in headers.get('X-Headers', {}).items():
        y = draw_text(c, f"{key}: {value}", y, indent=margin)

    # Email Path Visualization
    if img_data:
        if y < 6 * inch:  # Check if there's enough space for the image (adjust as needed)
            c.showPage()
            y = height - margin
        y = draw_section_title(c, "Email Path Visualization", y)

        img_data = base64.b64decode(img_data)
        with tempfile.NamedTemporaryFile(delete=False, suffix='.png') as temp_image:
            temp_image.write(img_data)
            temp_image_path = temp_image.name

        c.drawImage(temp_image_path, margin, y - 5 * inch, width=6 * inch, preserveAspectRatio=True, mask='auto')

    c.save()
    buffer.seek(0)

    response = make_response(buffer.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=email_analysis.pdf'

    return response

if __name__ == '__main__':
    app.run(debug=True)