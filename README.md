# Email-Sherlock

This Flask application allows users to upload email files or paste raw email headers for analysis. It provides a detailed report on email headers, attachments, IP addresses involved in the email path, and checks for possible email spoofing.

## Features

- Parse email headers and extract important information.
- Scan email attachments using VirusTotal API.
- Visualize the path of the email based on IP addresses.
- Check for potential email spoofing by analyzing SPF, DKIM, and DMARC results.
- Generate a visual report of the email's journey through different IPs.

## Prerequisites

Ensure you have the following installed:

- Python 3.7 or higher
- pip (Python package installer)

## Installation

1. **Clone the repository:**

    ```sh
    git clone https://github.com/yourusername/email-header-analyzer.git
    cd email-header-analyzer
    ```

2. **Install dependencies:**

    ```sh
    pip install -r requirements.txt
    ```

3. **Set up VirusTotal API key:**

    - Obtain an API key from [VirusTotal](https://www.virustotal.com/).
    - Replace the placeholder `VT_API_KEY` in the `app.py` file with your actual VirusTotal API key.

## Usage

1. **Run the application:**

    ```sh
    python app.py
    ```

2. **Access the application:**

    Open a web browser and navigate to `http://127.0.0.1:5000/`.

3. **Analyze an email:**

    - Upload an email file or paste raw email headers.
    - Click "Analyze" to view the detailed report.

## Project Structure

- `app.py`: The main Flask application file.
- `templates/`: Folder containing HTML templates.
    - `index.html`: The homepage template for uploading files or pasting email headers.
    - `result.html`: The template for displaying analysis results.
- `requirements.txt`: List of dependencies required to run the application.
- `README.md`: This file, providing an overview and setup instructions.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request or report any issues.

## Acknowledgements

- [VirusTotal](https://www.virustotal.com/) for providing the API for scanning email attachments.
- [IPWhois](https://github.com/secynic/ipwhois) for the IP geolocation functionality.
- [Flask](https://flask.palletsprojects.com/) for the web framework.
- [Matplotlib](https://matplotlib.org/) for data visualization.

