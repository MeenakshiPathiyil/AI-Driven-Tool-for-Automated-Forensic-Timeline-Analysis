# AI-Driven Tool for Automated Forensic Timeline Analysis
An AI-Driven tool designed to automate forensic timleine analysis. The tool processes forensic timelines generated using log2timeline, detect anomalies, identifies attack patterns based on the MITRE ATT&CK framework, and generates summaries for forensic investigations. Built with python, the backend powers the frontend application by providing APIs for timeline data, anomaly detection, and report generation.

## Table of Contents
- Features
- Prerequisites
- Installation
- Usage
- Project Structure
- API Endpoints
- Contributing
- License

## Features
- Anomaly Detection: Identifies unusual patterns in forensic timelines generated using log2timeline
- MITRE ATT&CK Integration: Maps detected events to MITRE ATT&CK techniques for structured analysis
- Summary Generation: Produces detailed summaries and reports of detected anomalies and attack patterns
- Data Ingestion: Supports CSV files generated using the dynamic flag in log2timeline

## Prerequisites
To run this project locally, ensure you have the following installed: 
- Python (v3.8 or higher)
- pip for installing uv
- uv for dependency management
- Git for version control

## Installation
1. Clone the Repository
   ```
   git clone https://github.com/MeenakshiPathiyil/AI-Driven-Tool-for-Automated-Forensic-Timeline-Analysis.git
   cd AI-Driven-Tool-for-Automated-Forensic-Timeline-Analysis
   ```
2. Set Up a Virtual Environment
   ```
   python -m venev venv
   source venv/bin/activate
   ```
3. Install uv
   ```
   pip install uv
   ```
4. Install Dependencies
   ```
   uv sync
   ```
5. Configure Environment Variables
   
   Create a .env file in the project root for sensitive configurations like API keys
6. Start the Backend
   ```
   python main.py
   ```

## Usage 
1. Run the backend: Start the server
   ```
   python main.py
   ```
2. Run the Frontend: Ensure the frontend repository is running
   ```
   npm start
   ```
3. Uplaod Forensic Logs: Uplaod the CSV file generated using log2timeline

## Contribution
Contributions to this project are welcome! If you have any suggestions, improvements or bug reports, please open an issue on the GitHub repository.
