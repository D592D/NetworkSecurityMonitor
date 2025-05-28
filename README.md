## Overview

This project is a real-time network security monitoring system built using Python and the Streamlit framework. It captures and displays network alerts, provides threat analysis insights, offers visualizations of security events, allows for basic configuration, and specifically tracks external IP addresses involved in network activity. The system also includes the functionality to launch a separate vulnerability scanner application.

## Features

* **Real-time Alert Monitoring:** Displays network security alerts as they occur.
* **Alert Summaries:** Provides metrics on total, active, and mitigated alerts.
* **Detailed Alert Information:** Shows the type, timestamp, source, destination, protocol, severity, and status of each alert.
* **Mitigation Information:** Displays any applied mitigation steps for alerts.
* **Threat Analysis:** (Section to be expanded with specific analysis features)
* **Visualizations:** Generates charts for alert distribution and a timeline of security logs.
* **Configuration:** (Section to be expanded with configuration options)
* **External IP Tracking:** Specifically monitors and displays external IP addresses involved in network activity, including DNS resolution.
* **Vulnerability Scanner Launch:** Includes a button to launch a separate Streamlit vulnerability scanning application.
* **AI-Powered Analysis:** Uses the OpenAI API to provide intelligent threat analysis and recommendations.

## Getting Started

### Prerequisites

* **Python 3.x** installed on your system.
* **pip** (Python package installer).
* An OpenAI API key (for AI analysis features).

### Installation

1.  Clone the repository to your local machine:

    ```bash
    git clone [https://github.com/D592D/NetworkSecurityMonitor.git](https://github.com/D592D/NetworkSecurityMonitor.git)
    cd NetworkSecurityMonitor
    ```

2.  Create a virtual environment (recommended):

    ```bash
    python -m venv venv
    source venv/bin/activate   # On macOS and Linux
    venv\Scripts\activate.bat  # On Windows
    ```

3.  Install the required Python packages:

    ```bash
    pip install -r requirements.txt
    ```

    *(Note: Make sure you have a `requirements.txt` file in the root of your project. You can generate it by running `pip freeze > requirements.txt` after installing the necessary libraries with pip.)*

### OpenAI API Key Setup (for AI Analysis features)

This project utilizes the OpenAI API for certain threat analysis functionalities. To enable these features, you will need an OpenAI API key.

1.  Sign up for an OpenAI account at [https://openai.com/](https://openai.com/).
2.  Generate a new API key from your OpenAI dashboard.
3.  Set the API key as an environment variable named `OPENAI_API_KEY` before running the application.

#### Setting the environment variable:

* **macOS/Linux:**

    ```bash
    export OPENAI_API_KEY="YOUR_ACTUAL_OPENAI_API_KEY"
    ```

* **Windows (Command Prompt):**

    ```bash
    set OPENAI_API_KEY="YOUR_ACTUAL_OPENAI_API_KEY"
    ```

* **Windows (PowerShell):**

    ```powershell
    $env:OPENAI_API_KEY = "YOUR_ACTUAL_OPENAI_API_KEY"
    ```

    You may want to add this to your shell's configuration file (e.g., `.bashrc`, `.zshrc`, `.profile`) to make it persistent.  Alternatively, you can use a `.env` file (see below).

### Running the Application

1.  Navigate to the `src` directory:

    ```bash
    cd src
    ```

2.  Run the main Streamlit application:

    ```bash
    streamlit run main.py
    ```

    This command will open the application in your web browser (usually at `http://localhost:8501`).

### Running the Vulnerability Scanner

1.  Ensure the main monitoring application is running.
2.  In the sidebar, click the "🔍 Vulnerability Run Scan" button.
3.  The vulnerability scanner application will attempt to launch in a new browser tab (usually at `http://localhost:5001`, though the IP might vary based on your local setup).

### Using a `.env` file for local development (Optional)

For local development, you can store your OpenAI API key in a `.env` file in the root of the project.  This file should **never** be committed to your Git repository.

1.  Create a file named `.env` in the root of your project (the same directory as `requirements.txt`).
2.  Add the following line to the `.env` file, replacing `YOUR_ACTUAL_OPENAI_API_KEY` with your key:

    ```
    OPENAI_API_KEY=YOUR_ACTUAL_OPENAI_API_KEY
    ```

3.  Install the `python-dotenv` package:

    ```bash
    pip install python-dotenv
    ```

4.  In your `src/utils/ai_analyzer.py` file, add the following lines at the beginning:

    ```python
    from dotenv import load_dotenv
    load_dotenv()
    ```

    This will load the environment variable from the `.env` file.

5.  Add `.env` to your `.gitignore` file to prevent it from being committed:

    ```
    echo .env >> .gitignore
    ```

