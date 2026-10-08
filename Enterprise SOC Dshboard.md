# Enterprise SOC Dashboard

## Centralized Security Monitoring and Alert Investigation

---

##  About the Project

The **Enterprise SOC Dashboard** is a centralized security monitoring system designed to help security teams monitor, view, search, and investigate security alerts from a single dashboard.

The system provides a simple web-based interface where security analysts can view security alerts, check alert statistics, investigate individual alerts, manage incidents and Indicators of Compromise (IOCs), and access threat intelligence information.

The project combines **Suricata, Python, FastAPI, PostgreSQL, MISP, HTML, CSS, and JavaScript** to build the monitoring platform.

---

##  Problem Statement

In an enterprise environment, security alerts can come from different security monitoring systems.

When these alerts are difficult to view and investigate from one place, security analysts may spend more time checking individual sources.

The Enterprise SOC Dashboard provides a centralized interface where security alerts can be viewed and investigated more easily.

---

##  Objective

The main objective of this project is to develop a centralized SOC dashboard that can:

- Monitor security alerts
- Display alerts in a simple dashboard
- Show alert statistics
- Search and filter alerts
- Investigate individual alerts
- Manage security incidents
- Manage Indicators of Compromise (IOCs)
- Display threat intelligence information
- Show backend connection status
- Store security-related information in PostgreSQL

---

##  System Architecture

The system consists of the following main components:

1. **Security Monitoring Layer**
   - Suricata monitors network security events and generates security alerts.

2. **Backend Layer**
   - Python and FastAPI handle API requests and backend operations.

3. **Database Layer**
   - PostgreSQL stores users, alerts, incidents, IOCs, and related security information.

4. **Threat Intelligence Layer**
   - MISP provides threat intelligence information.

5. **Frontend Layer**
   - HTML, CSS, and JavaScript provide the SOC dashboard interface.

### Simple Architecture

    Suricata
        ↓
    Security Alerts
        ↓
    FastAPI Backend
        ↓
    PostgreSQL Database
        ↓
    SOC Dashboard
        ↓
    Security Analyst

    MISP
        ↓
    Threat Intelligence
        ↓
    SOC Dashboard

---

##  System Workflow

The system follows a simple workflow:

    Security Event
          ↓
    Security Monitoring
          ↓
    Alert Generation
          ↓
    Backend Processing
          ↓
    Alert Storage
          ↓
    SOC Dashboard
          ↓
    Search / Filter / Investigation
          ↓
    Security Analyst

The dashboard allows the analyst to view security information and investigate alerts from a centralized interface.

---

##  How the System Works

### 1. Security Monitoring

Suricata is used as the network security monitoring component.

It can generate security alerts when monitored network traffic matches configured security rules.

### 2. Backend Processing

The FastAPI backend provides REST APIs for the dashboard.

The backend handles:

- Authentication
- Alert access
- Statistics
- Incident management
- IOC management
- Threat intelligence access
- Database operations
- Backend health status

### 3. Database Storage

PostgreSQL is used to store structured security information.

The database can contain information related to:

- Users
- Security alerts
- Incidents
- IOCs
- Audit information

### 4. Dashboard

The frontend provides a centralized dashboard for security analysts.

Analysts can:

- View alerts
- Search alerts
- Filter alerts
- Check statistics
- Investigate alerts
- Manage incidents
- Manage IOCs
- View threat intelligence

---

#  Key Features

##  Security Alert Monitoring

The dashboard provides a centralized view of security alerts.

Alert information can include:

- Alert ID
- Timestamp
- Source IP
- Destination IP
- Source Port
- Destination Port
- Protocol
- Severity
- Category
- Signature
- Rule information
- Network interface
- Action

---

##  Alert Statistics

The dashboard provides security alert statistics to give analysts a quick overview of the current security situation.

The dashboard can display information such as:

- Total Alerts
- High Severity Alerts
- Medium Severity Alerts
- Low Severity Alerts

---

##  Alert Search

The dashboard provides a search option for finding specific security alerts.

Analysts can search the available alert information instead of manually checking every alert.

---

##  Alert Filtering

Security alerts can be filtered based on available alert information.

Filtering helps analysts focus on specific types of alerts and severity levels.

---

##  Alert Investigation

The dashboard provides an alert investigation interface.

When an analyst selects an alert, detailed information can be viewed, including:

- Source IP
- Destination IP
- Source Port
- Destination Port
- Protocol
- Network Interface
- Severity
- Category
- Signature ID
- Revision
- Action
- Other available alert details

This helps the analyst understand the details of a security event.

---

##  Incident Management

The system provides an incident management section.

Security analysts can manage security incidents through the dashboard.

The system provides API operations for:

- Creating incidents
- Viewing incidents
- Updating incidents
- Deleting incidents

---

##  IOC Management

The dashboard provides IOC management functionality.

Indicators of Compromise can be stored and managed through the system.

Examples of IOC information include:

- IP addresses
- Domains
- Hashes
- Other security indicators

The system provides API operations for:

- Adding IOCs
- Viewing IOCs
- Updating IOCs
- Deleting IOCs

---

##  Threat Intelligence

MISP is used as the threat intelligence component.

The dashboard provides access to available threat intelligence information through the backend.

This allows security analysts to view relevant threat intelligence information from the SOC dashboard.

---

##  Backend Status

The dashboard provides backend connection status.

This helps the user understand whether the dashboard is successfully connected to the backend service.

The backend also provides a health-check API.

---

#  Technologies Used

## Security Monitoring

- **Suricata**

## Threat Intelligence

- **MISP**

## Backend

- **Python**
- **FastAPI**
- **Uvicorn**
- **REST API**

## Frontend

- **HTML**
- **CSS**
- **JavaScript**

## Database

- **PostgreSQL**

## Version Control

- **Git**
- **GitHub**

---

#  Project Structure

    Enterprise_SOC_Dashboard/
    │
    ├── backend/
    │   ├── main.py
    │   └── init_db.py
    │
    ├── frontend/
    │   └── index.html
    │
    ├── .gitignore
    └── README.md

---

#  Requirements

Before running the project, install the following:

- Python 3.x
- PostgreSQL
- Suricata
- MISP
- Git

Python packages required by the backend include:

- FastAPI
- Uvicorn
- PostgreSQL database driver
- Requests
- Other packages specified by the project configuration

---

#  Installation

## 1. Clone the Repository

    git clone https://github.com/sarathkumarkaturi/Enterprise_SOC_Dashboard.git

## 2. Open the Project Folder

    cd Enterprise_SOC_Dashboard

## 3. Create a Python Virtual Environment

    python -m venv venv

## 4. Activate the Virtual Environment

### Windows

    venv\Scripts\activate

### Linux / macOS

    source venv/bin/activate

## 5. Install Required Packages

Install the required Python packages for the backend.

    pip install fastapi uvicorn requests psycopg2-binary python-dotenv

---

#  PostgreSQL Setup

Install PostgreSQL and create a database for the SOC Dashboard.

Example:

    CREATE DATABASE soc_dashboard;

Create a PostgreSQL user if required and provide the database credentials through the environment configuration.

The project uses PostgreSQL for storing application and security-related data.

---

#  Environment Configuration

Create a `.env` file inside the `backend` directory.

Example configuration:

    MISP_URL=YOUR_MISP_URL
    MISP_API_KEY=YOUR_MISP_API_KEY
    MISP_VERIFY_SSL=false
    MISP_TIMEOUT=10

    SOC_DB_HOST=localhost
    SOC_DB_PORT=5432
    SOC_DB_NAME=soc_dashboard
    SOC_DB_USER=YOUR_DATABASE_USER
    SOC_DB_PASSWORD=YOUR_DATABASE_PASSWORD

### Important

Never upload your real:

- MISP API key
- Database password
- `.env` file
- Other private credentials

to GitHub.

The `.env` file is excluded using `.gitignore`.

---

#  Initialize the Database

The project includes:

    backend/init_db.py

Run the database initialization script according to the project configuration.

This prepares the required database structure for the application.

---

#  Running the Backend

Move into the backend directory:

    cd backend

Start the FastAPI server:

    uvicorn main:app --host 0.0.0.0 --port 8000

The backend will run on:

    http://localhost:8000

---

#  FastAPI API Documentation

FastAPI automatically provides interactive API documentation.

Open:

    http://localhost:8000/docs

The documentation can be used to test and understand the available API endpoints.

---

#  Running the Frontend

Open the frontend project:

    frontend/index.html

The frontend communicates with the FastAPI backend.

For local development, make sure the backend is running before opening the dashboard.

---

#  Main API Functions

The backend provides REST API endpoints for different parts of the SOC Dashboard.

## Health

    GET /api/health

Used to check backend availability.

## Authentication

    POST /api/signup

Used to create a user account.

    POST /api/login

Used for user login.

    GET /api/me

Used to access the current user information.

    GET /api/users

Used to view available users.

    DELETE /api/users/{username}

Used to remove a user.

---

#  Alert APIs

    GET /api/alerts

Used to retrieve security alerts.

    GET /api/statistics

Used to retrieve alert statistics.

---

#  Incident APIs

The system provides APIs for incident management.

These operations include:

    GET
    POST
    PUT
    DELETE

Incident APIs are used to:

- View incidents
- Create incidents
- Update incidents
- Delete incidents

---

#  IOC APIs

The system provides APIs for IOC management.

These operations include:

    GET
    POST
    PUT
    DELETE

IOC APIs are used to:

- View IOCs
- Add IOCs
- Update IOCs
- Delete IOCs

---

#  Threat Intelligence API

    GET /api/threat-intel

This endpoint provides threat intelligence information available through the MISP integration.

---

#  Dashboard

The SOC dashboard provides a centralized view of the security environment.

The main dashboard includes:

- Security alert information
- Alert statistics
- Alert search
- Alert filtering
- Investigation options
- Incident management
- IOC management
- Threat intelligence
- Backend connection status

---

#  Alert Investigation

The alert investigation section allows the analyst to select an alert and view more information about it.

The analyst can inspect details such as:

- Source
- Destination
- Ports
- Protocol
- Severity
- Category
- Signature
- Network interface
- Action
- Other available alert information

This provides a simple way to understand and investigate individual security alerts.

---

#  Security Monitoring

Suricata acts as the security monitoring component of the system.

It can inspect network traffic and generate security alerts based on configured rules.

The SOC Dashboard provides the interface for viewing and investigating the available security alerts.

---

#  Threat Intelligence

MISP is integrated with the backend to provide threat intelligence information.

The dashboard can access the available information through the threat intelligence API.

This gives the security analyst another source of security information while investigating alerts.

---

#  Project Output

The final system provides a centralized web-based SOC interface where a security analyst can:

1. Log in to the system.
2. View security alerts.
3. Check alert statistics.
4. Search for alerts.
5. Filter alerts.
6. Investigate individual alerts.
7. Manage security incidents.
8. Manage IOCs.
9. View threat intelligence.
10. Check backend connection status.

---

#  Advantages

- Centralized security monitoring interface
- Simple and user-friendly dashboard
- Easy alert investigation
- Searchable security alerts
- Alert filtering
- Incident management
- IOC management
- Threat intelligence integration
- PostgreSQL-based data storage
- REST API architecture
- FastAPI backend
- Web-based interface
- Easy to extend in the future

---

#  Applications

The Enterprise SOC Dashboard can be used in:

- Enterprise security operations
- College and university networks
- Small and medium organizations
- Network security monitoring
- Security operation centers
- Cybersecurity laboratories
- Security monitoring demonstrations
- Academic cybersecurity projects

---

#  Team

This project was developed as an academic cybersecurity project.

### Team Members

- Rakesh
- Bhargava Reddy
- Sarath Kumar
- Tharun kumar

---

**Domain:** Cybersecurity

---

#  Project Status

The project has been developed as a working Enterprise SOC Dashboard with:

- FastAPI backend
- PostgreSQL database
- Suricata security monitoring
- MISP threat intelligence integration
- Web-based dashboard
- Alert monitoring
- Alert investigation
- Incident management
- IOC management
- REST APIs

The project is maintained using Git and GitHub.

---

#  Security Note

Sensitive information must not be committed to the GitHub repository.

Do not upload:

- `.env`
- API keys
- Database passwords
- Personal credentials
- Private configuration files
- Local databases
- Temporary files

Always use environment variables for sensitive configuration.

---

# ⭐ Enterprise SOC Dashboard

### Centralized Security Monitoring
### Alert Investigation
### Incident Management
### IOC Management
### Threat Intelligence

**Built for practical cybersecurity monitoring and academic demonstration.**
