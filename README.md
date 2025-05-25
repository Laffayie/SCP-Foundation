# SCP Control Panel

A web-based control panel for managing SCP Foundation operations, with role-based access control and comprehensive features for O5 members, scientists, and security personnel.

## Features

- Role-based access control (O5, Scientist, Security)
- SCP management and tracking
- Task management system
- User profiles with customizable themes
- Statistics and reporting
- Responsive design with light/dark theme support

## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

## Installation

1. Clone the repository:

```bash
git clone <repository-url>
cd scp-control-panel
```

2. Create a virtual environment:

```bash
python -m venv venv
```

3. Activate the virtual environment:

- Windows:

```bash
venv\Scripts\activate
```

- Linux/Mac:

```bash
source venv/bin/activate
```

4. Install dependencies:

```bash
pip install -r requirements.txt
```

5. Initialize the database:

```bash
flask db init
flask db migrate
flask db upgrade
```

## Running the Application

1. Start the Flask development server:

```bash
python app.py
```

2. Open your web browser and navigate to:

```
http://localhost:5000
```

## Default Users

The application comes with the following default users:

- O5 Member:

  - Username: o5_admin
  - Password: O5Admin123!

- Scientist:

  - Username: scientist
  - Password: Scientist123!

- Security:
  - Username: security
  - Password: Security123!

## Directory Structure

```
scp-control-panel/
├── app.py              # Main application file
├── requirements.txt    # Python dependencies
├── static/            # Static files
│   ├── css/          # CSS stylesheets
│   ├── js/           # JavaScript files
│   └── uploads/      # User uploads
├── templates/         # HTML templates
└── instance/         # Instance-specific files
    └── scp.db        # SQLite database
```

## Security Features

- Password hashing using Werkzeug
- Role-based access control
- Session management
- CSRF protection
- Secure file uploads

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
