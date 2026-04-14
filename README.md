# aigeeks_osint

## What the Application Is

`aigeeks_osint` is a lightweight OSINT intelligence platform that performs asynchronous investigations against a target name or identifier, gathers findings from multiple sources, and generates a polished PDF report.

The application uses:
- a Flask-based API backend (`server.py`)
- a modular investigation engine (`osint_engine.py`)
- a PDF report generator (`report_generator.py`)
- a frontend UI (`index.html`)

## Application Features

- **Async investigation workflow**
  - Sends investigation requests to `/api/investigate`
  - Uses background threads so requests return immediately
  - Polls progress via `/api/status/<job_id>`

- **Modular adapter-based search engine**
  - Runs multiple data-gathering adapters in sequence
  - Includes social, technical, and presence discovery logic
  - Uses both HTML search and Selenium-based scraping where needed

- **PDF report generation**
  - Creates a professional report with:
    - cover page
    - executive summary
    - categorized findings
    - audit trail
  - Uses ReportLab for layout and styling

## How to Clone and Setup

```bash
git clone https://github.com/<your-org>/aigeeks_osint.git
cd aigeeks_osint
```

### Create a virtual environment

```bash
python -m venv venv
```

### Activate the virtual environment

- On Windows:

```bash
venv\Scripts\activate
```

- On macOS / Linux:

```bash
source venv/bin/activate
```
```

### Install dependencies

```bash
pip install -r requirements.txt
```

### Run the application

```bash
python server.py
```

The Flask API listens on `http://0.0.0.0:5050` by default.

## Notes

- The backend stores generated PDF reports under the `reports/` directory.
- Job state is kept in-memory, so restarting the server resets active jobs.
- Open `index.html` in your browser or serve it from a local static server to use the frontend.

