# Gravitee Customer Data Extractor

## Overview
This project provides an easy way to extract data from multiple Gravitee API Management instances into JSON files. It is packaged with Docker and VS Code Dev Containers to make setup easy and consistent across machines.

---

## Prerequisites
- [Docker Desktop](https://www.docker.com/products/docker-desktop)
- [Visual Studio Code](https://code.visualstudio.com/)
- [Dev Containers Extension for VS Code](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers)

---

## Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/geoffgrav/cmdb.git
cd cmdb
```

Or via VS Code:
- Open **Command Palette** (`Cmd+Shift+P` on Mac, `Ctrl+Shift+P` on Windows/Linux)
- Type `Git: Clone`
- Enter: `https://github.com/geoffgrav/cmdb.git`
- Open the cloned folder.

### 2. Open in Dev Container
- VS Code will prompt: **"Reopen in Container"**
- Click **"Reopen in Container"**

If not:
- Open Command Palette.
- Type `Dev Containers: Reopen in Container` and select it.

### 3. Create `.env` file
In the project root, create a file named `.env` with the following content:

```bash
CUSTOMER_CSV_PATH=./customers.csv
```

This tells the tool where to find your customer list.

### 4. Update `customers.csv`
Edit the `customers.csv` file with the following format:

| gravitee_url | customer_name | api_token |
|--------------|---------------|-----------|
| https://demo-apim-api.customer1.gravitee.xyz | Customer1 | your_token_here |

Add each customer you want to extract data from.

### 5. Activate the Python Virtual Environment
In the VS Code terminal inside the container:
```bash
source venv/bin/activate
```
You will see `(venv)` appear in your prompt.

### 6. Run the Extraction Script
```bash
python extract_gravitee_data.py
```

The tool will:
- Connect to each Gravitee instance in your CSV.
- Extract data.
- Save JSON output files into the `gravitee_data/` folder.

---

## Useful Commands

```bash
# Activate venv (inside container)
source venv/bin/activate

# Run the script
python extract_gravitee_data.py
```

---

## Troubleshooting
- **No "Reopen in Container" prompt?** Use the Command Palette manually.
- **Permission errors?** Make sure your `customers.csv` is present and readable.
- **Virtual environment errors?** Always make sure you're inside the container before running `source venv/bin/activate`.

---

## Summary
This tool makes it easy for anyone to pull Gravitee customer data safely and repeatably, with almost no setup steps beyond Docker, VS Code, and editing a simple CSV file.

---

Happy extracting! 🚀

