# Sequence Rule Engine Frontend

This is the web UI for managing and testing sequence rules in the Wazuh Sequence Rule Engine.

## Features

- **Rules List**: View all rules with key information (name, ID, grouping fields, time window, step count)
- **Rule Detail View**: See complete rule details including YAML definition and summary
- **Rule Editor**: Create and edit rules with YAML syntax
- **Rule Validation**: Validate rules before saving
- **Rule Testing**: Test rules against sample JSONL logs
- **CRUD Operations**: Create, Read, Update, Delete rules
- **Duplicate Rules**: Quickly create new rules based on existing ones
- **Dark Mode UI**: Modern dark-themed interface using Bootstrap 5

## How to Run

1. **Start the Backend API**:
   ```bash
   cd sequence_rule_engine
   uvicorn backend.main:app --reload
   ```
   The API will be available at `http://localhost:8000`

2. **Serve the Frontend**:
   You can use any HTTP server. For example, using Python:
   ```bash
   cd sequence_rule_engine/frontend
   python -m http.server 8080
   ```
   Or use the built-in live server in VS Code.

3. **Open in Browser**:
   Navigate to `http://localhost:8080` (or your server's URL)

## Usage

### Viewing Rules

- Rules are displayed in the left panel
- Click on a rule to view its details in the right panel
- Details include rule metadata, sequence steps, and YAML definition

### Creating a New Rule

1. Click the "New Rule" button
2. Enter your rule definition in YAML format
3. Click "Validate" to check for errors
4. Click "Save Rule" to create the rule

### Editing a Rule

1. Click the "Edit" button for a rule
2. Modify the YAML definition
3. Click "Validate" to check for errors
4. Click "Update Rule" to save changes

### Testing a Rule

1. Open the rule editor (new or edit)
2. Switch to the "Test" tab
3. Paste JSONL formatted logs in the sample logs textarea
4. Click "Run Test"
5. View matches and step-by-step trace

### Duplicating a Rule

1. Click the "Duplicate" button for a rule
2. The editor will open with a copy of the rule
3. Modify the ID and name
4. Click "Save Rule" to create the duplicate

### Deleting a Rule

1. Click the "Delete" button for a rule
2. Confirm the deletion in the popup

## API Endpoints Used

- `GET /rules` - List all rules
- `POST /rules` - Create a new rule
- `GET /rules/{id}` - Get a specific rule
- `PUT /rules/{id}` - Update a rule
- `DELETE /rules/{id}` - Delete a rule
- `POST /rules/validate` - Validate rule YAML
- `POST /rules/test` - Test rule against sample logs

## Files

- **index.html**: Main HTML structure and layout
- **styles.css**: Dark mode styling and custom CSS
- **components.js**: Reusable UI rendering functions
- **app.js**: Main application logic and API interactions

## Rule Format

Rules are defined in YAML with the following structure:

```yaml
id: "rule-001"
name: "SSH Brute Force followed by Successful Login"
by: ["data.srcip"]
within_seconds: 300
sequence:
  - as: "failed_login"
    where: "rule.id == '5710'"
  - as: "failed_login2"
    where: "rule.id == '5710'"
  - as: "success_login"
    where: "rule.id == '5715'"
output:
  timestamp_ref: "success_login"
  format: "Detected brute force sequence from {data.srcip}"
```

## Sample JSONL Logs Format

```jsonl
{"timestamp":"2025-12-06T22:17:00","rule":{"id":"5710"},"data":{"srcip":"192.168.1.100"}}
{"timestamp":"2025-12-06T22:17:05","rule":{"id":"5710"},"data":{"srcip":"192.168.1.100"}}
{"timestamp":"2025-12-06T22:17:10","rule":{"id":"5715"},"data":{"srcip":"192.168.1.100"}}
```

## Browser Compatibility

- Modern browsers (Chrome, Firefox, Safari, Edge)
- Requires JavaScript enabled
- Uses Bootstrap 5 and ES6+ features
