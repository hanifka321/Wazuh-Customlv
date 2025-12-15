# Milestone 4 Summary: Rule Editor UI & Test Runner

## Overview

Milestone 4 implements a complete web-based UI for managing and testing sequence rules in the Wazuh Sequence Rule Engine, along with backend validation and testing capabilities.

## Completed Features

### 1. Frontend Structure ✅

Created a complete frontend application in `sequence_rule_engine/frontend/`:

- **index.html**: Main page with two-panel layout (rules list + detail view), modals for editing/testing
- **styles.css**: Dark mode themed styling using CSS custom properties
- **app.js**: Main application logic with API integration and YAML parsing
- **components.js**: Reusable UI rendering functions for rules, validation, and test results
- **README.md**: Comprehensive documentation for the frontend
- **start_frontend.sh**: Convenience script to serve the frontend

### 2. Rules List Page ✅

**Left Panel - Rules Table:**
- Displays all rules with columns: Name, ID, By fields, Within (seconds), Step count
- Actions: New, Edit, Delete, Duplicate buttons
- Click on row to view details
- Responsive table with hover effects

**Right Panel - Rule Detail:**
- Read-only view of selected rule
- Shows rule summary with metadata
- Lists sequence steps with aliases and where clauses
- Displays full YAML definition in formatted code block
- Updates when clicking different rules

### 3. Rule Editor + Test Modal ✅

**Modal with Two Tabs:**

**Editor Tab:**
- Textarea for YAML rule input with monospace font
- Template YAML provided for new rules
- "Validate" button to check rule without saving
- "Save Rule" button to create/update rules
- Validation error messages displayed below textarea
- Success message on successful validation

**Test Tab:**
- Readonly rule YAML (from editor tab)
- Textarea for sample JSONL logs
- Template logs provided
- "Run Test" button to execute test
- Results area showing:
  - Number of events processed
  - Number of matches found
  - Match details table with timestamp, rule name, event IDs
  - Step-by-step trace showing which steps matched
  - Error messages for invalid input

### 4. Validation Endpoint ✅

**POST /rules/validate**
- Request: `{rule_yaml: str}`
- Response: `{valid: bool, errors: [str]}`
- Validates:
  - YAML syntax
  - Required fields (id, name, by, within_seconds, sequence, output)
  - Field types (by and sequence must be lists)
  - Minimum 2 sequence steps
  - Each step has "as" and "where" fields
  - Pydantic model validation for complete structure
- Returns clear, specific error messages

### 5. Test Runner Backend ✅

**POST /rules/test**
- Request: `{rule_yaml: str, sample_logs: str}`
- Response: `{success: bool, matches: [...], events_processed: int, error?: str}`
- Functionality:
  - Parses JSONL logs
  - Groups events by specified fields
  - Matches sequences with time window validation
  - Returns detailed match information including step traces
  - Handles errors gracefully

**Engine Components:**
- **matcher.py**: RuleMatcher class with sequence matching logic
  - Groups events by "by" fields
  - Evaluates where expressions for each step
  - Validates time windows
  - Tracks matched event IDs
  - Provides step-by-step trace
- **SequenceMatch**: Data class for match results

### 6. CRUD Operations ✅

All operations fully functional and tested:

- **Create**: New rule via editor modal
- **Read**: List all rules, view individual rule details
- **Update**: Edit existing rule via editor modal
- **Delete**: Delete with confirmation modal
- **Duplicate**: Create copy of existing rule with modified ID

### 7. Testing ✅

Comprehensive test coverage:

- **test_sequence_api.py**: 8 tests for validation and test endpoints
  - Valid rule validation
  - Invalid rules (missing fields, bad syntax, insufficient steps)
  - Test with matching/non-matching logs
  - Error handling for invalid YAML and JSONL

- **test_sequence_matcher.py**: 9 tests for matcher engine
  - Simple sequence matching
  - No matches scenarios
  - Partial sequences
  - Multiple sequences
  - Grouping by fields
  - Time window validation
  - Invalid input handling

- **test_sequence_e2e.py**: 3 end-to-end tests
  - Full workflow (create → validate → test → update → delete)
  - Validation error catching
  - Test endpoint error handling

**All 20 tests passing** ✅

### 8. Additional Features ✅

- **CORS Support**: Added CORS middleware to backend for frontend access
- **Dark Mode UI**: Professional dark theme using Bootstrap 5
- **Client-Side YAML Parser**: Custom YAML-to-JSON parser for frontend
- **Template Data**: Pre-filled templates for rules and sample logs
- **Error Handling**: Comprehensive error messages and user feedback
- **Responsive Design**: Works on various screen sizes
- **Sample Rule**: Pre-created rule-001.yaml for testing

## File Structure

```
sequence_rule_engine/
├── backend/
│   ├── main.py              # FastAPI app with all endpoints + CORS
│   ├── models.py            # Pydantic models (Rule, Step, Output)
│   └── storage.py           # File-based rule storage
├── engine/
│   ├── parser.py            # JSONL parser
│   ├── extractor.py         # Field extractor
│   ├── where_parser.py      # Where expression parser
│   ├── matcher.py           # NEW: Sequence matcher
│   └── models.py            # Event model
├── frontend/
│   ├── index.html           # NEW: Main UI
│   ├── styles.css           # NEW: Dark mode styling
│   ├── app.js               # NEW: Application logic
│   ├── components.js        # NEW: UI components
│   ├── README.md            # NEW: Frontend docs
│   └── start_frontend.sh    # NEW: Convenience script
├── rules/
│   └── rule-001.yaml        # NEW: Sample rule
├── start_server.sh          # NEW: Backend startup script
└── README.md                # Updated with M4 info

tests/
├── test_sequence_api.py     # NEW: API endpoint tests (8 tests)
├── test_sequence_matcher.py # NEW: Matcher engine tests (9 tests)
└── test_sequence_e2e.py     # NEW: End-to-end tests (3 tests)
```

## Usage

### Starting the System

1. **Backend**:
   ```bash
   cd sequence_rule_engine
   ./start_server.sh
   # Or: uvicorn backend.main:app --reload
   ```
   API available at http://localhost:8000
   API docs at http://localhost:8000/docs

2. **Frontend**:
   ```bash
   cd sequence_rule_engine/frontend
   ./start_frontend.sh
   # Or: python3 -m http.server 8080
   ```
   UI available at http://localhost:8080

### Using the UI

1. **View Rules**: Rules appear in left panel, click to see details
2. **Create Rule**: Click "New Rule" → Enter YAML → Validate → Save
3. **Edit Rule**: Click "Edit" on rule → Modify YAML → Validate → Update
4. **Test Rule**: In editor modal → "Test" tab → Paste logs → Run Test
5. **Duplicate Rule**: Click "Duplicate" → Modify ID/name → Save
6. **Delete Rule**: Click "Delete" → Confirm

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /health | Health check |
| GET | /rules | List all rules |
| POST | /rules | Create new rule |
| GET | /rules/{id} | Get rule by ID |
| PUT | /rules/{id} | Update rule |
| DELETE | /rules/{id} | Delete rule |
| POST | /rules/validate | Validate rule YAML |
| POST | /rules/test | Test rule against logs |

## Acceptance Criteria Status

✅ Can see list of all rules in left panel
✅ Can create new rule via editor
✅ Can edit existing rule
✅ Can delete rule
✅ Can paste YAML and validate
✅ Can paste sample logs and run test
✅ Test results show matches with timestamp + name + ids
✅ UI responsive and functional
✅ All CRUD operations work end-to-end
✅ Validation shows clear error messages
✅ Step-by-step trace in test results (bonus feature)
✅ Dark mode UI (bonus feature)
✅ Template data provided (bonus feature)

## Technical Highlights

1. **No External Dependencies**: Frontend uses pure HTML/CSS/JS with Bootstrap CDN
2. **Custom YAML Parser**: Implemented in JavaScript for client-side parsing
3. **Dark Mode**: Professional theme with CSS custom properties
4. **Comprehensive Testing**: 20 tests covering all functionality
5. **Error Handling**: Graceful error messages throughout
6. **CORS Support**: Properly configured for cross-origin requests
7. **Type Safety**: Pydantic models ensure data integrity
8. **Modular Code**: Separated concerns (UI, API, engine, storage)

## Demo Scenario

1. Open frontend at http://localhost:8080
2. See existing rule-001 in the list
3. Click on it to view details
4. Click "Edit" to modify it
5. Switch to "Test" tab
6. Paste sample logs (template provided)
7. Click "Run Test" to see matches
8. See step-by-step trace of matched events
9. Click "Duplicate" to create a variant
10. Modify the new rule and save
11. Test the new rule
12. Delete the duplicate rule

## Known Limitations

1. **YAML Parser**: The JavaScript YAML parser is simplified and may not handle all YAML edge cases (use backend validation for complex cases)
2. **Storage**: Rules stored as files (SQLite storage stubbed but not implemented)
3. **Authentication**: No authentication on API (suitable for internal use)
4. **Real-time Updates**: UI doesn't auto-refresh when rules change externally

## Future Enhancements

- Syntax highlighting for YAML editor
- Real-time validation as you type
- Import/export rules in bulk
- Rule templates library
- Visual sequence builder (drag-and-drop)
- Real-time log streaming integration
- Rule testing history
- Performance metrics dashboard

## Conclusion

Milestone 4 successfully delivers a complete, functional web UI for managing and testing sequence rules. All acceptance criteria are met, with additional bonus features. The system is well-tested, documented, and ready for use.
