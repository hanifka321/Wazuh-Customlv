const API_BASE_URL = 'http://localhost:8000';

const app = {
    rules: [],
    currentRule: null,
    currentRuleId: null,
    editorModal: null,
    deleteModal: null,
    ruleToDelete: null,

    async init() {
        this.editorModal = new bootstrap.Modal(document.getElementById('ruleEditorModal'));
        this.deleteModal = new bootstrap.Modal(document.getElementById('deleteConfirmModal'));
        
        await this.loadRules();
    },

    async loadRules() {
        UI.showLoading('Loading rules...');
        
        try {
            const response = await fetch(`${API_BASE_URL}/rules`);
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            this.rules = await response.json();
            UI.renderRulesTable(this.rules);
        } catch (error) {
            console.error('Failed to load rules:', error);
            UI.showError(`Failed to load rules: ${error.message}`);
        }
    },

    viewRule(ruleId) {
        const rule = this.rules.find(r => r.id === ruleId);
        if (rule) {
            UI.renderRuleDetail(rule);
        }
    },

    showNewRuleModal() {
        this.currentRuleId = null;
        this.currentRule = null;
        
        document.getElementById('ruleEditorModalTitle').textContent = 'New Rule';
        document.getElementById('ruleYamlInput').value = this.getTemplateYaml();
        document.getElementById('sampleLogsInput').value = this.getTemplateLogs();
        document.getElementById('saveRuleBtn').textContent = 'Save Rule';
        
        UI.hideValidationMessages();
        document.getElementById('testResults').innerHTML = '';
        
        this.editorModal.show();
    },

    async editRule(ruleId) {
        const rule = this.rules.find(r => r.id === ruleId);
        if (!rule) return;

        this.currentRuleId = ruleId;
        this.currentRule = rule;
        
        document.getElementById('ruleEditorModalTitle').textContent = `Edit Rule: ${rule.name}`;
        document.getElementById('ruleYamlInput').value = UI.ruleToYaml(rule);
        document.getElementById('saveRuleBtn').textContent = 'Update Rule';
        
        UI.hideValidationMessages();
        document.getElementById('testResults').innerHTML = '';
        
        this.editorModal.show();
    },

    async duplicateRule(ruleId) {
        const rule = this.rules.find(r => r.id === ruleId);
        if (!rule) return;

        this.currentRuleId = null;
        this.currentRule = null;
        
        const duplicatedYaml = UI.ruleToYaml(rule).replace(
            `id: "${rule.id}"`,
            `id: "${rule.id}-copy"`
        ).replace(
            `name: "${rule.name}"`,
            `name: "${rule.name} (Copy)"`
        );
        
        document.getElementById('ruleEditorModalTitle').textContent = 'Duplicate Rule';
        document.getElementById('ruleYamlInput').value = duplicatedYaml;
        document.getElementById('saveRuleBtn').textContent = 'Save Rule';
        
        UI.hideValidationMessages();
        
        this.editorModal.show();
    },

    deleteRule(ruleId, ruleName) {
        this.ruleToDelete = ruleId;
        document.getElementById('deleteRuleName').textContent = ruleName;
        this.deleteModal.show();
    },

    async confirmDelete() {
        if (!this.ruleToDelete) return;

        try {
            const response = await fetch(`${API_BASE_URL}/rules/${this.ruleToDelete}`, {
                method: 'DELETE'
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            this.deleteModal.hide();
            await this.loadRules();
            
            document.getElementById('ruleDetail').innerHTML = '<p class="text-muted">Select a rule to view details</p>';
        } catch (error) {
            console.error('Failed to delete rule:', error);
            alert(`Failed to delete rule: ${error.message}`);
        }
    },

    async validateRule() {
        const ruleYaml = document.getElementById('ruleYamlInput').value;
        
        if (!ruleYaml.trim()) {
            UI.renderValidationErrors(['Rule YAML is empty']);
            return;
        }

        try {
            const response = await fetch(`${API_BASE_URL}/rules/validate`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ rule_yaml: ruleYaml })
            });

            const result = await response.json();

            if (result.valid) {
                UI.renderValidationErrors([]);
                UI.showValidationSuccess();
            } else {
                UI.renderValidationErrors(result.errors);
            }
        } catch (error) {
            console.error('Validation error:', error);
            UI.renderValidationErrors([`Request failed: ${error.message}`]);
        }
    },

    async saveRule() {
        const ruleYaml = document.getElementById('ruleYamlInput').value;
        
        if (!ruleYaml.trim()) {
            UI.renderValidationErrors(['Rule YAML is empty']);
            return;
        }

        try {
            const validateResponse = await fetch(`${API_BASE_URL}/rules/validate`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ rule_yaml: ruleYaml })
            });

            const validateResult = await validateResponse.json();

            if (!validateResult.valid) {
                UI.renderValidationErrors(validateResult.errors);
                return;
            }

            let ruleData;
            try {
                ruleData = this.parseYamlToJson(ruleYaml);
            } catch (e) {
                UI.renderValidationErrors([`YAML parsing error: ${e.message}`]);
                return;
            }
            
            let response;
            if (this.currentRuleId) {
                response = await fetch(`${API_BASE_URL}/rules/${this.currentRuleId}`, {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(ruleData)
                });
            } else {
                response = await fetch(`${API_BASE_URL}/rules`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(ruleData)
                });
            }

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.detail || `HTTP error! status: ${response.status}`);
            }

            this.editorModal.hide();
            await this.loadRules();
            
            const savedRule = await response.json();
            this.viewRule(savedRule.id);
        } catch (error) {
            console.error('Save error:', error);
            UI.renderValidationErrors([`Save failed: ${error.message}`]);
        }
    },

    async runTest() {
        const ruleYaml = document.getElementById('ruleYamlInput').value;
        const sampleLogs = document.getElementById('sampleLogsInput').value;
        
        if (!ruleYaml.trim()) {
            document.getElementById('testResults').innerHTML = '<div class="alert alert-danger">Rule YAML is empty</div>';
            return;
        }
        
        if (!sampleLogs.trim()) {
            document.getElementById('testResults').innerHTML = '<div class="alert alert-danger">Sample logs are empty</div>';
            return;
        }

        document.getElementById('testResults').innerHTML = '<div class="alert alert-info">Running test...</div>';

        try {
            const response = await fetch(`${API_BASE_URL}/rules/test`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    rule_yaml: ruleYaml,
                    sample_logs: sampleLogs
                })
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.detail || `HTTP error! status: ${response.status}`);
            }

            const result = await response.json();
            UI.renderTestResults(result);
        } catch (error) {
            console.error('Test error:', error);
            document.getElementById('testResults').innerHTML = `
                <div class="alert alert-danger">
                    <h6>Test Error</h6>
                    <p class="mb-0">${UI.escapeHtml(error.message)}</p>
                </div>
            `;
        }
    },

    getTemplateYaml() {
        return `id: "rule-001"
name: "SSH Brute Force followed by Successful Login"
by: ["data.srcip"]
within_seconds: 300
sequence:
  - as: "failed_login"
    where: "rule.id == '5710'"
  - as: "failed_login2"
    where: "rule.id == '5710'"
  - as: "failed_login3"
    where: "rule.id == '5710'"
  - as: "success_login"
    where: "rule.id == '5715'"
output:
  timestamp_ref: "success_login"
  format: "Detected brute force sequence from {data.srcip}"`;
    },

    getTemplateLogs() {
        return `{"timestamp":"2025-12-06T22:17:00","rule":{"id":"5710","description":"SSH authentication failed"},"agent":{"name":"server1"},"data":{"srcip":"192.168.1.100","dstuser":"admin"}}
{"timestamp":"2025-12-06T22:17:05","rule":{"id":"5710","description":"SSH authentication failed"},"agent":{"name":"server1"},"data":{"srcip":"192.168.1.100","dstuser":"admin"}}
{"timestamp":"2025-12-06T22:17:10","rule":{"id":"5710","description":"SSH authentication failed"},"agent":{"name":"server1"},"data":{"srcip":"192.168.1.100","dstuser":"admin"}}
{"timestamp":"2025-12-06T22:17:15","rule":{"id":"5715","description":"SSH authentication success"},"agent":{"name":"server1"},"data":{"srcip":"192.168.1.100","dstuser":"admin"}}`;
    },

    parseYamlToJson(yamlStr) {
        const lines = yamlStr.split('\n');
        const result = {};
        const stack = [{ obj: result, indent: -1, isArray: false }];
        let lastKey = null;
        
        for (let i = 0; i < lines.length; i++) {
            let line = lines[i].replace(/\r/, '');
            if (!line.trim() || line.trim().startsWith('#')) continue;
            
            const indent = line.search(/\S/);
            const trimmed = line.trim();
            
            while (stack.length > 1 && indent <= stack[stack.length - 1].indent) {
                stack.pop();
            }
            
            const current = stack[stack.length - 1].obj;
            
            if (trimmed.startsWith('- ')) {
                const itemStr = trimmed.substring(2);
                
                if (!Array.isArray(current[lastKey])) {
                    if (lastKey && typeof current[lastKey] === 'object' && Object.keys(current[lastKey]).length === 0) {
                        current[lastKey] = [];
                    }
                }
                
                const targetArray = Array.isArray(current) ? current : (lastKey && Array.isArray(current[lastKey]) ? current[lastKey] : null);
                
                if (targetArray) {
                    if (itemStr.includes(':')) {
                        const item = {};
                        targetArray.push(item);
                        stack.push({ obj: item, indent, isArray: false });
                        
                        const [key, value] = itemStr.split(':').map(s => s.trim());
                        if (value) {
                            item[key] = this.parseValue(value);
                        }
                        lastKey = key;
                    } else {
                        targetArray.push(this.parseValue(itemStr));
                    }
                }
            } else if (trimmed.includes(':')) {
                const colonIndex = trimmed.indexOf(':');
                const key = trimmed.substring(0, colonIndex).trim();
                const value = trimmed.substring(colonIndex + 1).trim();
                
                if (!value || value === '') {
                    const nextLine = i + 1 < lines.length ? lines[i + 1] : '';
                    const nextIndent = nextLine.search(/\S/);
                    const nextTrimmed = nextLine.trim();
                    
                    if (nextTrimmed.startsWith('- ')) {
                        current[key] = [];
                        stack.push({ obj: current, indent, isArray: true });
                        lastKey = key;
                    } else {
                        current[key] = {};
                        stack.push({ obj: current[key], indent, isArray: false });
                        lastKey = null;
                    }
                } else if (value.startsWith('[')) {
                    current[key] = JSON.parse(value);
                    lastKey = key;
                } else {
                    current[key] = this.parseValue(value);
                    lastKey = key;
                }
            }
        }
        
        return result;
    },

    parseValue(str) {
        str = str.trim();
        if (str.startsWith('"') && str.endsWith('"')) {
            return str.slice(1, -1);
        }
        if (str.startsWith("'") && str.endsWith("'")) {
            return str.slice(1, -1);
        }
        if (!isNaN(str) && str !== '') {
            return Number(str);
        }
        if (str === 'true') return true;
        if (str === 'false') return false;
        if (str === 'null') return null;
        return str;
    }
};

// Initialize app when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    app.init();
});
