const UI = {
    renderRulesTable(rules) {
        const tbody = document.getElementById('rulesTableBody');
        
        if (rules.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No rules found</td></tr>';
            return;
        }

        tbody.innerHTML = rules.map(rule => `
            <tr onclick="app.viewRule('${rule.id}')">
                <td>${this.escapeHtml(rule.name)}</td>
                <td><code>${this.escapeHtml(rule.id)}</code></td>
                <td>${this.renderByFields(rule.by)}</td>
                <td>${rule.within_seconds}</td>
                <td><span class="badge bg-info">${rule.sequence.length} steps</span></td>
                <td class="action-buttons" onclick="event.stopPropagation()">
                    <button class="btn btn-sm btn-outline-primary" onclick="app.editRule('${rule.id}')">Edit</button>
                    <button class="btn btn-sm btn-outline-warning" onclick="app.duplicateRule('${rule.id}')">Duplicate</button>
                    <button class="btn btn-sm btn-outline-danger" onclick="app.deleteRule('${rule.id}', '${this.escapeHtml(rule.name)}')">Delete</button>
                </td>
            </tr>
        `).join('');
    },

    renderByFields(byArray) {
        if (!byArray || byArray.length === 0) {
            return '<span class="text-muted">none</span>';
        }
        return byArray.map(field => `<code class="small">${this.escapeHtml(field)}</code>`).join(', ');
    },

    renderRuleDetail(rule) {
        const container = document.getElementById('ruleDetail');
        
        const yamlStr = this.ruleToYaml(rule);
        
        container.innerHTML = `
            <div class="rule-summary">
                <h5>${this.escapeHtml(rule.name)}</h5>
                <p class="text-muted mb-0"><small>ID: ${this.escapeHtml(rule.id)}</small></p>
                
                <h6>Grouping Fields</h6>
                <p>${this.renderByFields(rule.by)}</p>
                
                <h6>Time Window</h6>
                <p>${rule.within_seconds} seconds</p>
                
                <h6>Sequence Steps</h6>
                ${this.renderSequenceSteps(rule.sequence)}
                
                <h6>Output</h6>
                <p>Timestamp Ref: <code>${this.escapeHtml(rule.output.timestamp_ref)}</code></p>
                <p>Format: <code>${this.escapeHtml(rule.output.format)}</code></p>
            </div>
            
            <h6>YAML Definition</h6>
            <pre><code>${this.escapeHtml(yamlStr)}</code></pre>
        `;
    },

    renderSequenceSteps(steps) {
        return `<ol class="mb-0">${steps.map(step => `
            <li>
                <strong>${this.escapeHtml(step.as)}</strong>: 
                <code class="small">${this.escapeHtml(step.where)}</code>
            </li>
        `).join('')}</ol>`;
    },

    renderValidationErrors(errors) {
        const container = document.getElementById('validationErrors');
        if (errors.length === 0) {
            container.classList.add('d-none');
            return;
        }

        container.classList.remove('d-none');
        container.innerHTML = `
            <h6>Validation Errors:</h6>
            <ul class="mb-0">
                ${errors.map(err => `<li>${this.escapeHtml(err)}</li>`).join('')}
            </ul>
        `;
    },

    showValidationSuccess() {
        const container = document.getElementById('validationSuccess');
        container.classList.remove('d-none');
        setTimeout(() => {
            container.classList.add('d-none');
        }, 3000);
    },

    hideValidationMessages() {
        document.getElementById('validationErrors').classList.add('d-none');
        document.getElementById('validationSuccess').classList.add('d-none');
    },

    renderTestResults(result) {
        const container = document.getElementById('testResults');
        
        if (!result.success) {
            container.innerHTML = `
                <div class="alert alert-danger">
                    <h6>Test Error</h6>
                    <p class="mb-0">${this.escapeHtml(result.error)}</p>
                </div>
            `;
            return;
        }

        const matchCount = result.matches.length;
        const eventCount = result.events_processed;

        container.innerHTML = `
            <div class="alert alert-info">
                <strong>Test Complete:</strong> Processed ${eventCount} events, found ${matchCount} matches
            </div>
            ${matchCount > 0 ? this.renderMatches(result.matches) : '<p class="text-muted">No sequences matched</p>'}
        `;
    },

    renderMatches(matches) {
        return `
            <table class="test-results-table">
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Rule Name</th>
                        <th>Event IDs</th>
                        <th>Steps</th>
                    </tr>
                </thead>
                <tbody>
                    ${matches.map(match => `
                        <tr>
                            <td><code>${this.escapeHtml(match.timestamp)}</code></td>
                            <td>${this.escapeHtml(match.rule_name)}</td>
                            <td><code>${match.matched_event_ids.join(', ')}</code></td>
                            <td>${this.renderStepDetails(match.steps)}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
    },

    renderStepDetails(steps) {
        return steps.map(step => `
            <div class="step-detail ${step.matched ? 'matched' : ''}">
                <strong>Step ${step.step}</strong> (${this.escapeHtml(step.alias)}): 
                ${step.matched ? '✓' : '✗'} 
                ${step.event ? `<code>${this.escapeHtml(step.event.timestamp || '')}</code>` : ''}
            </div>
        `).join('');
    },

    ruleToYaml(rule) {
        const lines = [
            `id: "${rule.id}"`,
            `name: "${rule.name}"`,
            `by: [${rule.by.map(f => `"${f}"`).join(', ')}]`,
            `within_seconds: ${rule.within_seconds}`,
            `sequence:`,
        ];

        rule.sequence.forEach(step => {
            lines.push(`  - as: "${step.as}"`);
            lines.push(`    where: "${step.where}"`);
        });

        lines.push(`output:`);
        lines.push(`  timestamp_ref: "${rule.output.timestamp_ref}"`);
        lines.push(`  format: "${rule.output.format}"`);

        return lines.join('\n');
    },

    escapeHtml(text) {
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return String(text).replace(/[&<>"']/g, m => map[m]);
    },

    showLoading(message = 'Loading...') {
        const tbody = document.getElementById('rulesTableBody');
        tbody.innerHTML = `<tr><td colspan="6" class="text-center">${message}</td></tr>`;
    },

    showError(message) {
        const tbody = document.getElementById('rulesTableBody');
        tbody.innerHTML = `<tr><td colspan="6" class="text-center text-danger">${this.escapeHtml(message)}</td></tr>`;
    }
};
