/**
 * Build a self-contained HTML invitation report (offline, no API required).
 */

const fs = require('fs');
const path = require('path');

function reportToHtml(report) {
    const adminDir = path.join(__dirname, '..', 'admin');
    const css = fs.readFileSync(path.join(adminDir, 'gate-report.css'), 'utf8');
    let html = fs.readFileSync(path.join(adminDir, 'gate-report.html'), 'utf8');
    const js = fs.readFileSync(path.join(adminDir, 'gate-report.js'), 'utf8');

    const generatedLabel = formatGeneratedLabel(report.generatedAt);
    const dataJson = JSON.stringify(report).replace(/</g, '\\u003c');

    html = html.replace(
        '<link rel="stylesheet" href="gate-report.css">',
        '<style>\n' + css + '\n</style>',
    );
    html = html.replace(
        'Local-only dashboard · employer outreach tracking',
        generatedLabel,
    );
    html = html.replace(
        '<button type="button" id="btn-refresh" class="btn">Refresh</button>\n            ',
        '',
    );
    html = html.replace(
        '<script src="gate-report.js"></script>',
        '<script>window.__GATE_REPORT_STATIC__=true;window.__GATE_REPORT_DATA__=' +
            dataJson +
            ';</script>\n    <script>\n' +
            js +
            '\n    </script>',
    );

    return html;
}

function formatGeneratedLabel(iso) {
    if (!iso) return 'Generated report · offline snapshot';
    try {
        const when = new Date(iso).toLocaleString(undefined, {
            month: 'short',
            day: 'numeric',
            year: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
        });
        return 'Generated ' + when + ' · offline snapshot';
    } catch (e) {
        return 'Generated report · offline snapshot';
    }
}

module.exports = {
    reportToHtml,
};
