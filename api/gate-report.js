const gate = require('../lib/gate-backend.js');
const gateReport = require('../lib/gate-report.js');
const { applyGateCors, handleGateCorsPreflight } = require('../lib/gate-cors.js');

module.exports = async function gateReportHandler(req, res) {
    try {
        if (handleGateCorsPreflight(req, res)) {
            return;
        }
        applyGateCors(req, res);

        if (process.env.ALLOW_GATE_REPORT !== 'true') {
            return res.status(404).json({ error: 'not_found' });
        }

        if (req.method !== 'GET') {
            res.setHeader('Allow', 'GET');
            return res.status(405).json({ error: 'method_not_allowed' });
        }

        res.setHeader('Cache-Control', 'no-store');

        const sql = gate.getSql();
        if (!sql) {
            return res.status(503).json({ error: 'service_unavailable' });
        }

        const url = new URL(req.url, 'http://localhost');
        const filters = {
            status: url.searchParams.get('status') || 'all',
            since: url.searchParams.get('since') || null,
            minDaysPending: url.searchParams.get('minDaysPending')
                ? parseInt(url.searchParams.get('minDaysPending'), 10)
                : null,
            includeEvents: url.searchParams.get('includeEvents') === 'true',
        };

        const format = url.searchParams.get('format') || 'json';
        const sheet = url.searchParams.get('sheet') || 'invitations';

        const report = await gateReport.getInvitationReport(sql, filters);

        if (format === 'csv') {
            if (sheet === 'events') {
                const data = await gateReport.fetchReportData(sql);
                const filtered = gateReport.filterReportEvents(data.events);
                const codesById = new Map();
                data.codes.forEach(function (c) {
                    codesById.set(c.id, c);
                });
                const proximityMap = gateReport.buildProximityMap(
                    filtered.events,
                    codesById,
                );
                const csv = gateReport.eventsToCsv(
                    filtered.events,
                    codesById,
                    proximityMap,
                );
                res.setHeader('Content-Type', 'text/csv; charset=utf-8');
                res.setHeader(
                    'Content-Disposition',
                    'attachment; filename="gate-events.csv"',
                );
                return res.status(200).send(csv);
            }
            const csv = gateReport.invitationsToCsv(report.invitations);
            res.setHeader('Content-Type', 'text/csv; charset=utf-8');
            res.setHeader(
                'Content-Disposition',
                'attachment; filename="gate-invitations.csv"',
            );
            return res.status(200).send(csv);
        }

        return res.status(200).json(report);
    } catch (err) {
        console.error('gate-report', err && err.message, err);
        if (!res.headersSent) {
            return res.status(503).json({ error: 'service_unavailable' });
        }
    }
};
