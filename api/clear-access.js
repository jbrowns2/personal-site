const gate = require('../lib/gate-backend.js');
const { applyGateCors, handleGateCorsPreflight } = require('../lib/gate-cors.js');

module.exports = async function clearAccess(req, res) {
    try {
        if (handleGateCorsPreflight(req, res)) {
            return;
        }
        applyGateCors(req, res);
        if (req.method !== 'POST' && req.method !== 'GET') {
            res.setHeader('Allow', 'GET, POST');
            return res.status(405).json({ error: 'method_not_allowed' });
        }

        res.setHeader('Cache-Control', 'no-store');
        res.setHeader('Set-Cookie', gate.buildClearSessionCookie(req));
        return res.status(200).json({ ok: true, cleared: true });
    } catch (fatal) {
        console.error('clear-access:unhandled', fatal && fatal.message, fatal);
        if (!res.headersSent) {
            res.setHeader('Cache-Control', 'no-store');
            return res.status(503).json({ ok: false, error: 'service_unavailable' });
        }
    }
};
