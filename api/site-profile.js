const gate = require('../lib/gate-backend.js');
const { applyGateCors, handleGateCorsPreflight } = require('../lib/gate-cors.js');

module.exports = async function siteProfile(req, res) {
    try {
        if (handleGateCorsPreflight(req, res)) {
            return;
        }
        applyGateCors(req, res);
        if (req.method !== 'GET') {
            res.setHeader('Allow', 'GET');
            return res.status(405).json({ error: 'method_not_allowed' });
        }

        res.setHeader('Cache-Control', 'private, no-store');

        const session = gate.getSessionContext(req);
        if (!session) {
            return res.status(401).json({ error: 'unauthorized' });
        }

        const slug = gate.normalizeProfileSlug(session.profileSlug);
        if (!slug) {
            return res.status(404).json({ error: 'no_profile' });
        }

        const profile = gate.loadSiteProfile(slug);
        if (!profile) {
            return res.status(404).json({ error: 'profile_not_found', slug: slug });
        }

        return res.status(200).json({ ok: true, profile: profile });
    } catch (fatal) {
        console.error('site-profile:unhandled', fatal && fatal.message, fatal);
        if (!res.headersSent) {
            res.setHeader('Cache-Control', 'no-store');
            return res.status(503).json({ ok: false, error: 'service_unavailable' });
        }
    }
};
