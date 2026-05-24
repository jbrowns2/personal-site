/**
 * CORS for credentialed gate API requests from local static previews
 * (http://localhost, 127.0.0.1, or file://) to the deployed backend.
 */

'use strict';

function isAllowedDevOrigin(origin) {
    if (origin == null || typeof origin !== 'string') {
        return false;
    }
    if (origin === 'null') {
        return true;
    }
    try {
        const u = new URL(origin);
        if (u.protocol !== 'http:') {
            return false;
        }
        return u.hostname === 'localhost' || u.hostname === '127.0.0.1';
    } catch (e) {
        return false;
    }
}

function applyGateCors(req, res) {
    const origin = req.headers.origin;
    if (!isAllowedDevOrigin(origin)) {
        return;
    }
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    const vary = res.getHeader('Vary');
    if (vary) {
        if (typeof vary === 'string' && vary.indexOf('Origin') === -1) {
            res.setHeader('Vary', vary + ', Origin');
        }
    } else {
        res.setHeader('Vary', 'Origin');
    }
}

/** @returns {boolean} true if response was fully handled (OPTIONS preflight). */
function handleGateCorsPreflight(req, res) {
    if (req.method !== 'OPTIONS') {
        return false;
    }
    applyGateCors(req, res);
    res.setHeader('Access-Control-Max-Age', '86400');
    res.statusCode = 204;
    res.end();
    return true;
}

module.exports = { applyGateCors, handleGateCorsPreflight };
