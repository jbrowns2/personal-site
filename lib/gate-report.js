/**
 * Invitation reporting for portfolio access gate (local dashboard + CLI).
 */

const { parseUserAgent } = require('./gate-backend.js');

const FAILURE_OUTCOMES = ['incorrect', 'disabled_code', 'expired_code'];

function toIso(value) {
    if (!value) return null;
    try {
        return new Date(value).toISOString();
    } catch (e) {
        return null;
    }
}

function daysBetween(start, end) {
    if (!start || !end) return null;
    const ms = new Date(end).getTime() - new Date(start).getTime();
    return Math.max(0, Math.floor(ms / 86400000));
}

function median(nums) {
    if (!nums.length) return null;
    const sorted = nums.slice().sort(function (a, b) { return a - b; });
    const mid = Math.floor(sorted.length / 2);
    if (sorted.length % 2 === 0) {
        return (sorted[mid - 1] + sorted[mid]) / 2;
    }
    return sorted[mid];
}

function round1(n) {
    return Math.round(n * 10) / 10;
}

function visitorKey(ip, fingerprint) {
    if (fingerprint) return 'fp:' + fingerprint;
    if (ip) return 'ip:' + ip;
    return null;
}

function parseDelimitedEnvList(value) {
    if (!value || typeof value !== 'string') return [];
    return value
        .split(/[\s,;]+/)
        .map(function (s) { return s.trim(); })
        .filter(Boolean);
}

function normalizeExcludedIp(ip) {
    if (!ip) return null;
    var s = String(ip).trim().toLowerCase();
    if (s.indexOf('::ffff:') === 0) {
        s = s.slice(7);
    }
    return s;
}

function parseReportExclusions(env) {
    env = env || process.env;
    var fingerprints = new Set(
        parseDelimitedEnvList(env.GATE_REPORT_EXCLUDE_FINGERPRINTS || ''),
    );
    var ips = new Set(
        parseDelimitedEnvList(env.GATE_REPORT_EXCLUDE_IPS || '')
            .map(normalizeExcludedIp)
            .filter(Boolean),
    );
    return { fingerprints: fingerprints, ips: ips };
}

function isExcludedEvent(ev, exclusions) {
    if (!exclusions) return false;
    if (ev.fingerprint && exclusions.fingerprints.has(ev.fingerprint)) {
        return true;
    }
    var ip = normalizeExcludedIp(ev.ip);
    if (ip && exclusions.ips.has(ip)) {
        return true;
    }
    return false;
}

function filterReportEvents(events, exclusions) {
    exclusions = exclusions || parseReportExclusions();
    if (!exclusions.fingerprints.size && !exclusions.ips.size) {
        return {
            events: events,
            excludedEventCount: 0,
            exclusions: {
                active: false,
                fingerprintCount: 0,
                ipCount: 0,
                excludedEventCount: 0,
            },
        };
    }
    var excludedEventCount = 0;
    var filtered = events.filter(function (ev) {
        if (isExcludedEvent(ev, exclusions)) {
            excludedEventCount++;
            return false;
        }
        return true;
    });
    return {
        events: filtered,
        excludedEventCount: excludedEventCount,
        exclusions: {
            active: true,
            fingerprintCount: exclusions.fingerprints.size,
            ipCount: exclusions.ips.size,
            excludedEventCount: excludedEventCount,
        },
    };
}

function mapOutcomeToBreakdownKey(outcome) {
    if (outcome === 'disabled_code') return 'disabledCode';
    if (outcome === 'expired_code') return 'expiredCode';
    if (outcome === 'incorrect') return 'incorrect';
    return null;
}

function deriveResponseStatus(code, useCount, now) {
    if (!code.active) return 'disabled';
    if (useCount > 0) return 'responded';
    if (code.expires_at && new Date(code.expires_at).getTime() < now) {
        return 'expired_unused';
    }
    return 'pending';
}

function deriveEngagementLevel(useCount) {
    if (useCount === 0) return 'none';
    if (useCount === 1) return 'single_use';
    if (useCount <= 4) return 'returning';
    return 'heavy';
}

function buildProximityMap(events, codesById) {
    var proximity = new Map();
    var successesByVisitor = [];

    events.forEach(function (ev) {
        if (ev.outcome !== 'success' || !ev.code_id) return;
        var key = visitorKey(ev.ip, ev.fingerprint);
        if (!key) return;
        successesByVisitor.push({
            key: key,
            codeId: ev.code_id,
            createdAt: new Date(ev.created_at).getTime(),
        });
    });

    events.forEach(function (ev) {
        if (ev.outcome === 'success' || ev.code_id) return;
        var failTime = new Date(ev.created_at).getTime();
        var key = visitorKey(ev.ip, ev.fingerprint);
        if (!key) return;

        successesByVisitor.forEach(function (succ) {
            if (succ.key !== key) return;
            var code = codesById.get(succ.codeId);
            if (!code) return;
            var invitedAt = new Date(code.created_at).getTime();
            if (failTime < invitedAt || failTime >= succ.createdAt) return;

            var list = proximity.get(succ.codeId) || [];
            list.push({ event: ev, attribution: 'proximity' });
            proximity.set(succ.codeId, list);
        });
    });

    return proximity;
}

function formatEventRow(ev, codesById, proximityForCode) {
    var ua = parseUserAgent(ev.user_agent);
    var code = ev.code_id ? codesById.get(ev.code_id) : null;
    var attribution = ev.code_id ? 'direct' : null;
    var note = null;

    if (!attribution && proximityForCode) {
        var prox = proximityForCode.find(function (p) { return p.event.id === ev.id; });
        if (prox) {
            attribution = prox.attribution;
            note = 'Same visitor later succeeded on this code';
        }
    }

    return {
        id: ev.id,
        outcome: ev.outcome,
        createdAt: toIso(ev.created_at),
        ip: ev.ip ? String(ev.ip) : null,
        fingerprint: ev.fingerprint || null,
        userAgent: ev.user_agent || null,
        deviceType: ua.deviceType,
        browser: ua.browser,
        os: ua.os,
        attribution: attribution,
        note: note,
    };
}

async function fetchReportData(sql) {
    var codes = await sql`
        SELECT id, label, active, expires_at, last_used_at, created_at,
               code_lookup_hash, access_code, contact_name, contact_email,
               role_title, notes
        FROM portfolio_gate_access_codes
        ORDER BY created_at DESC, id DESC
    `;

    var events = [];
    try {
        events = await sql`
            SELECT id, code_id, outcome, attempt_lookup_hash, ip, fingerprint,
                   user_agent, created_at
            FROM portfolio_gate_access_code_events
            ORDER BY created_at ASC, id ASC
        `;
    } catch (err) {
        if (err && err.code === '42P01') {
            events = [];
        } else {
            throw err;
        }
    }

    return { codes: codes, events: events };
}

function buildInvitationReport(codes, events, filters) {
    filters = filters || {};
    var now = Date.now();
    var codesById = new Map();
    codes.forEach(function (c) { codesById.set(c.id, c); });

    var eventsByCode = new Map();
    events.forEach(function (ev) {
        if (ev.code_id) {
            var list = eventsByCode.get(ev.code_id) || [];
            list.push(ev);
            eventsByCode.set(ev.code_id, list);
        }
    });

    var proximityMap = buildProximityMap(events, codesById);

    var invitations = codes.map(function (code) {
        var directEvents = eventsByCode.get(code.id) || [];
        var proxEvents = proximityMap.get(code.id) || [];
        var allAttributedFails = directEvents.filter(function (e) {
            return FAILURE_OUTCOMES.indexOf(e.outcome) >= 0;
        });
        proxEvents.forEach(function (p) { allAttributedFails.push(p.event); });

        var successEvents = directEvents.filter(function (e) { return e.outcome === 'success'; });
        var useCount = successEvents.length;
        var firstUsedAt = successEvents.length
            ? toIso(successEvents[0].created_at)
            : null;
        var lastUsedAt = successEvents.length
            ? toIso(successEvents[successEvents.length - 1].created_at)
            : null;

        var failureBreakdown = { incorrect: 0, disabledCode: 0, expiredCode: 0 };
        var attributedFailureCount = 0;
        var unattributedFailureCount = 0;
        var firstFailedAt = null;

        allAttributedFails.forEach(function (ev) {
            var key = mapOutcomeToBreakdownKey(ev.outcome);
            if (key) failureBreakdown[key] = (failureBreakdown[key] || 0) + 1;
            if (ev.code_id) {
                attributedFailureCount++;
            } else {
                unattributedFailureCount++;
            }
            if (!firstFailedAt || new Date(ev.created_at) < new Date(firstFailedAt)) {
                firstFailedAt = toIso(ev.created_at);
            }
        });

        var failedBeforeFirstSuccess = 0;
        if (firstUsedAt) {
            var firstSuccessTime = new Date(firstUsedAt).getTime();
            allAttributedFails.forEach(function (ev) {
                if (new Date(ev.created_at).getTime() < firstSuccessTime) {
                    failedBeforeFirstSuccess++;
                }
            });
        }

        var uniqueIps = new Set();
        var uniqueFps = new Set();
        var browsers = new Set();
        var oss = new Set();
        var deviceCounts = { desktop: 0, mobile: 0, tablet: 0, unknown: 0 };

        directEvents.forEach(function (ev) {
            if (ev.ip) uniqueIps.add(String(ev.ip));
            if (ev.fingerprint) uniqueFps.add(ev.fingerprint);
            var ua = parseUserAgent(ev.user_agent);
            if (ua.browser) browsers.add(ua.browser);
            if (ua.os) oss.add(ua.os);
            deviceCounts[ua.deviceType] = (deviceCounts[ua.deviceType] || 0) + 1;
        });

        var primaryDevice = 'unknown';
        var maxDev = 0;
        Object.keys(deviceCounts).forEach(function (k) {
            if (deviceCounts[k] > maxDev) {
                maxDev = deviceCounts[k];
                primaryDevice = k;
            }
        });

        var responseStatus = deriveResponseStatus(code, useCount, now);
        var invitedAt = toIso(code.created_at);
        var daysOutstanding =
            responseStatus === 'pending' ? daysBetween(code.created_at, new Date()) : null;
        var daysToExpiry =
            code.expires_at && responseStatus === 'pending'
                ? daysBetween(new Date(), code.expires_at)
                : null;

        var recentEventLimit = filters.includeEvents ? Infinity : 10;
        var combinedEvents = directEvents.concat(
            proxEvents.map(function (p) { return p.event; }),
        );
        combinedEvents.sort(function (a, b) {
            return new Date(b.created_at) - new Date(a.created_at);
        });
        var seenIds = new Set();
        var recentEvents = [];
        combinedEvents.forEach(function (ev) {
            if (seenIds.has(ev.id)) return;
            seenIds.add(ev.id);
            if (recentEvents.length < recentEventLimit) {
                recentEvents.push(
                    formatEventRow(ev, codesById, proxEvents),
                );
            }
        });

        return {
            codeId: code.id,
            accessCode: code.access_code || null,
            employerLabel: code.label,
            contactName: code.contact_name || null,
            contactEmail: code.contact_email || null,
            roleTitle: code.role_title || null,
            notes: code.notes || null,
            lookupHashConfigured: !!code.code_lookup_hash,
            invitedAt: invitedAt,
            expiresAt: code.expires_at ? toIso(code.expires_at) : null,
            active: code.active,
            responseStatus: responseStatus,
            daysOutstanding: daysOutstanding,
            daysToExpiry: daysToExpiry,
            daysSinceLastUse: lastUsedAt ? daysBetween(lastUsedAt, new Date()) : null,
            daysToFirstUse:
                firstUsedAt && invitedAt ? daysBetween(code.created_at, firstUsedAt) : null,
            firstUsedAt: firstUsedAt,
            lastUsedAt: lastUsedAt,
            useCount: useCount,
            engagementLevel: deriveEngagementLevel(useCount),
            uniqueIpCount: uniqueIps.size,
            uniqueFingerprintCount: uniqueFps.size,
            failedAttemptCount: allAttributedFails.length,
            attributedFailureCount: attributedFailureCount,
            unattributedFailureCount: unattributedFailureCount,
            failedBeforeFirstSuccess: failedBeforeFirstSuccess,
            hadIncorrectEntries: allAttributedFails.length > 0,
            failureBreakdown: failureBreakdown,
            firstFailedAt: firstFailedAt,
            deviceSummary: {
                primaryDevice: primaryDevice,
                browsers: Array.from(browsers),
                operatingSystems: Array.from(oss),
            },
            recentEvents: recentEvents,
        };
    });

    if (filters.status && filters.status !== 'all') {
        invitations = invitations.filter(function (inv) {
            return inv.responseStatus === filters.status;
        });
    }
    if (filters.since) {
        var sinceMs = new Date(filters.since).getTime();
        invitations = invitations.filter(function (inv) {
            return new Date(inv.invitedAt).getTime() >= sinceMs;
        });
    }
    if (filters.minDaysPending) {
        invitations = invitations.filter(function (inv) {
            return (
                inv.responseStatus === 'pending' &&
                inv.daysOutstanding >= filters.minDaysPending
            );
        });
    }

    return invitations;
}

function buildSummary(codes, events, invitations) {
    var now = Date.now();
    var sevenDaysAgo = now - 7 * 86400000;
    var oneDayAgo = now - 86400000;

    var totalSuccessfulEntries = 0;
    var totalFailedEntries = 0;
    var failedEntriesToday = 0;
    var failedEntries7d = 0;
    var failedBreakdown = { incorrect: 0, disabledCode: 0, expiredCode: 0 };
    var attributedFailures = 0;
    var unattributedFailures = 0;
    var employersWithFailed = new Set();
    var employersWithSuccess = new Set();

    events.forEach(function (ev) {
        if (ev.outcome === 'success') {
            totalSuccessfulEntries++;
            if (ev.code_id) employersWithSuccess.add(ev.code_id);
            return;
        }
        totalFailedEntries++;
        var t = new Date(ev.created_at).getTime();
        if (t >= oneDayAgo) failedEntriesToday++;
        if (t >= sevenDaysAgo) failedEntries7d++;
        var key = mapOutcomeToBreakdownKey(ev.outcome);
        if (key) failedBreakdown[key]++;
        if (ev.code_id) {
            attributedFailures++;
            employersWithFailed.add(ev.code_id);
        } else {
            unattributedFailures++;
        }
    });

    invitations.forEach(function (inv) {
        if (inv.failedAttemptCount > 0 && inv.useCount === 0) {
            employersWithFailed.add(inv.codeId);
        }
        if (inv.failedAttemptCount > 0) {
            employersWithFailed.add(inv.codeId);
        }
    });

    var responded = invitations.filter(function (i) { return i.useCount > 0; }).length;
    var pending = invitations.filter(function (i) { return i.responseStatus === 'pending'; }).length;
    var expiredUnused = invitations.filter(function (i) {
        return i.responseStatus === 'expired_unused';
    }).length;

    var daysToFirst = invitations
        .filter(function (i) { return i.daysToFirstUse != null; })
        .map(function (i) { return i.daysToFirstUse; });
    var failedBeforeSuccess = invitations
        .filter(function (i) { return i.useCount > 0 && i.failedBeforeFirstSuccess > 0; })
        .map(function (i) { return i.failedBeforeFirstSuccess; });

    var pendingAging = { '0to7Days': 0, '8to14Days': 0, '15to30Days': 0, over30Days: 0 };
    invitations.forEach(function (inv) {
        if (inv.responseStatus !== 'pending' || inv.daysOutstanding == null) return;
        var d = inv.daysOutstanding;
        if (d <= 7) pendingAging['0to7Days']++;
        else if (d <= 14) pendingAging['8to14Days']++;
        else if (d <= 30) pendingAging['15to30Days']++;
        else pendingAging.over30Days++;
    });

    var employersFailedButNeverSucceeded = invitations.filter(function (inv) {
        return inv.failedAttemptCount > 0 && inv.useCount === 0;
    }).length;

    return {
        totalInvitations: codes.length,
        activeInvitations: codes.filter(function (c) { return c.active; }).length,
        disabledInvitations: codes.filter(function (c) { return !c.active; }).length,
        responded: responded,
        pending: pending,
        expiredUnused: expiredUnused,
        responseRatePct:
            codes.length > 0 ? round1((responded / codes.length) * 100) : 0,
        totalSuccessfulEntries: totalSuccessfulEntries,
        totalFailedEntries: totalFailedEntries,
        failedEntriesToday: failedEntriesToday,
        failedEntries7d: failedEntries7d,
        failedBreakdown: failedBreakdown,
        attributedFailures: attributedFailures,
        unattributedFailures: unattributedFailures,
        employersWithFailedAttempts: employersWithFailed.size,
        employersFailedButNeverSucceeded: employersFailedButNeverSucceeded,
        avgDaysToFirstUse:
            daysToFirst.length > 0
                ? round1(daysToFirst.reduce(function (a, b) { return a + b; }, 0) / daysToFirst.length)
                : null,
        medianDaysToFirstUse: median(daysToFirst),
        avgFailedAttemptsBeforeSuccess:
            failedBeforeSuccess.length > 0
                ? round1(
                      failedBeforeSuccess.reduce(function (a, b) { return a + b; }, 0) /
                          failedBeforeSuccess.length,
                  )
                : null,
        returningVisitors: invitations.filter(function (i) { return i.useCount > 1; }).length,
        pendingAging: pendingAging,
        expiringSoon: invitations.filter(function (inv) {
            return (
                inv.responseStatus === 'pending' &&
                inv.daysToExpiry != null &&
                inv.daysToExpiry <= 7
            );
        }).length,
        recentlyResponded7d: invitations.filter(function (inv) {
            return (
                inv.firstUsedAt &&
                new Date(inv.firstUsedAt).getTime() >= sevenDaysAgo
            );
        }).length,
        stalePending30dPlus: invitations.filter(function (inv) {
            return inv.responseStatus === 'pending' && inv.daysOutstanding >= 30;
        }).length,
    };
}

function buildActivity(events, codesById, proximityMap) {
    var recentEvents = events
        .slice()
        .sort(function (a, b) { return new Date(b.created_at) - new Date(a.created_at); })
        .slice(0, 25)
        .map(function (ev) {
            var code = ev.code_id ? codesById.get(ev.code_id) : null;
            var attributedLabel = code ? code.label : null;
            if (!attributedLabel && ev.code_id == null) {
                proximityMap.forEach(function (proxList, codeId) {
                    if (proxList.find(function (p) { return p.event.id === ev.id; })) {
                        var c = codesById.get(codeId);
                        if (c) attributedLabel = c.label;
                    }
                });
            }
            var ua = parseUserAgent(ev.user_agent);
            return {
                eventId: ev.id,
                outcome: ev.outcome,
                employerLabel: code ? code.label : null,
                attributedEmployerLabel: attributedLabel,
                codeId: ev.code_id,
                createdAt: toIso(ev.created_at),
                deviceType: ua.deviceType,
                browser: ua.browser,
            };
        });

    var dayMap = new Map();
    var now = new Date();
    for (var i = 29; i >= 0; i--) {
        var d = new Date(now);
        d.setUTCDate(d.getUTCDate() - i);
        var key = d.toISOString().slice(0, 10);
        dayMap.set(key, {
            date: key,
            successCount: 0,
            failedCount: 0,
            incorrectCount: 0,
            disabledCodeCount: 0,
            expiredCodeCount: 0,
            uniqueEmployers: new Set(),
        });
    }

    events.forEach(function (ev) {
        var key = toIso(ev.created_at).slice(0, 10);
        if (!dayMap.has(key)) return;
        var row = dayMap.get(key);
        if (ev.outcome === 'success') {
            row.successCount++;
            if (ev.code_id) row.uniqueEmployers.add(ev.code_id);
        } else {
            row.failedCount++;
            var bk = mapOutcomeToBreakdownKey(ev.outcome);
            if (bk === 'incorrect') row.incorrectCount++;
            if (bk === 'disabledCode') row.disabledCodeCount++;
            if (bk === 'expiredCode') row.expiredCodeCount++;
        }
    });

    var dailyRollup = Array.from(dayMap.values()).map(function (row) {
        return {
            date: row.date,
            successCount: row.successCount,
            failedCount: row.failedCount,
            incorrectCount: row.incorrectCount,
            disabledCodeCount: row.disabledCodeCount,
            expiredCodeCount: row.expiredCodeCount,
            uniqueEmployers: row.uniqueEmployers.size,
        };
    });

    var weekMap = new Map();
    codesById.forEach(function (code) {
        var d = new Date(code.created_at);
        var day = d.getUTCDay();
        var diff = d.getUTCDate() - day + (day === 0 ? -6 : 1);
        var weekStart = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), diff));
        var key = weekStart.toISOString().slice(0, 10);
        weekMap.set(key, (weekMap.get(key) || 0) + 1);
    });

    var invitationsByWeek = Array.from(weekMap.entries())
        .map(function (entry) {
            return { weekStart: entry[0], issued: entry[1] };
        })
        .sort(function (a, b) { return a.weekStart.localeCompare(b.weekStart); });

    return {
        recentEvents: recentEvents,
        dailyRollup: dailyRollup,
        invitationsByWeek: invitationsByWeek,
    };
}

function buildFollowUp(invitations, events, codesById, proximityMap) {
    var needsFollowUp = invitations
        .filter(function (inv) {
            return inv.responseStatus === 'pending' && inv.daysOutstanding >= 14;
        })
        .sort(function (a, b) { return b.daysOutstanding - a.daysOutstanding; })
        .map(function (inv) {
            return {
                employerLabel: inv.employerLabel,
                daysOutstanding: inv.daysOutstanding,
                contactEmail: inv.contactEmail,
                notes: inv.notes,
            };
        });

    var sevenDaysAgo = Date.now() - 7 * 86400000;
    var respondedRecently = invitations
        .filter(function (inv) {
            return inv.firstUsedAt && new Date(inv.firstUsedAt).getTime() >= sevenDaysAgo;
        })
        .map(function (inv) {
            return {
                employerLabel: inv.employerLabel,
                firstUsedAt: inv.firstUsedAt,
                daysToFirstUse: inv.daysToFirstUse,
            };
        });

    var expiringSoon = invitations
        .filter(function (inv) {
            return (
                inv.responseStatus === 'pending' &&
                inv.daysToExpiry != null &&
                inv.daysToExpiry <= 7
            );
        })
        .map(function (inv) {
            return {
                employerLabel: inv.employerLabel,
                expiresAt: inv.expiresAt,
                daysToExpiry: inv.daysToExpiry,
            };
        });

    var triedButFailed = invitations
        .filter(function (inv) {
            return inv.failedAttemptCount > 0 && inv.useCount === 0;
        })
        .map(function (inv) {
            var lastFailed = null;
            inv.recentEvents.forEach(function (ev) {
                if (FAILURE_OUTCOMES.indexOf(ev.outcome) >= 0) {
                    if (!lastFailed || ev.createdAt > lastFailed) lastFailed = ev.createdAt;
                }
            });
            return {
                employerLabel: inv.employerLabel,
                failedAttemptCount: inv.failedAttemptCount,
                lastFailedAt: lastFailed,
                responseStatus: inv.responseStatus,
                note: 'Entered wrong codes but never succeeded — consider resending invite',
            };
        });

    var recentIncorrectEntries = events
        .filter(function (ev) { return ev.outcome === 'incorrect'; })
        .sort(function (a, b) { return new Date(b.created_at) - new Date(a.created_at); })
        .slice(0, 15)
        .map(function (ev) {
            var attributedLabel = null;
            proximityMap.forEach(function (proxList, codeId) {
                if (proxList.find(function (p) { return p.event.id === ev.id; })) {
                    var c = codesById.get(codeId);
                    if (c) attributedLabel = c.label;
                }
            });
            var ua = parseUserAgent(ev.user_agent);
            return {
                createdAt: toIso(ev.created_at),
                outcome: ev.outcome,
                attributedEmployerLabel: attributedLabel,
                ip: ev.ip ? String(ev.ip) : null,
                deviceType: ua.deviceType,
            };
        });

    return {
        needsFollowUp: needsFollowUp,
        respondedRecently: respondedRecently,
        expiringSoon: expiringSoon,
        triedButFailed: triedButFailed,
        recentIncorrectEntries: recentIncorrectEntries,
    };
}

async function getInvitationReport(sql, filters) {
    var data = await fetchReportData(sql);
    var filtered = filterReportEvents(data.events);
    var events = filtered.events;
    var codesById = new Map();
    data.codes.forEach(function (c) { codesById.set(c.id, c); });
    var proximityMap = buildProximityMap(events, codesById);

    var allInvitations = buildInvitationReport(data.codes, events, {});
    var invitations = buildInvitationReport(data.codes, events, filters || {});
    var summary = buildSummary(data.codes, events, allInvitations);
    var activity = buildActivity(events, codesById, proximityMap);
    var followUp = buildFollowUp(allInvitations, events, codesById, proximityMap);

    return {
        generatedAt: new Date().toISOString(),
        exclusions: filtered.exclusions,
        summary: summary,
        invitations: invitations,
        activity: activity,
        followUp: followUp,
    };
}

function invitationsToCsv(invitations) {
    var headers = [
        'access_code',
        'employer_label',
        'contact_name',
        'contact_email',
        'role_title',
        'invited_at',
        'expires_at',
        'active',
        'response_status',
        'days_outstanding',
        'days_to_first_use',
        'first_used_at',
        'last_used_at',
        'use_count',
        'failed_attempt_count',
        'failed_before_first_success',
        'had_incorrect_entries',
        'engagement_level',
        'unique_ips',
        'notes',
    ];
    var rows = invitations.map(function (inv) {
        return [
            inv.accessCode || '',
            inv.employerLabel,
            inv.contactName || '',
            inv.contactEmail || '',
            inv.roleTitle || '',
            inv.invitedAt || '',
            inv.expiresAt || '',
            inv.active,
            inv.responseStatus,
            inv.daysOutstanding != null ? inv.daysOutstanding : '',
            inv.daysToFirstUse != null ? inv.daysToFirstUse : '',
            inv.firstUsedAt || '',
            inv.lastUsedAt || '',
            inv.useCount,
            inv.failedAttemptCount,
            inv.failedBeforeFirstSuccess,
            inv.hadIncorrectEntries,
            inv.engagementLevel,
            inv.uniqueIpCount,
            (inv.notes || '').replace(/"/g, '""'),
        ]
            .map(function (v) {
                var s = String(v);
                return s.indexOf(',') >= 0 || s.indexOf('"') >= 0 ? '"' + s + '"' : s;
            })
            .join(',');
    });
    return headers.join(',') + '\n' + rows.join('\n') + '\n';
}

function eventsToCsv(events, codesById, proximityMap) {
    var headers = [
        'event_id',
        'code_id',
        'employer_label',
        'outcome',
        'attribution',
        'created_at',
        'ip',
        'fingerprint',
        'user_agent',
        'device_type',
        'browser',
        'os',
    ];
    var rows = events.map(function (ev) {
        var code = ev.code_id ? codesById.get(ev.code_id) : null;
        var attribution = ev.code_id ? 'direct' : '';
        if (!attribution) {
            proximityMap.forEach(function (proxList, codeId) {
                if (proxList.find(function (p) { return p.event.id === ev.id; })) {
                    attribution = 'proximity';
                    if (!code) code = codesById.get(codeId);
                }
            });
        }
        var ua = parseUserAgent(ev.user_agent);
        return [
            ev.id,
            ev.code_id || '',
            code ? code.label : '',
            ev.outcome,
            attribution,
            toIso(ev.created_at),
            ev.ip ? String(ev.ip) : '',
            ev.fingerprint || '',
            (ev.user_agent || '').replace(/"/g, '""'),
            ua.deviceType,
            ua.browser,
            ua.os,
        ]
            .map(function (v) {
                var s = String(v);
                return s.indexOf(',') >= 0 || s.indexOf('"') >= 0 ? '"' + s + '"' : s;
            })
            .join(',');
    });
    return headers.join(',') + '\n' + rows.join('\n') + '\n';
}

module.exports = {
    getInvitationReport,
    invitationsToCsv,
    eventsToCsv,
    fetchReportData,
    buildProximityMap,
    parseReportExclusions,
    filterReportEvents,
    isExcludedEvent,
    FAILURE_OUTCOMES,
};
