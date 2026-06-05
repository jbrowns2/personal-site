(function () {
    'use strict';

    var reportData = null;
    var currentStatus = 'all';
    var searchQuery = '';
    var sortKey = 'invited-desc';
    var outcomeFilter = 'all';

    var els = {
        loading: document.getElementById('report-loading'),
        error: document.getElementById('report-error'),
        content: document.getElementById('report-content'),
        summaryCards: document.getElementById('summary-cards'),
        funnelChart: document.getElementById('funnel-chart'),
        dailyChart: document.getElementById('daily-chart'),
        failedChart: document.getElementById('failed-chart'),
        agingChart: document.getElementById('aging-chart'),
        actionPanels: document.getElementById('action-panels'),
        invitationsTbody: document.getElementById('invitations-tbody'),
        activityFeed: document.getElementById('activity-feed'),
        generatedAt: document.getElementById('generated-at'),
        drawer: document.getElementById('detail-drawer'),
        drawerContent: document.getElementById('drawer-content'),
    };

    function apiBase() {
        var path = window.location.pathname || '';
        if (path.indexOf('/admin/') >= 0) {
            return '/api';
        }
        return '/api';
    }

    function formatDate(iso) {
        if (!iso) return '—';
        try {
            return new Date(iso).toLocaleString(undefined, {
                month: 'short',
                day: 'numeric',
                year: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
            });
        } catch (e) {
            return iso;
        }
    }

    function formatShortDate(iso) {
        if (!iso) return '—';
        try {
            return new Date(iso).toLocaleDateString(undefined, {
                month: 'short',
                day: 'numeric',
                year: 'numeric',
            });
        } catch (e) {
            return iso;
        }
    }

    function esc(s) {
        if (s == null) return '';
        return String(s)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    function showError(msg) {
        els.loading.hidden = true;
        els.content.hidden = true;
        els.error.hidden = false;
        els.error.textContent = msg;
    }

    async function loadReport() {
        els.loading.hidden = false;
        els.error.hidden = true;
        els.content.hidden = true;
        try {
            var res = await fetch(apiBase() + '/gate-report?includeEvents=true', {
                credentials: 'same-origin',
            });
            if (res.status === 404) {
                showError(
                    'Report API unavailable. Set ALLOW_GATE_REPORT=true in .env and run npm run dev:vercel.',
                );
                return;
            }
            if (!res.ok) throw new Error('HTTP ' + res.status);
            reportData = await res.json();
            els.loading.hidden = true;
            els.content.hidden = false;
            renderAll();
        } catch (err) {
            showError('Failed to load report: ' + (err.message || err));
        }
    }

    function renderSummary(s) {
        var cards = [
            { label: 'Total invitations', value: s.totalInvitations },
            { label: 'Response rate', value: s.responseRatePct + '%' },
            { label: 'Responded', value: s.responded },
            { label: 'Pending', value: s.pending },
            { label: 'Expired unused', value: s.expiredUnused },
            { label: 'Avg days to respond', value: s.avgDaysToFirstUse != null ? s.avgDaysToFirstUse : '—' },
            { label: 'Returning visitors', value: s.returningVisitors },
            {
                label: 'Stale pending (30d+)',
                value: s.stalePending30dPlus,
                warn: s.stalePending30dPlus > 0,
            },
            {
                label: 'Expiring soon (7d)',
                value: s.expiringSoon,
                warn: s.expiringSoon > 0,
            },
            { label: 'Successful entries', value: s.totalSuccessfulEntries },
            { label: 'Failed entries (all)', value: s.totalFailedEntries },
            {
                label: 'Failed entries (7d)',
                value: s.failedEntries7d,
                warn: s.failedEntries7d > 3,
            },
        ];
        els.summaryCards.innerHTML = cards
            .map(function (c) {
                return (
                    '<div class="summary-card' +
                    (c.warn ? ' highlight-warning' : '') +
                    '"><div class="label">' +
                    esc(c.label) +
                    '</div><div class="value">' +
                    esc(c.value) +
                    '</div></div>'
                );
            })
            .join('');
    }

    function renderFunnel(s) {
        els.funnelChart.innerHTML =
            '<span class="funnel-step">Issued (' +
            s.totalInvitations +
            ')</span><span class="funnel-arrow">→</span>' +
            '<span class="funnel-step">Responded (' +
            s.responded +
            ')</span><span class="funnel-arrow">→</span>' +
            '<span class="funnel-step">Failed (' +
            s.totalFailedEntries +
            ')</span><span class="funnel-arrow">→</span>' +
            '<span class="funnel-step">Returning (' +
            s.returningVisitors +
            ')</span>';
    }

    function renderBarChart(container, rows, maxVal) {
        if (!maxVal) maxVal = 1;
        container.innerHTML = rows
            .map(function (r) {
                var pct = Math.round((r.value / maxVal) * 100);
                return (
                    '<div class="bar-row"><span class="bar-label">' +
                    esc(r.label) +
                    '</span><div class="bar-track"><div class="bar-fill-single" style="width:' +
                    pct +
                    '%"></div></div><span class="bar-value">' +
                    r.value +
                    '</span></div>'
                );
            })
            .join('');
    }

    function renderDailyChart(rollup) {
        var max = 1;
        rollup.forEach(function (d) {
            var t = d.successCount + d.failedCount;
            if (t > max) max = t;
        });
        var recent = rollup.slice(-14);
        els.dailyChart.innerHTML = recent
            .map(function (d) {
                var total = d.successCount + d.failedCount;
                var succPct = total ? Math.round((d.successCount / max) * 100) : 0;
                var failPct = total ? Math.round((d.failedCount / max) * 100) : 0;
                return (
                    '<div class="bar-row"><span class="bar-label">' +
                    d.date.slice(5) +
                    '</span><div class="bar-track">' +
                    (d.successCount
                        ? '<div class="bar-fill-success" style="width:' + succPct + '%"></div>'
                        : '') +
                    (d.failedCount
                        ? '<div class="bar-fill-failed" style="width:' + failPct + '%"></div>'
                        : '') +
                    '</div><span class="bar-value">' +
                    total +
                    '</span></div>'
                );
            })
            .join('');
    }

    function renderActionPanels(fu) {
        function panel(title, items, fmt) {
            if (!items.length) {
                return (
                    '<div class="action-panel"><h3>' +
                    esc(title) +
                    '</h3><ul><li class="muted">None</li></ul></div>'
                );
            }
            return (
                '<div class="action-panel"><h3>' +
                esc(title) +
                '</h3><ul>' +
                items
                    .map(function (item) {
                        return '<li>' + fmt(item) + '</li>';
                    })
                    .join('') +
                '</ul></div>'
            );
        }
        els.actionPanels.innerHTML =
            panel('Needs follow-up (14d+)', fu.needsFollowUp, function (i) {
                return (
                    esc(i.employerLabel) +
                    ' — ' +
                    i.daysOutstanding +
                    'd' +
                    (i.contactEmail ? ' · ' + esc(i.contactEmail) : '')
                );
            }) +
            panel('Recently responded (7d)', fu.respondedRecently, function (i) {
                return (
                    esc(i.employerLabel) +
                    ' — ' +
                    formatShortDate(i.firstUsedAt) +
                    ' (' +
                    i.daysToFirstUse +
                    'd)'
                );
            }) +
            panel('Expiring soon', fu.expiringSoon, function (i) {
                return (
                    esc(i.employerLabel) +
                    ' — ' +
                    i.daysToExpiry +
                    'd left'
                );
            }) +
            panel('Tried but failed', fu.triedButFailed, function (i) {
                return (
                    esc(i.employerLabel) +
                    ' — ' +
                    i.failedAttemptCount +
                    ' fails' +
                    (i.lastFailedAt ? ' · ' + formatShortDate(i.lastFailedAt) : '')
                );
            });
    }

    function filterInvitations(list) {
        var q = searchQuery.toLowerCase();
        return list.filter(function (inv) {
            if (currentStatus !== 'all' && inv.responseStatus !== currentStatus) {
                return false;
            }
            if (!q) return true;
            var hay =
                (inv.employerLabel || '') +
                ' ' +
                (inv.contactName || '') +
                ' ' +
                (inv.contactEmail || '') +
                ' ' +
                (inv.roleTitle || '');
            return hay.toLowerCase().indexOf(q) >= 0;
        });
    }

    function sortInvitations(list) {
        var sorted = list.slice();
        sorted.sort(function (a, b) {
            switch (sortKey) {
                case 'invited-asc':
                    return (a.invitedAt || '').localeCompare(b.invitedAt || '');
                case 'pending-desc':
                    return (b.daysOutstanding || 0) - (a.daysOutstanding || 0);
                case 'first-use-desc':
                    return (b.firstUsedAt || '').localeCompare(a.firstUsedAt || '');
                case 'uses-desc':
                    return b.useCount - a.useCount;
                case 'failed-desc':
                    return b.failedAttemptCount - a.failedAttemptCount;
                case 'label-asc':
                    return (a.employerLabel || '').localeCompare(b.employerLabel || '');
                default:
                    return (b.invitedAt || '').localeCompare(a.invitedAt || '');
            }
        });
        return sorted;
    }

    function renderTable() {
        var list = sortInvitations(filterInvitations(reportData.invitations));
        els.invitationsTbody.innerHTML = list
            .map(function (inv, idx) {
                var days =
                    inv.responseStatus === 'pending'
                        ? inv.daysOutstanding
                        : inv.daysToFirstUse;
                var contact = inv.contactName || inv.contactEmail || '—';
                if (inv.contactName && inv.contactEmail) {
                    contact = inv.contactName + ' · ' + inv.contactEmail;
                }
                return (
                    '<tr data-idx="' +
                    idx +
                    '" data-code-id="' +
                    inv.codeId +
                    '">' +
                    '<td>' +
                    esc(inv.employerLabel) +
                    (inv.hadIncorrectEntries
                        ? ' <span class="flag-yes" title="Had incorrect entries">⚠</span>'
                        : '') +
                    '</td>' +
                    '<td>' +
                    esc(contact) +
                    '</td>' +
                    '<td>' +
                    esc(inv.roleTitle || '—') +
                    '</td>' +
                    '<td>' +
                    formatShortDate(inv.invitedAt) +
                    '</td>' +
                    '<td><span class="badge badge-' +
                    inv.responseStatus +
                    '">' +
                    inv.responseStatus.replace('_', ' ') +
                    '</span></td>' +
                    '<td>' +
                    formatShortDate(inv.firstUsedAt) +
                    '</td>' +
                    '<td>' +
                    formatShortDate(inv.lastUsedAt) +
                    '</td>' +
                    '<td>' +
                    inv.useCount +
                    '</td>' +
                    '<td>' +
                    inv.failedAttemptCount +
                    '</td>' +
                    '<td>' +
                    (inv.failedBeforeFirstSuccess || '—') +
                    '</td>' +
                    '<td>' +
                    (days != null ? days : '—') +
                    '</td>' +
                    '<td>' +
                    esc(inv.engagementLevel) +
                    '</td>' +
                    '<td>' +
                    (inv.expiresAt ? formatShortDate(inv.expiresAt) : 'Never') +
                    '</td>' +
                    '</tr>'
                );
            })
            .join('');

        els.invitationsTbody.querySelectorAll('tr').forEach(function (tr) {
            tr.addEventListener('click', function () {
                var codeId = Number(tr.getAttribute('data-code-id'));
                var inv = reportData.invitations.find(function (i) {
                    return i.codeId === codeId;
                });
                if (inv) openDrawer(inv);
            });
        });
    }

    function renderActivityFeed() {
        var events = reportData.activity.recentEvents || [];
        if (outcomeFilter !== 'all') {
            events = events.filter(function (e) {
                return e.outcome === outcomeFilter;
            });
        }
        els.activityFeed.innerHTML = events
            .map(function (ev) {
                var label =
                    ev.employerLabel ||
                    ev.attributedEmployerLabel ||
                    'Unknown';
                var icon =
                    ev.outcome === 'success'
                        ? '✓'
                        : ev.outcome === 'incorrect'
                          ? '✗'
                          : '⊘';
                return (
                    '<li class="outcome-' +
                    ev.outcome +
                    '">[' +
                    formatDate(ev.createdAt) +
                    '] ' +
                    icon +
                    ' ' +
                    esc(ev.outcome) +
                    ' — ' +
                    esc(label) +
                    (ev.deviceType ? ' — ' + esc(ev.deviceType) : '') +
                    (ev.browser ? ' ' + esc(ev.browser) : '') +
                    '</li>'
                );
            })
            .join('');
    }

    function openDrawer(inv) {
        var events = (inv.recentEvents || []).slice();
        els.drawerContent.innerHTML =
            '<h2>' +
            esc(inv.employerLabel) +
            '</h2>' +
            '<div class="drawer-meta">' +
            (inv.contactName ? esc(inv.contactName) + '<br>' : '') +
            (inv.contactEmail ? esc(inv.contactEmail) + '<br>' : '') +
            (inv.roleTitle ? esc(inv.roleTitle) + '<br>' : '') +
            'Status: ' +
            esc(inv.responseStatus) +
            ' · Uses: ' +
            inv.useCount +
            ' · Failed: ' +
            inv.failedAttemptCount +
            (inv.failedBeforeFirstSuccess
                ? '<br>' +
                  inv.failedBeforeFirstSuccess +
                  ' wrong tries before first success'
                : '') +
            (inv.notes ? '<br><br><strong>Notes:</strong> ' + esc(inv.notes) : '') +
            '</div>' +
            '<h3>Event timeline</h3>' +
            '<ul class="event-timeline">' +
            events
                .map(function (ev) {
                    return (
                        '<li><span class="event-outcome ' +
                        ev.outcome +
                        '">' +
                        esc(ev.outcome) +
                        '</span> — ' +
                        formatDate(ev.createdAt) +
                        (ev.deviceType
                            ? '<br>' + esc(ev.deviceType) + ' · ' + esc(ev.browser)
                            : '') +
                        (ev.ip ? '<br>IP: ' + esc(ev.ip) : '') +
                        (ev.attribution === 'proximity'
                            ? '<br><em>Attributed via same visitor before success</em>'
                            : '') +
                        '</li>'
                    );
                })
                .join('') +
            '</ul>';
        els.drawer.hidden = false;
    }

    function closeDrawer() {
        els.drawer.hidden = true;
    }

    function renderAll() {
        var s = reportData.summary;
        renderSummary(s);
        renderFunnel(s);
        renderDailyChart(reportData.activity.dailyRollup || []);
        renderBarChart(els.failedChart, [
            { label: 'Incorrect', value: s.failedBreakdown.incorrect || 0 },
            { label: 'Disabled', value: s.failedBreakdown.disabledCode || 0 },
            { label: 'Expired', value: s.failedBreakdown.expiredCode || 0 },
        ], s.totalFailedEntries || 1);
        renderBarChart(els.agingChart, [
            { label: '0–7d', value: s.pendingAging['0to7Days'] || 0 },
            { label: '8–14d', value: s.pendingAging['8to14Days'] || 0 },
            { label: '15–30d', value: s.pendingAging['15to30Days'] || 0 },
            { label: '30d+', value: s.pendingAging.over30Days || 0 },
        ], Math.max(
            s.pendingAging['0to7Days'],
            s.pendingAging['8to14Days'],
            s.pendingAging['15to30Days'],
            s.pendingAging.over30Days,
            1,
        ));
        renderActionPanels(reportData.followUp || {});
        renderTable();
        renderActivityFeed();
        els.generatedAt.textContent = reportData.generatedAt
            ? 'Updated ' + formatDate(reportData.generatedAt)
            : '';
    }

    document.getElementById('btn-refresh').addEventListener('click', loadReport);
    document.getElementById('btn-export').addEventListener('click', function () {
        window.location.href = apiBase() + '/gate-report?format=csv';
    });
    document.getElementById('drawer-close').addEventListener('click', closeDrawer);
    document.getElementById('drawer-backdrop').addEventListener('click', closeDrawer);

    document.querySelectorAll('#status-tabs .tab').forEach(function (tab) {
        tab.addEventListener('click', function () {
            document.querySelectorAll('#status-tabs .tab').forEach(function (t) {
                t.classList.remove('active');
            });
            tab.classList.add('active');
            currentStatus = tab.getAttribute('data-status');
            renderTable();
        });
    });

    document.getElementById('search-box').addEventListener('input', function (e) {
        searchQuery = e.target.value;
        renderTable();
    });

    document.getElementById('sort-select').addEventListener('change', function (e) {
        sortKey = e.target.value;
        renderTable();
    });

    document.getElementById('outcome-filter').addEventListener('change', function (e) {
        outcomeFilter = e.target.value;
        renderActivityFeed();
    });

    loadReport();
})();
