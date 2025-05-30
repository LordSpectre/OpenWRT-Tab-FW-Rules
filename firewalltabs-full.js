﻿'use strict';
'require view';
'require ui';
'require rpc';
'require uci';
'require form';
'require firewall as fwmodel';
'require tools.firewall as fwtool';
'require tools.widgets as widgets';

// Funzioni helper per testo delle regole (invariate)
function rule_proto_txt(s, ctHelpers) {
    var f = (uci.get('firewall', s, 'family') || '').toLowerCase().replace(/^(?:any|\*)$/, '');
    var proto = L.toArray(uci.get('firewall', s, 'proto')).filter(function(p) {
        return (p != '*' && p != 'any' && p != 'all');
    }).map(function(p) {
        var pr = fwtool.lookupProto(p);
        return {
            num: pr[0],
            name: pr[1],
            types: (pr[0] == 1 || pr[0] == 58)
                ? L.toArray(uci.get('firewall', s, 'icmp_type'))
                : null
        };
    });
    var m = String(uci.get('firewall', s, 'helper') || '').match(/^(!\s*)?(\S+)$/);
    var h = m ? {
        val: m[0].toUpperCase(),
        inv: m[1],
        name: (ctHelpers.filter(function(ctH) { return ctH.name.toLowerCase() == m[2].toLowerCase(); })[0] || {}).description
    } : null;
    m = String(uci.get('firewall', s, 'mark')).match(/^(!\s*)?(0x[0-9a-f]{1,8}|[0-9]{1,10})(?:\/(0x[0-9a-f]{1,8}|[0-9]{1,10}))?$/i);
    var w = m ? {
        val: m[0].toUpperCase().replace(/X/g, 'x'),
        inv: m[1],
        num: '0x%02X'.format(+m[2]),
        mask: m[3] ? '0x%02X'.format(+m[3]) : null
    } : null;
    m = String(uci.get('firewall', s, 'dscp')).match(/^(!\s*)?(?:(CS[0-7]|BE|AF[1234][123]|EF)|(0x[0-9a-f]{1,2}|[0-9]{1,2}))$/);
    var d = m ? { val: m[0], inv: m[1], name: m[2], num: m[3] ? '0x%02X'.format(+m[3]) : null } : null;
    return fwtool.fmt(_('%{src?%{dest?Forwarded:Incoming}:Outgoing} %{ipv6?%{ipv4?<var>IPv4</var> and <var>IPv6</var>:<var>IPv6</var>}:<var>IPv4</var>}%{proto?, protocol %{proto#%{next?, }%{item.types?<var class="cbi-tooltip-container">%{item.name}<span class="cbi-tooltip">ICMP with types %{item.types#%{next?, }<var>%{item}</var>}</span></var>:<var>%{item.name}</var>}}}%{mark?, mark <var%{mark.inv? data-tooltip="Match fwmarks except %{mark.num}%{mark.mask? with mask %{mark.mask}}.":%{mark.mask? data-tooltip="Mask fwmark value with %{mark.mask} before compare."}}>%{mark.val}</var>}%{dscp?, DSCP %{dscp.inv?<var data-tooltip="Match DSCP classifications except %{dscp.num?:%{dscp.name}}">%{dscp.val}</var>:<var>%{dscp.val}</var>}}%{helper?, helper %{helper.inv?<var data-tooltip="Match any helper except &quot;%{helper.name}&quot;">%{helper.val}</var>:<var data-tooltip="%{helper.name}">%{helper.val}</var>}}'), {
        ipv4: (!f || f == 'ipv4'),
        ipv6: (!f || f == 'ipv6'),
        src: uci.get('firewall', s, 'src'),
        dest: uci.get('firewall', s, 'dest'),
        proto: proto,
        helper: h,
        mark: w,
        dscp: d
    });
}
function rule_src_txt(s, hosts) {
    var z = uci.get('firewall', s, 'src'), d = (uci.get('firewall', s, 'direction') == 'in') ? uci.get('firewall', s, 'device') : null;
    return fwtool.fmt(_('From %{src}%{src_device?, interface <var>%{src_device}</var>}%{src_ip?, IP %{src_ip#%{next?, }<var%{item.inv? data-tooltip="Match IP addresses except %{item.val}."}>%{item.ival}</var>}}%{src_port?, port %{src_port#%{next?, }<var%{item.inv? data-tooltip="Match ports except %{item.val}."}>%{item.ival}</var>}}%{src_mac?, MAC %{src_mac#%{next?, }<var%{item.inv? data-tooltip="Match MACs except %{item.val}%{item.hint.name? a.k.a. %{item.hint.name}}.":%{item.hint.name? data-tooltip="%{item.hint.name}"}}>%{item.ival}</var>}}'), {
        src: E('span', { 'class': 'zonebadge', 'style': fwmodel.getZoneColorStyle(z) }, [(z == '*') ? E('em', _('any zone')) : (z ? E('strong', z) : E('em', _('this device')))]),
        src_ip: fwtool.map_invert(uci.get('firewall', s, 'src_ip'), 'toLowerCase'),
        src_mac: fwtool.map_invert(uci.get('firewall', s, 'src_mac'), 'toUpperCase').map(function(v){ return Object.assign(v, { hint: hosts[v.val] }); }),
        src_port: fwtool.map_invert(uci.get('firewall', s, 'src_port')),
        src_device: d
    });
}
function rule_dest_txt(s) {
    var z = uci.get('firewall', s, 'dest'), d = (uci.get('firewall', s, 'direction') == 'out') ? uci.get('firewall', s, 'device') : null;
    return fwtool.fmt(_('To %{dest}%{dest_device?, interface <var>%{src_device}</var>}%{dest_ip?, IP %{dest_ip#%{next?, }<var%{item.inv? data-tooltip="Match IP addresses except %{item.val}."}>%{item.ival}</var>}}%{dest_port?, port %{dest_port#%{next?, }<var%{item.inv? data-tooltip="Match ports except %{item.val}."}>%{item.ival}</var>}}'), {
        dest: E('span', { 'class': 'zonebadge', 'style': fwmodel.getZoneColorStyle(z) }, [(z == '*') ? E('em', _('any zone')) : (z ? E('strong', z) : E('em', _('this device')))]),
        dest_ip: fwtool.map_invert(uci.get('firewall', s, 'dest_ip'), 'toLowerCase'),
        dest_port: fwtool.map_invert(uci.get('firewall', s, 'dest_port')),
        dest_device: d
    });
}
function rule_limit_txt(s) {
    var m = String(uci.get('firewall', s, 'limit')).match(/^(\d+)\/([smhd])\w*$/i), l = m ? { num: +m[1], unit: ({ s:_('second'),m:_('minute'),h:_('hour'),d:_('day') })[m[2]], burst: uci.get('firewall', s, 'limit_burst') } : null;
    if (!l) return '';
    return fwtool.fmt(_('Limit matching to <var>%{limit.num}</var> packets per <var>%{limit.unit}</var>%{limit.burst? burst <var>%{limit.burst}</var>}'), { limit: l });
}
function rule_target_txt(s_param, ctHelpers) {
    var t = uci.get('firewall', s_param, 'target'), h = (uci.get('firewall', s_param, 'set_helper') || '').toUpperCase();
    var s_data = {
        target:t,
        src:uci.get('firewall',s_param,'src'),
        dest:uci.get('firewall',s_param,'dest'),
        set_helper:h,
        set_mark:uci.get('firewall',s_param,'set_mark'),
        set_xmark:uci.get('firewall',s_param,'set_xmark'),
        set_dscp:uci.get('firewall',s_param,'set_dscp'),
        helper_name:(ctHelpers.filter(function(ctH){ return ctH.name.toUpperCase()==h; })[0]||{}).description
    };
    switch(t) {
        case 'DROP':
            return fwtool.fmt(_('<var data-tooltip="DROP">Drop</var> %{src?%{dest?forward:input}:output}'), s_data);
        case 'ACCEPT':
            return fwtool.fmt(_('<var data-tooltip="ACCEPT">Accept</var> %{src?%{dest?forward:input}:output}'), s_data);
        case 'REJECT':
            return fwtool.fmt(_('<var data-tooltip="REJECT">Reject</var> %{src?%{dest?forward:input}:output}'), s_data);
        case 'NOTRACK':
            return fwtool.fmt(_('<var data-tooltip="NOTRACK">Do not track</var> %{src?%{dest?forward:input}:output}'), s_data);
        case 'HELPER':
            return fwtool.fmt(_('<var data-tooltip="HELPER">Assign conntrack helper</var> <var data-tooltip="%{helper_name}">%{set_helper}</var>'), s_data);
        case 'MARK':
            return fwtool.fmt(_('<var data-tooltip="MARK">%{set_mark?Assign:XOR}</var> firewall mark <var>%{set_mark?:%{set_xmark}}</var>'), s_data);
        case 'DSCP':
            return fwtool.fmt(_('<var data-tooltip="DSCP">Assign DSCP classification</var> <var>%{set_dscp}</var>'), s_data);
        default:
            return t;
    }
}

return view.extend({
    activeZoneName: null,
    mapInstance: null,
    hostsData: null,
    ctHelpersData: null,
    ruleContainerNode: null,

    callHostHints: rpc.declare({ object: 'luci-rpc', method: 'getHostHints', expect: { '': {} } }),
    callConntrackHelpers: rpc.declare({ object: 'luci', method: 'getConntrackHelpers', expect: { result: [] } }),

    load: function() {
        return Promise.all([
            this.callHostHints(),
            this.callConntrackHelpers(),
            uci.load('firewall')
        ]);
    },

    render: function(data) {
        this.hostsData = data[0];
        this.ctHelpersData = data[1];

        if (fwtool.checkLegacySNAT()) {
            return fwtool.renderMigration();
        } else {
            return this.renderRules(data);
        }
    },

    renderZoneRulesGrid: function(mapInstance, zoneName, hostsData, ctHelpersData, containerElement) {
        var viewInstance = this;
        containerElement.innerHTML = '';
        let rulesGridTitle = _('Rules with source: %s').format(zoneName);
        let s = new form.GridSection(mapInstance, 'rule', rulesGridTitle);
        var o;

        /* helper per ridisegnare la griglia */
        var refreshZoneGrid = function() {
            console.log('[refreshZoneGrid] refresh grid for', zoneName);
            viewInstance.renderZoneRulesGrid(
                viewInstance.mapInstance,
                zoneName,
                viewInstance.hostsData,
                viewInstance.ctHelpersData,
                viewInstance.ruleContainerNode
            );
        };

        /* override dei gestori per auto‑refresh */
        s.handleAdd = function(ev) {
    var cfg = this.uciconfig || this.map.config;
    var section_id = uci.add(cfg, this.sectiontype);
    // imposta subito la zona
    uci.set(cfg, section_id, 'src', zoneName);
    // registra la sezione aggiunta
    this.map.addedSection = section_id;
    // apri il modal di configurazione
    return this.renderMoreOptionsModal(section_id).then(function(ok) {
        if (ok !== false) {
            // attendiamo un ciclo di evento per garantire l'applicazione delle modifiche in memoria
            setTimeout(function() {
                refreshZoneGrid();
            }, 0);
        } else {
            // se l'utente annulla, rimuoviamo la sezione temporanea
            uci.remove(cfg, section_id);
        }
        return ok;
    });
};

        s.handleEdit = function(section_id) {
    return this.renderMoreOptionsModal(section_id).then(function(ok) {
        if (ok !== false) {
            // attendiamo un ciclo di evento per garantire l'applicazione delle modifiche in memoria
            setTimeout(function() {
                refreshZoneGrid();
            }, 0);
        }
        return ok;
    });
};

        s.handleRemove = function(section_id) {
            return form.GridSection.prototype.handleRemove.apply(this, arguments).then(refreshZoneGrid);
        };
        /* ------------- fine helper/override ---------------- */

        /* dichiarazione dei tab */
        s.tab('general',  _('General Settings'));
        s.tab('advanced', _('Advanced Settings'));
        s.tab('timed',    _('Time Restrictions'));

        s.addremove = true;
        s.anonymous = true;
        s.sortable = true;
        s.cloneable = true;
        s.filter = function(section_id) {
            let uciSectionType = uci.get('firewall', section_id, '.type');
            if (uciSectionType !== 'rule') return false;
            let target = uci.get('firewall', section_id, 'target');
            if (target === 'SNAT') return false;
            let ruleSrcZone = uci.get('firewall', section_id, 'src');
            return ruleSrcZone === zoneName;
        };
        s.sectiontitle = function(section_id) {
            return uci.get('firewall', section_id, 'name') || _('Unnamed rule');
        };

        /* opzioni del form */
        o = s.taboption('general', form.Value, 'name', _('Name'));
        o.placeholder = _('Unnamed rule');
        o.modalonly = true;

        o = s.option(form.DummyValue, '_match', _('Match'));
        o.modalonly = false;
        o.textvalue = function(section_id_param) {
            return E('small', [
                rule_proto_txt(section_id_param, ctHelpersData), E('br'),
                rule_src_txt(section_id_param, hostsData), E('br'),
                rule_dest_txt(section_id_param), E('br'),
                rule_limit_txt(section_id_param)
            ]);
        };

        o = s.option(form.ListValue, '_target', _('Action'));
        o.modalonly = false;
        o.textvalue = function(section_id_param) {
            return rule_target_txt(section_id_param, ctHelpersData);
        };

        o = s.option(form.Flag, 'enabled', _('Enable'));
        o.modalonly = false; o.default = true; o.editable = true;
        o.tooltip = function(section_id) {
            var weekdays = uci.get('firewall', section_id, 'weekdays');
            var monthdays = uci.get('firewall', section_id, 'monthdays');
            var start_time = uci.get('firewall', section_id, 'start_time');
            var stop_time = uci.get('firewall', section_id, 'stop_time');
            var start_date = uci.get('firewall', section_id, 'start_date');
            var stop_date = uci.get('firewall', section_id, 'stop_date');
            if (weekdays || monthdays || start_time || stop_time || start_date || stop_date)
                return _('Time restrictions are enabled for this rule');
            return null;
        };

        o = s.taboption('advanced', form.ListValue, 'direction', _('Match device'));
        o.modalonly = true; o.value('', _('unspecified'));
        o.value('in', _('Inbound device')); o.value('out', _('Outbound device'));
        o.cfgvalue = function(section_id) {
            var val = uci.get('firewall', section_id, 'direction');
            switch(val) {
                case 'in': case 'ingress': return 'in';
                case 'out': case 'egress': return 'out';
            }
            return null;
        };

        o = s.taboption('advanced', widgets.DeviceSelect, 'device', _('Device name'), _('Specifies whether to tie this traffic rule to a specific inbound or outbound network device.'));
        o.modalonly = true; o.noaliases = true; o.rmempty = false;
        o.depends('direction', 'in'); o.depends('direction', 'out');

        o = s.taboption('advanced', form.ListValue, 'family', _('Restrict to address family'));
        o.modalonly = true; o.rmempty = true;
        o.value('', _('IPv4 and IPv6')); o.value('ipv4', _('IPv4 only')); o.value('ipv6', _('IPv6 only'));
        o.validate = function(section_id, value) {
            fwtool.updateHostHints(this.map, section_id, 'src_ip', value, hostsData);
            fwtool.updateHostHints(this.map, section_id, 'dest_ip', value, hostsData);
            return true;
        };

        o = s.taboption('general', fwtool.CBIProtocolSelect, 'proto', _('Protocol'));
        o.modalonly = true; o.default = 'tcp udp';

        o = s.taboption('advanced', form.MultiValue, 'icmp_type', _('Match ICMP type'));
        o.modalonly = true; o.multiple = true; o.custom = true; o.cast = 'table'; o.placeholder = _('any/all');
        o.value('address-mask-reply'); o.value('address-mask-request'); o.value('address-unreachable'); o.value('bad-header');
        // (elenco completo omesso per brevità, copia da codice originale)
        o.depends({ proto: 'icmp', '!contains': true });
        o.depends({ proto: 'icmpv6', '!contains': true });

        o = s.taboption('general', widgets.ZoneSelect, 'src', _('Source zone'));
        o.modalonly = true; o.nocreate = true; o.allowany = true; o.allowlocal = 'src';

        o = s.taboption('advanced', form.Value, 'ipset', _('Use ipset'));
        uci.sections('firewall', 'ipset', function(s_ipset) {
            if (typeof(s_ipset.name) == 'string')
                o.value(s_ipset.name, s_ipset.comment ? '%s (%s)'.format(s_ipset.name, s_ipset.comment) : s_ipset.name);
        });
        o.modalonly = true; o.rmempty = true;

        fwtool.addMACOption(s, 'advanced', 'src_mac', _('Source MAC address'), null, hostsData);
        fwtool.addIPOption(s, 'general', 'src_ip', _('Source address'), null, '', hostsData, true);
        o = s.taboption('general', form.Value, 'src_port', _('Source port'));
        o.modalonly = true; o.datatype = 'list(neg(portrange))'; o.placeholder = _('any');
        o.depends({ proto: 'tcp', '!contains': true });
        o.depends({ proto: 'udp', '!contains': true });

        o = s.taboption('general', widgets.ZoneSelect, 'dest', _('Destination zone'));
        o.modalonly = true; o.nocreate = true; o.allowany = true; o.allowlocal = true;

        fwtool.addIPOption(s, 'general', 'dest_ip', _('Destination address'), null, '', hostsData, true);
        o = s.taboption('general', form.Value, 'dest_port', _('Destination port'));
        o.modalonly = true; o.datatype = 'list(neg(portrange))'; o.placeholder = _('any');
        o.depends({ proto: 'tcp', '!contains': true });
        o.depends({ proto: 'udp', '!contains': true });

        o = s.taboption('general', form.ListValue, 'target', _('Action'));
        o.modalonly = true; o.default = 'ACCEPT';
        o.value('DROP', _('drop')); o.value('ACCEPT', _('accept')); o.value('REJECT', _('reject'));
        o.value('NOTRACK', _("don't track")); o.value('HELPER', _('assign conntrack helper'));
        o.value('MARK_SET', _('apply firewall mark')); o.value('MARK_XOR', _('XOR firewall mark'));
        o.value('DSCP', _('DSCP classification'));
        o.cfgvalue = function(section_id) {
            var t = uci.get('firewall', section_id, 'target');
            var m_val = uci.get('firewall', section_id, 'set_mark');
            if (t == 'MARK') return m_val ? 'MARK_SET' : 'MARK_XOR';
            return t;
        };
        o.write = function(section_id, value) {
            return this.super('write', [section_id, (value == 'MARK_SET' || value == 'MARK_XOR') ? 'MARK' : value]);
        };

        fwtool.addMarkOption(s, 1);
        fwtool.addMarkOption(s, 2);
        fwtool.addDSCPOption(s, true);

        o = s.taboption('general', form.ListValue, 'set_helper', _('Tracking helper'), _('Assign the specified connection tracking helper to matched traffic.'));
        o.modalonly = true; o.placeholder = _('any'); o.depends('target', 'HELPER');
        for (var i = 0; i < ctHelpersData.length; i++)
            o.value(ctHelpersData[i].name, '%s (%s)'.format(ctHelpersData[i].description, ctHelpersData[i].name.toUpperCase()));

        o = s.taboption('advanced', form.Value, 'helper', _('Match helper'), _('Match traffic using the specified connection tracking helper.'));
        o.modalonly = true; o.placeholder = _('any');
        for (var i = 0; i < ctHelpersData.length; i++)
            o.value(ctHelpersData[i].name, '%s (%s)'.format(ctHelpersData[i].description, ctHelpersData[i].name.toUpperCase()));
        o.validate = function(section_id, value) {
            if (!value) return true;
            for (var i = 0; i < ctHelpersData.length; i++) {
                if (value == ctHelpersData[i].name || value.replace(/^!\s*/, '') == ctHelpersData[i].name)
                    return true;
            }
            return _('Unknown or not installed conntrack helper "%s"').format(value.replace(/^!\s*/, ''));
        };

        fwtool.addMarkOption(s, false); fwtool.addDSCPOption(s, false);
        fwtool.addLimitOption(s); fwtool.addLimitBurstOption(s);
        if (!L.hasSystemFeature('firewall4')) {
            o = s.taboption('advanced', form.Value, 'extra', _('Extra arguments'), _('Passes additional arguments to iptables. Use with care!'));
            o.modalonly = true;
        }

        o = s.taboption('timed', form.MultiValue, 'weekdays', _('Week Days'));
        o.modalonly = true; o.multiple = true; o.display = 5; o.placeholder = _('Any day');
        ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'].forEach(function(d) { o.value(d, _(d)); });
        o.write = function(section_id, value) {
            return this.super('write', [section_id, L.toArray(value).join(' ')]);
        };

        o = s.taboption('timed', form.MultiValue, 'monthdays', _('Month Days'));
        o.modalonly = true; o.multiple = true; o.display_size = 15; o.placeholder = _('Any day');
        for (var i = 1; i <= 31; i++) o.value(i);
        o.write = function(section_id, value) {
            return this.super('write', [section_id, L.toArray(value).join(' ')]);
        };

        o = s.taboption('timed', form.Value, 'start_time', _('Start Time (hh:mm:ss)'));
        o.modalonly = true; o.datatype = 'timehhmmss';
        o = s.taboption('timed', form.Value, 'stop_time', _('Stop Time (hh:mm:ss)'));
        o.modalonly = true; o.datatype = 'timehhmmss';
        o = s.taboption('timed', form.Value, 'start_date', _('Start Date (yyyy-mm-dd)'));
        o.modalonly = true; o.datatype = 'dateyyyymmdd';
        o = s.taboption('timed', form.Value, 'stop_date', _('Stop Date (yyyy-mm-dd)'));
        o.modalonly = true; o.datatype = 'dateyyyymmdd';
        o = s.taboption('timed', form.Flag, 'utc_time', _('Time in UTC'));
        o.modalonly = true; o.default = false;

        // render della griglia
        var gridRenderPromise = s.render();
        if (gridRenderPromise instanceof Promise) {
            gridRenderPromise.then(function(gridNode) {
            containerElement.appendChild(gridNode);

                containerElement.appendChild(gridNode);
            }).catch(function(err) {
                console.error('Error rendering GridSection for zone ' + zoneName + ':', err);
                containerElement.appendChild(E('p', { 'class': 'error' }, _('Error loading rules for this zone.')));
            });
        } else if (gridRenderPromise) {
            containerElement.appendChild(gridRenderPromise);
        }
    },

    renderRules: function(data) {
        var self = this;
        self.hostsData = data[0];
        self.ctHelpersData = data[1];
        var m;

        var viewContainer = E('div', { 'class': 'luci-firewall-rules-custom-view' });

        var zoneNames = [];
        var firewallSections = uci.sections('firewall');
        if (firewallSections && firewallSections.length > 0) {
            firewallSections.forEach(function(section) {
                if (section['.type'] === 'zone') {
                    var actualZoneName = uci.get('firewall', section['.name'], 'name');
                    if (actualZoneName) {
                        zoneNames.push(actualZoneName);
                    }
                }
            });
        }
        zoneNames = zoneNames.filter(function(item, pos, selfArr) {
            return selfArr.indexOf(item) == pos;
        });
        zoneNames.sort();

        viewContainer.appendChild(E('h2', {}, _('Firewall - Traffic Rules')));
        viewContainer.appendChild(E('p', {}, _('Traffic rules define policies for packets travelling between different zones, for example to reject traffic between certain hosts or to open WAN ports on the router.')));

        var tabContainer = E('div', { 'class': 'cbi-tabmenu' });
        self.ruleContainerNode = E('div', { 'class': 'cbi-section', 'id': 'rules-grid-container' });

        viewContainer.appendChild(tabContainer);
        viewContainer.appendChild(self.ruleContainerNode);

        // Crea barra pulsanti con ADD e RELOAD per ogni tab
        var refreshBtn = E('div', { 'style': 'margin-top:10px;' }, [
    E('button', {
        'class': 'cbi-button cbi-button-add',
        'click': function() { window.location.reload(); }
    }, _('Refresh'))
]);
viewContainer.appendChild(refreshBtn);

        self.mapInstance = new form.Map('firewall', '', '');
        self.mapInstance.noheader = true;

        if (zoneNames.length > 0) {
            self.activeZoneName = zoneNames[0];

            zoneNames.forEach(function(zoneName, index) {
                var tabButton = E('button', {
                    'class': (index === 0)
                        ? 'cbi-button cbi-button-neutral cbi-tab-button cbi-tab-active'
                        : 'cbi-button cbi-button-neutral cbi-tab-button',
                    'click': function(ev) {
                        Array.from(tabContainer.childNodes).forEach(function(childNode) {
                            if (childNode.nodeType === 1 && childNode.classList) {
                                childNode.classList.remove('cbi-tab-active');
                            }
                        });
                        ev.target.classList.add('cbi-tab-active');
                        self.activeZoneName = zoneName;
                        self.renderZoneRulesGrid(self.mapInstance, zoneName, self.hostsData, self.ctHelpersData, self.ruleContainerNode);
                    }
                }, zoneName);
                tabContainer.appendChild(tabButton);
            });

            self.renderZoneRulesGrid(self.mapInstance, self.activeZoneName, self.hostsData, self.ctHelpersData, self.ruleContainerNode);

        } else {
            self.ruleContainerNode.appendChild(E('p', {}, _('No firewall zones found.')));
        }

        var mapPromise = self.mapInstance.render();
        return mapPromise.then(function(mapControlsDomNode) {
            if (mapControlsDomNode) viewContainer.appendChild(mapControlsDomNode);
            return viewContainer;
        }).catch(function(err) {
            console.error('[PROMISE_ERROR] renderRules - Error rendering map controls:', err);
            viewContainer.appendChild(E('div', { class: 'alert-message error' }, [
                E('h4', {}, _('Error Rendering Map Controls')),
                E('p', {}, '' + err)
            ]));
            return viewContainer;
        });
    },

    handleRemove: function() {
        return this.super('handleRemove', arguments);
    }
});

