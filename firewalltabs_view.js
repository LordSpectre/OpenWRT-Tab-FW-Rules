'use strict';
'require view';
'require ui';
'require rpc';
'require uci';
'require form';
'require firewall as fwmodel';
'require tools.firewall as fwtool';

function rule_proto_txt(s, ctHelpers) {
    var f = (uci.get('firewall', s, 'family') || '').toLowerCase().replace(/^(?:any|\*)$/, '');
    var proto = L.toArray(uci.get('firewall', s, 'proto')).filter(function(p) {
        return (p != '*' && p != 'any' && p != 'all');
    }).map(function(p) {
        var pr = fwtool.lookupProto(p);
        return { num: pr[0], name: pr[1], types: (pr[0] == 1 || pr[0] == 58) ? L.toArray(uci.get('firewall', s, 'icmp_type')) : null };
    });
    var m = String(uci.get('firewall', s, 'helper') || '').match(/^(!\s*)?(\S+)$/);
    var h = m ? { val: m[0].toUpperCase(), inv: m[1], name: (ctHelpers.filter(function(ctH) { return ctH.name.toLowerCase() == m[2].toLowerCase(); })[0] || {}).description } : null;
    m = String(uci.get('firewall', s, 'mark')).match(/^(!\s*)?(0x[0-9a-f]{1,8}|[0-9]{1,10})(?:\/(0x[0-9a-f]{1,8}|[0-9]{1,10}))?$/i);
    var w = m ? { val: m[0].toUpperCase().replace(/X/g, 'x'), inv: m[1], num: '0x%02X'.format(+m[2]), mask: m[3] ? '0x%02X'.format(+m[3]) : null } : null;
    m = String(uci.get('firewall', s, 'dscp')).match(/^(!\s*)?(?:(CS[0-7]|BE|AF[1234][123]|EF)|(0x[0-9a-f]{1,2}|[0-9]{1,2}))$/);
    var d = m ? { val: m[0], inv: m[1], name: m[2], num: m[3] ? '0x%02X'.format(+m[3]) : null } : null;
    return fwtool.fmt(_('%{src?%{dest?Forwarded:Incoming}:Outgoing} %{ipv6?%{ipv4?<var>IPv4</var> and <var>IPv6</var>:<var>IPv6</var>}:<var>IPv4</var>}%{proto?, protocol %{proto#%{next?, }%{item.types?<var class="cbi-tooltip-container">%{item.name}<span class="cbi-tooltip">ICMP with types %{item.types#%{next?, }<var>%{item}</var>}</span></var>:<var>%{item.name}</var>}}}%{mark?, mark <var%{mark.inv? data-tooltip="Match fwmarks except %{mark.num}%{mark.mask? with mask %{mark.mask}}.":%{mark.mask? data-tooltip="Mask fwmark value with %{mark.mask} before compare."}}>%{mark.val}</var>}%{dscp?, DSCP %{dscp.inv?<var data-tooltip="Match DSCP classifications except %{dscp.num?:%{dscp.name}}">%{dscp.val}</var>:<var>%{dscp.val}</var>}}%{helper?, helper %{helper.inv?<var data-tooltip="Match any helper except &quot;%{helper.name}&quot;">%{helper.val}</var>:<var data-tooltip="%{helper.name}">%{helper.val}</var>}}'), {
        ipv4: (!f || f == 'ipv4'), ipv6: (!f || f == 'ipv6'), src: uci.get('firewall', s, 'src'), dest: uci.get('firewall', s, 'dest'), proto: proto, helper: h, mark: w, dscp: d
    });
}
function rule_src_txt(s, hosts) {
    var z = uci.get('firewall', s, 'src'), d = (uci.get('firewall', s, 'direction') == 'in') ? uci.get('firewall', s, 'device') : null;
    return fwtool.fmt(_('From %{src}%{src_device?, interface <var>%{src_device}</var>}%{src_ip?, IP %{src_ip#%{next?, }<var%{item.inv? data-tooltip="Match IP addresses except %{item.val}."}>%{item.ival}</var>}}%{src_port?, port %{src_port#%{next?, }<var%{item.inv? data-tooltip="Match ports except %{item.val}."}>%{item.ival}</var>}}%{src_mac?, MAC %{src_mac#%{next?, }<var%{item.inv? data-tooltip="Match MACs except %{item.val}%{item.hint.name? a.k.a. %{item.hint.name}}.":%{item.hint.name? data-tooltip="%{item.hint.name}"}}>%{item.ival}</var>}}'), {
        src: E('span', { 'class': 'zonebadge', 'style': fwmodel.getZoneColorStyle(z) }, [(z == '*') ? E('em', _('any zone')) : (z ? E('strong', z) : E('em', _('this device')))]),
        src_ip: fwtool.map_invert(uci.get('firewall', s, 'src_ip'), 'toLowerCase'),
        src_mac: fwtool.map_invert(uci.get('firewall', s, 'src_mac'), 'toUpperCase').map(function(v){ return Object.assign(v, { hint: hosts[v.val] }); }),
        src_port: fwtool.map_invert(uci.get('firewall', s, 'src_port')), src_device: d
    });
}
function rule_dest_txt(s) {
    var z = uci.get('firewall', s, 'dest'), d = (uci.get('firewall', s, 'direction') == 'out') ? uci.get('firewall', s, 'device') : null;
    return fwtool.fmt(_('To %{dest}%{dest_device?, interface <var>%{src_device}</var>}%{dest_ip?, IP %{dest_ip#%{next?, }<var%{item.inv? data-tooltip="Match IP addresses except %{item.val}."}>%{item.ival}</var>}}%{dest_port?, port %{dest_port#%{next?, }<var%{item.inv? data-tooltip="Match ports except %{item.val}."}>%{item.ival}</var>}}'), {
        dest: E('span', { 'class': 'zonebadge', 'style': fwmodel.getZoneColorStyle(z) }, [(z == '*') ? E('em', _('any zone')) : (z ? E('strong', z) : E('em', _('this device')))]),
        dest_ip: fwtool.map_invert(uci.get('firewall', s, 'dest_ip'), 'toLowerCase'),
        dest_port: fwtool.map_invert(uci.get('firewall', s, 'dest_port')), dest_device: d
    });
}
function rule_limit_txt(s) {
    var m = String(uci.get('firewall', s, 'limit')).match(/^(\d+)\/([smhd])\w*$/i), l = m ? { num: +m[1], unit: ({ s:_('second'),m:_('minute'),h:_('hour'),d:_('day') })[m[2]], burst: uci.get('firewall', s, 'limit_burst') } : null;
    if (!l) return '';
    return fwtool.fmt(_('Limit matching to <var>%{limit.num}</var> packets per <var>%{limit.unit}</var>%{limit.burst? burst <var>%{limit.burst}</var>}'), { limit: l });
}
function rule_target_txt(s_param, ctHelpers) {
    var t = uci.get('firewall', s_param, 'target'), h = (uci.get('firewall', s_param, 'set_helper') || '').toUpperCase(),
    s_data = { target:t, src:uci.get('firewall',s_param,'src'), dest:uci.get('firewall',s_param,'dest'), set_helper:h, set_mark:uci.get('firewall',s_param,'set_mark'), set_xmark:uci.get('firewall',s_param,'set_xmark'), set_dscp:uci.get('firewall',s_param,'set_dscp'), helper_name:(ctHelpers.filter(function(ctH){ return ctH.name.toUpperCase()==h; })[0]||{}).description };
    switch(t){ case 'DROP':return fwtool.fmt(_('<span class="zonebadge" style="background-color:#ff0000; color:white;">DROP</span> %{src?%{dest?forward:input}:output}'),s_data); case 'ACCEPT':return fwtool.fmt(_('<span class="zonebadge" style="background-color:#008000; color:white;">ACCEPT</span> %{src?%{dest?forward:input}:output}'),s_data); case 'REJECT':return fwtool.fmt(_('<span class="zonebadge" style="background-color:#ffa500; color:white;">REJECT</span> %{src?%{dest?forward:input}:output}'),s_data); case 'NOTRACK':return fwtool.fmt(_('<span class="zonebadge" style="background-color:#808080; color:white;">NOTRACK</span> %{src?%{dest?forward:input}:output}'),s_data); case 'HELPER':return fwtool.fmt(_('Assign conntrack helper <var data-tooltip="%{helper_name}">%{set_helper}</var>'),s_data); case 'MARK':return fwtool.fmt(_('%{set_mark?Assign:XOR} firewall mark <var>%{set_mark?:%{set_xmark}}</var>'),s_data); case 'DSCP':return fwtool.fmt(_('Assign DSCP classification <var>%{set_dscp}</var>'),s_data); default:return t; }
}

return view.extend({
    activeZoneName: null,
    mapInstanceForContext: null, 
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

    injectCSS: function(cssString) {
        var style = document.createElement('style');
        style.type = 'text/css';
        style.appendChild(document.createTextNode(cssString));
        document.head.appendChild(style);
    },

    render: function(data) {
        this.hostsData = data[0];
        this.ctHelpersData = data[1];
        
        this.mapInstanceForContext = new form.Map('firewall', '', '');
                this.mapInstanceForContext.noheader = true;

        // Inietta una regola CSS per nascondere i pulsanti di modifica
        // Usiamo !important per cercare di sovrascrivere regole CSS preesistenti
        this.injectCSS('.cbi-button-edit { display: none !important; }');
        // Se il selettore sopra non funziona, prova questo sotto commentando quello sopra:
        // this.injectCSS('.cbi-section table tbody tr td:last-child .cbi-button { display: none !important; }');

        var viewContainer = E('div', { 'class': 'luci-firewall-tabbedrules-view' });
        var zoneNames = [];
        var firewallSections = uci.sections('firewall', 'zone'); 
        if (firewallSections && firewallSections.length > 0) {
            firewallSections.forEach(function(section) {
                if (section.name) { 
                    zoneNames.push(section.name);
                }
            });
        }
        zoneNames.sort();
        
        viewContainer.appendChild(E('h2', {}, _('Firewall Rules - Tabbed View')));
        viewContainer.appendChild(E('p', {}, _('This page displays firewall traffic rules grouped by source zone. This is a read-only view.')));

        var tabContainer = E('div', { 'class': 'cbi-tabmenu' });
        this.ruleContainerNode = E('div', { 'class': 'cbi-section', 'id': 'tabbed-rules-grid-container' }); 

        viewContainer.appendChild(tabContainer);
        viewContainer.appendChild(this.ruleContainerNode);

        if (zoneNames.length > 0) {
            this.activeZoneName = zoneNames[0]; 
            zoneNames.forEach(function(zoneName, index) {
                var tabButton = E('button', {
                    'class': (index === 0) ? 'cbi-button cbi-button-neutral cbi-tab-button cbi-tab-active' : 'cbi-button cbi-button-neutral cbi-tab-button',
                    'click': function(ev) {
                        Array.from(tabContainer.childNodes).forEach(function(childNode) {
                            if (childNode.nodeType === 1 && childNode.classList) { 
                                childNode.classList.remove('cbi-tab-active');
                            }
                        });
                        ev.target.classList.add('cbi-tab-active');
                        this.activeZoneName = zoneName; 
                        this.renderZoneRulesGridReadOnly(this.activeZoneName);
                    }.bind(this) 
                }, zoneName);
                tabContainer.appendChild(tabButton);
            }, this);
            
            this.renderZoneRulesGridReadOnly(this.activeZoneName);
        } else {
            this.ruleContainerNode.appendChild(E('p', {}, _('No firewall zones found.')));
        }
        
        return viewContainer;
    },

    renderZoneRulesGridReadOnly: function(zoneName) {
        if (!this.ruleContainerNode) return;
        this.ruleContainerNode.innerHTML = ''; 
        let rulesGridTitle = _('Rules with source: %s').format(zoneName);
        
        let s = new form.GridSection(this.mapInstanceForContext, 'rule', rulesGridTitle);
        var o;

        s.anonymous = true; 
        s.addremove = false; 
        s.sortable = false;  
        s.cloneable = false; 
        s.editable = false; 
        s.itemactions = []; 

        s.filter = function(section_id) {
            let uciSectionType = uci.get('firewall', section_id, '.type');
            if (uciSectionType !== 'rule') return false;
            let target = uci.get('firewall', section_id, 'target');
            if (target === 'SNAT') return false; 
            let ruleSrcZone = uci.get('firewall', section_id, 'src');
            return ruleSrcZone === zoneName;
        };
        
        o = s.option(form.DummyValue, '_enabled_display', _('Enabled'));
        o.editable = false;
        o.textvalue = function(section_id) {
            var enabled_val = uci.get('firewall', section_id, 'enabled');
            if (enabled_val === '0' || enabled_val === 'false') {
                return _('No');
            } else {
                return _('Yes');
            }
        };

        o = s.option(form.DummyValue, '_name_display', _('Name'));
        o.textvalue = function(section_id) {
             return uci.get('firewall', section_id, 'name') || E('em', '-');
        };

        o = s.option(form.DummyValue, '_match', _('Match'));
        o.textvalue = function(section_id_param) { 
            return E('small', [
                rule_proto_txt(section_id_param, this.map.view.ctHelpersData), E('br'),
                rule_src_txt(section_id_param, this.map.view.hostsData), E('br'),
                rule_dest_txt(section_id_param), E('br'),
                rule_limit_txt(section_id_param)
            ]);
        }.bind({map: {view: this}});

        o = s.option(form.DummyValue, '_action_display', _('Action')); 
        o.textvalue = function(section_id_param) { 
            return rule_target_txt(section_id_param, this.map.view.ctHelpersData);
        }.bind({map: {view: this}});

        var gridRenderPromise = s.render();
        if (gridRenderPromise instanceof Promise) {
            gridRenderPromise.then(function(resolvedGridNode) {
                if (resolvedGridNode) {
                    this.ruleContainerNode.appendChild(resolvedGridNode);
                }
            }.bind(this)).catch(function(err) {
                this.ruleContainerNode.appendChild(E('p', { 'class': 'error' }, _('Error loading rules for this zone: %s').format(err.message)));
            }.bind(this));
        } else if (gridRenderPromise) { 
            this.ruleContainerNode.appendChild(gridRenderPromise);
        }
    },

    handleSaveApply: null,
    handleSave: null,
    handleReset: null
});
