"""Offline directory inventory. © Nasser Aldin Farag (0xFarag). All rights reserved."""
import ipaddress
import re

from .evidence_formats import MAX_ROWS, canonical, read_json, sha


LABELS = {'bloodhound': 'BloodHound', 'neo4j': 'Neo4j'}
NODE_TYPES = {'User', 'Group', 'Computer', 'Domain', 'OU', 'Container'}
MEMBER_TYPES = {'User', 'Group', 'Computer'}
CONTAINERS = {'Domain', 'OU', 'Container'}
ALIAS = re.compile(r'[0-9a-f]{32}\Z')
ACCOUNT_SID = re.compile(r'(S-1-5-21-[0-9]{1,10}-[0-9]{1,10}-[0-9]{1,10})-[0-9]{1,10}\Z')
APOC_ID = re.compile(r'[A-Za-z0-9_.:-]{1,128}\Z')


def _need(ok):
    if not ok:
        raise ValueError('invalid graph inventory')


def _row(fmt, digest, domain, inventory):
    kind = inventory['kind']
    rule = 'node-' + inventory['nodeType'] if kind == 'node' else inventory['relation']
    ident = sha(canonical([digest, domain, inventory]))[:32]
    return {'source': LABELS[fmt], 'host': domain, 'id': fmt + '-' + ident, 'method': 'INVENTORY',
            'path': '/', 'status': None, 'marker': False, 'rule': rule, 'inventory': inventory}


def _account_sid(value):
    _need(isinstance(value, str))
    match = ACCOUNT_SID.fullmatch(value)
    _need(match and all(int(part) <= 0xffffffff for part in value.split('-')[4:]))
    return match.group(1)


def _apoc_id(value):
    _need(isinstance(value, str) and APOC_ID.fullmatch(value))
    return value


def _bloodhound(text, add_node, add_edge):
    document = read_json(text)
    meta, groups = document['meta'], document['data']
    _need(type(meta['version']) is int and meta['version'] in (5, 6) and meta['type'] == 'groups')
    _need(isinstance(groups, list) and type(meta['count']) is int and meta['count'] == len(groups) <= MAX_ROWS)
    domains = {}
    domain_sids = {}
    for group in groups:
        group_id, props = group['ObjectIdentifier'], group['Properties']
        domain_sid = _account_sid(group_id)
        _need(props.get('domainsid', domain_sid) == domain_sid)
        domain = add_node(group_id, props['domain'], 'Group', False)
        _need(domains.setdefault(domain, domain_sid) == domain_sid and domain_sids.setdefault(domain_sid, domain) == domain)
        members = group['Members']
        _need(isinstance(members, list) and len(members) <= MAX_ROWS)
        for member in members:
            ident, kind = member['ObjectIdentifier'], member['ObjectType']
            _need(kind in MEMBER_TYPES and _account_sid(ident) == domain_sid)
            add_node(ident, domain, kind, True)
            add_edge(ident, group_id, 'MemberOf')


def _apoc_type(labels):
    _need(isinstance(labels, list) and 1 <= len(labels) <= 2 and len(labels) == len(set(labels)))
    kinds = set(labels) - {'Base'}
    _need(len(kinds) == 1 and kinds <= NODE_TYPES)
    return kinds.pop()


def _domain(value, safe_host):
    domain = safe_host(value)
    _need('.' in domain)
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        return domain
    raise ValueError('explicit DNS domain required')


def _neo4j(text, add_node, add_edge, nodes, safe_host):
    rel_ids = set()
    endpoint_claims = []
    for line in text.splitlines():
        if not line.strip():
            continue
        item = read_json(line)
        ident = _apoc_id(item['id'])
        if item['type'] == 'node':
            add_node(ident, item['properties']['domain'], _apoc_type(item['labels']), False)
        else:
            _need(item['type'] == 'relationship' and ident not in rel_ids)
            rel_ids.add(ident)
            for endpoint in (item['start'], item['end']):
                node_id = _apoc_id(endpoint['id'])
                kind = _apoc_type(endpoint['labels']) if 'labels' in endpoint else None
                props = endpoint.get('properties', {})
                _need(isinstance(props, dict))
                domain = _domain(props['domain'], safe_host) if 'domain' in props else None
                endpoint_claims.append((node_id, kind, domain))
            add_edge(item['start']['id'], item['end']['id'], item['label'])
    for node_id, kind, domain in endpoint_claims:
        _need(node_id in nodes)
        node_domain, node_kind, _ = nodes[node_id]
        _need((domain is None or domain == node_domain) and (kind is None or kind == node_kind))


def import_graph(fmt, digest, text, safe_host):
    nodes, edges = {}, set()

    def add_node(ident, domain, kind, reference):
        domain = _domain(domain, safe_host)
        previous = nodes.get(ident)
        if previous:
            _need(previous[:2] == (domain, kind) and (previous[2] or reference))
            reference = previous[2] and reference
        nodes[ident] = (domain, kind, reference)
        _need(len(nodes) + len(edges) <= MAX_ROWS)
        return domain

    def add_edge(start, end, relation):
        _need(relation in ('MemberOf','Contains') and start != end)
        edge = (start, end, relation)
        _need(edge not in edges)
        edges.add(edge)
        _need(len(nodes) + len(edges) <= MAX_ROWS)

    if fmt == 'bloodhound':
        _bloodhound(text, add_node, add_edge)
    else:
        _neo4j(text, add_node, add_edge, nodes, safe_host)
    rows, aliases = [], {}
    for ident, (domain, kind, ref) in nodes.items():
        alias = sha(canonical([fmt, digest, domain, ident]))[:32]
        aliases[ident] = alias
        rows.append(_row(fmt, digest, domain, {'kind':'node', 'node':alias, 'nodeType':kind, 'referenceOnly':ref}))
    for start, end, relation in sorted(edges):
        _need(start in nodes and end in nodes and nodes[start][0] == nodes[end][0])
        rows.append(_row(fmt, digest, nodes[start][0], {
            'kind':'edge', 'from':aliases[start], 'to':aliases[end], 'relation':relation}))
    return rows


def validate_rows(fmt, digest, rows, safe_host):
    """Replay projected graph invariants, including type, domain and referential integrity."""
    nodes, edges = {}, []
    for row in rows:
        _need(isinstance(row, dict) and set(row) == {'source','host','id','method','path','status','marker','rule','inventory'})
        info, domain = row['inventory'], _domain(row['host'], safe_host)
        _need(isinstance(info, dict))
        if info['kind'] == 'node':
            _need(set(info) == {'kind','node','nodeType','referenceOnly'})
            alias, kind, ref = info['node'], info['nodeType'], info['referenceOnly']
            _need(isinstance(alias, str) and ALIAS.fullmatch(alias) and alias not in nodes)
            _need(kind in NODE_TYPES and type(ref) is bool and (fmt == 'bloodhound' or not ref))
            if fmt == 'bloodhound':
                _need(kind in MEMBER_TYPES and (ref or kind == 'Group'))
            nodes[alias] = (domain, kind, ref)
        else:
            _need(info['kind'] == 'edge' and set(info) == {'kind','from','to','relation'})
            _need(info['relation'] in ('Contains','MemberOf') and (fmt == 'neo4j' or info['relation'] == 'MemberOf'))
            edges.append((domain, info['from'], info['to'], info['relation']))
        # Compare canonical bytes so JSON false cannot be replaced by numeric zero in a signed input.
        _need(canonical(row) == canonical(_row(fmt, digest, domain, info)))
    _need(len(set(edges)) == len(edges))
    referenced = set()
    for domain, start, end, relation in edges:
        _need(start != end and start in nodes and end in nodes and nodes[start][0] == nodes[end][0] == domain)
        if relation == 'MemberOf':
            _need(nodes[start][1] in MEMBER_TYPES and nodes[end][1] == 'Group')
            if fmt == 'bloodhound':
                _need(not nodes[end][2])
            referenced.add(start)
        else:
            _need(nodes[start][1] in CONTAINERS)
    _need(not any(ref and alias not in referenced for alias, (_, _, ref) in nodes.items()))
    return rows
