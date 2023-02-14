# -*- coding: utf-8 -*-
from collections import namedtuple
import re
import json
import yaml
import requests
import salt.exceptions
from multiprocessing import Pool
from multiprocessing import cpu_count 




def zones(
        name,
        account,
        api_token=None,
        auth_email=None,
        auth_key=None,
        only_get_data=None,
        delete=None,
        paused=None,
        jump_start=None,
        zone_type=None
    ):
    command = 'zones'

    value_update = {
        'paused': paused,
        'type': zone_type
    }
    value_update = {key:val for key, val in value_update.items() if val != None}


    value_create = {
        'name': name,
        'account': account,
        'jump_start': jump_start,
        'type': zone_type
    }
    value_create = {key:val for key, val in value_create.items() if val != None}

    test = _get_test()
    result = {"name": name, "changes": {}, "comment": '', "result": None}

    method = "GET"
    configs_main = _get_configs_main()
    uri  = f"{configs_main['uri']}/zones?name={name}"
    resp = _request(uri, method=method, json=None, auth_email=auth_email, auth_key=auth_key, api_token=api_token)
    resp_result = resp.get('result', [])

    def _find_only_is_value(**kwargs):
        result = {}
        if kwargs['command'] == 'zones':
            if kwargs['account'].get('id'):
                id_name = 'id'
            else:
                id_name = 'name'
            for data in kwargs['data']:
                if data['name'] == kwargs['name'] and data['account'][id_name] == kwargs['account'].get(id_name):
                    return data
        return result

    data = _find_only_is_value(name=name, account=account, command=command, data=resp_result)

    if only_get_data == True:
        result["changes"] = data
        result['result'] = None if test else resp['success']
        result['comment'] = 'only get data zone'
        if not __opts__.get("zones.configs"):
            __opts__.update({"zones.configs":{}})
        __opts__["zones.configs"].update({name:data})
        return result

    if data:
        if delete == True:
            action = 'delete'
            method = 'DELETE'
            uri  = f"{configs_main['uri']}/zones/{data['id']}"
            result["changes"] = {command:f"{action} {command}: {name}"}
            if not test:
                resp = _request(uri, method=method, json=value_create, auth_email=auth_email, auth_key=auth_key, api_token=api_token)
                data = resp.get('result')
                result["changes"] = data
            result['result'] = None if test else resp['success']
            result['comment'] = f"{action}: zone {name} (id:{data['id']}), deleting zone"

        else:
            action = 'update'
            method = 'PATCH'
            uri  = f"{configs_main['uri']}/zones/{data['id']}"
            update_list = []
            success = [True]
            for key, value in value_update.items():
                if not value is None and data[key] != value:
                    update_list.append(f"{action} {key}: {data[key]} ---> {value}")
                    json = {key:value}
                    if not test:
                        resp = _request(uri, method=method, json=json, auth_email=auth_email, auth_key=auth_key, api_token=api_token)
                        data = resp.get('result')
                        success.append(resp['success'])
            if update_list:
                result["changes"] = {command:update_list}
                result['result'] = None if test else all(success)
                result['comment'] = f"{action}: zone {name} (id:{data['id']}) {str(len(update_list))}, parameters changed"
            else:
                action = 'ok'
                result['result'] = None if test else True
                result['comment'] = f"{action}: zone {name} (id:{data['id']}), zone exists, no changes required"

    else:
        if delete == True:
            action = 'ok'
            result['result'] = None if test else True
            result['comment'] = f"{action}: zone {name}, zone does not exist and should not exist"

        else:
            action = 'add'
            method = 'POST'
            uri  = f"{configs_main['uri']}/zones"
            result["changes"] = {command:f"{action} {command}: {name}"}
            if not test:
                resp = _request(uri, method=method, json=value_create, auth_email=auth_email, auth_key=auth_key, api_token=api_token)
                data = resp.get('result')
                result["changes"] = data
            result['result'] = None if test else resp['success']
            result['comment'] = f"{action}: zone {name} (id:{data.get('id','')}), creating a new zone"




    data.update({'delete':delete})
    data.update({'zone_action':action})
    if not __opts__.get("zones.configs"):
        __opts__.update({"zones.configs":{}})
    __opts__["zones.configs"].update({name:data})
    return result





def _get_configs_main():
    configs_main = (
        {
            'uri': "https://api.cloudflare.com/client/v4"
        }
    )
    return configs_main






def _request(uri, method="GET", json=None, auth_email=None, auth_key=None, api_token=None):
    if api_token:
        headers = {"Authorization": "Bearer {0}".format(api_token)}
    else:
        headers = {"X-Auth-Email": auth_email, "X-Auth-Key": auth_key}

    if method == "GET":
        resp = requests.get(uri, headers=headers)
    elif method == "POST":
        resp = requests.post(uri, headers=headers, json=json)
    elif method == "PATCH":
        resp = requests.patch(uri, headers=headers, json=json)
    elif method == "PUT":
        resp = requests.put(uri, headers=headers, json=json)
    elif method == "DELETE":
        resp = requests.delete(uri, headers=headers)
    else:
        raise Exception("Unknown request method: {0}".format(method))
    if not resp.ok:
        raise Exception(
            "Got HTTP code {0}: {1} URL:{2}".format(resp.status_code, resp.text, uri)
        )
    return resp.json()


def _get_test():
    if __opts__["test"] == True:
        test = True
    else:
        test = False
    return test



def _return_status_zone(name, zone, test, zone_action, zone_delete):
    if zone_delete == True:
        return {
            "name": name,
            "changes": {},
            "comment": f'zone {zone} does not exist and should not exist',
            "result": None if test else True
        }
    elif test == True and zone_action == 'add':
        return {
            "name": name,
            "changes": {},
            "comment": f'zone {zone} does not exist, but will be created',
            "result": None
        }
    else:
        return {
            "name": name,
            "changes": {},
            "comment": f'No cloudflare.zones function named {zone} in state, zone id not defined',
            "result": False
        }




def _return_only_get_data(zone_id, command, auth_email, auth_key, api_token, result, test):
    method = "GET"
    configs_main = _get_configs_main()
    uri  = f"{configs_main['uri']}/zones/{zone_id}/{command}"
    resp = _request(uri, method=method, json=None, auth_email=auth_email, auth_key=auth_key, api_token=api_token)
    data = resp.get('result', [])
    result["changes"] = {command:data}
    result['result'] = None if test else resp['success']
    result['comment'] = f'only get data {command}'
    return result



def _existing_by_page(uri, auth_email, auth_key, api_token):
    data = []
    success = [True]
    page = 1
    while True:
        uri = f'{uri}?page={page}'
        resp = _request(uri, method="GET", json=None, auth_email=auth_email, auth_key=auth_key, api_token=api_token)
        data += resp.get('result', [])
        success.append(resp['success'])
        current_page = resp["result_info"]["page"]
        total_pages = resp["result_info"]["total_pages"]
        if current_page == total_pages or total_pages == 0:
            break

        page += 1

    return data, all(success)








def ssl_universal_settings(
        name,
        zone,
        api_token=None,
        auth_email=None,
        auth_key=None,
        only_get_data=None,
        enabled=True,
        certificate_authority=None
    ):
    value_update = {
        'enabled': enabled,
        'certificate_authority': certificate_authority
    }
    value_update = {key:val for key, val in value_update.items() if val != None}

    command      = 'ssl/universal/settings'
    test         = _get_test()
    result       = {"name": name, "changes": {}, "comment": '', "result": None}
    zone_data    = __opts__.get("zones.configs", {}).get(zone, {})
    zone_id      = zone_data.get('id')
    zone_name    = zone_data.get('name')
    zone_delete  = zone_data.get('delete')
    zone_status  = zone_data.get('status')
    zone_action  = zone_data.get('zone_action')
    configs_main = _get_configs_main()
    uri          = f"{configs_main['uri']}/zones/{zone_id}/{command}"

    if zone_id and zone_name:
        pass
    else:
        return _return_status_zone(name, zone, test, zone_action, zone_delete)

    if only_get_data == True:
        return _return_only_get_data(zone_id, command, auth_email, auth_key, api_token, result, test)

    if zone_status != 'active':
        return {"name": name, "changes": {}, "comment": f"ok zone '{zone_name}' (id:{zone_id}) not active", "result": None}

    method = "GET"
    resp = _request(uri, method=method, json=None, auth_email=auth_email, auth_key=auth_key, api_token=None)
    data = resp.get('result', [])


    update_list = []
    update_dict = {}
    action = 'update'
    method = 'PATCH'
    for key, value in value_update.items():
        if key in data and data[key] != value and value != None:
            update_list.append(f"{action} {key}: {data[key]} ---> {value}")
            update_dict.update({key:value})

    action = 'add'
    method = 'PATCH'
    for key, value in value_update.items():
        if not key in data and value != None:
            update_list.append(f"{action} {key}: {value}")
            update_dict.update({key:value})


    if update_list:
        result["changes"] = {command:update_list}
        result['comment'] = f'update {command} zone {zone} (id:{zone_id}), apply changes ({str(len(update_list))})'
    else:
        result['comment'] = f'ok {command} zone {zone} (id:{zone_id}), no changes required'

    if not test and update_list is True:
        resp = _request(uri, method=method, json=update_dict, auth_email=auth_email, auth_key=auth_key, api_token=None)
        data = resp.get('result')


    result['result'] = None if test else resp['success']

    return result










def firewall_rules(
        name,
        zone,
        api_token=None,
        auth_email=None,
        auth_key=None,
        rules=None,
        only_get_data=None
    ):

    command       = 'firewall/rules'
    test          = _get_test()
    result        = {"name": name, "changes": {}, "comment": '', "result": None}
    zone_data     = __opts__.get("zones.configs", {}).get(zone, {})
    zone_id       = zone_data.get('id')
    zone_name     = zone_data.get('name')
    zone_delete   = zone_data.get('delete')
    zone_action   = zone_data.get('zone_action')
    configs_main  = _get_configs_main()
    uri_rules     = f"{configs_main['uri']}/zones/{zone_id}/{command}"
    uri_filters   = f"{configs_main['uri']}/zones/{zone_id}/filters"
    rules_yaml    = rules

    if zone_id and zone_name:
        pass
    else:
        return _return_status_zone(name, zone, test, zone_action, zone_delete)

    if only_get_data == True:
        data, success = _existing_by_page(uri_rules, auth_email, auth_key, api_token)
        result["changes"] = {command:data}
        result['result'] = None if test else success
        result['comment'] = f'only get data {command}'
        return result




    сf_rules,   success_rules_get   = _existing_by_page(uri_rules,   auth_email, auth_key, api_token)
    сf_filters, success_filters_get = _existing_by_page(uri_filters, auth_email, auth_key, api_token)
    success = all([success_rules_get, success_filters_get])

    if zone_delete:
        rules_yaml = []

    rules_yaml_dict = {}
    for rule_yaml in rules_yaml:
        description = rule_yaml['description']
        if description in rules_yaml_dict:
            return {"name": name, "changes": {}, "comment": f"error in yaml fale description '{description}' is not unique", "result": False}
        else:
            rules_yaml_dict.update({(description): rule_yaml})



    сf_rules_dict = {}
    for сf_rule in сf_rules:
        description   = сf_rule['description']
        сf_rules_dict.update({(description): сf_rule})

    update_dict        = {}
    rules_update_json  = []
    filter_update_json = []
    rules_add_json     = []
    count_update_list  = 0
    count_add_list     = 0
    for rule_yaml_key, rule_yaml_value in rules_yaml_dict.items():
        if rule_yaml_key in сf_rules_dict:
            action     = 'update'
            method_PUT = 'PUT'
            rule_yaml_value['id'] = сf_rules_dict[rule_yaml_key]['id']
            rule_yaml_value['filter']['id'] = сf_rules_dict[rule_yaml_key]['filter']['id']

            rules_update_list = []
            for key, value in rule_yaml_value.items():
                if сf_rules_dict[rule_yaml_key].get(key) != value and key != 'filter':
                    rules_update_list.append(f"{action} {key}: {сf_rules_dict[rule_yaml_key].get(key)} ---> {value}")

            filter_update_list = []
            for key, value in rule_yaml_value['filter'].items():
                if сf_rules_dict[rule_yaml_key]['filter'].get(key) != value:
                    filter_update_list.append(f"{action} {key}: {сf_rules_dict[rule_yaml_key]['filter'].get(key)} ---> {value}")

            if rules_update_list or filter_update_list:
                if not update_dict.get(rule_yaml_key):
                    update_dict.update({rule_yaml_key:{}})

                if rules_update_list:
                    update_dict[rule_yaml_key].update({'rule': rules_update_list})
                    rules_update_json.append(rule_yaml_value)
                    count_update_list += len(rules_update_list)

                if filter_update_list:
                    update_dict[rule_yaml_key].update({'filter': filter_update_list})
                    filter_update_json.append(rule_yaml_value['filter'])
                    count_update_list += len(filter_update_list)
        else:
            action      = 'add'
            method_POST = 'POST'

            rules_add_list = []
            for key, value in rule_yaml_value.items():
                if key != 'filter':
                    rules_add_list.append(f"{action} {key}: {value}")

            filter_add_list = []
            for key, value in rule_yaml_value['filter'].items():
                filter_add_list.append(f"{action} {key}: {value}")


            if filter_add_list or rules_add_list:
                rules_add_json.append(rule_yaml_value)
                if not update_dict.get(rule_yaml_key):
                    update_dict.update({rule_yaml_key:{}})

                if rules_add_list:
                    update_dict[rule_yaml_key].update({'rule': rules_add_list})
                    count_add_list += len(rules_add_list)

                if filter_add_list:
                    update_dict[rule_yaml_key].update({'filter': filter_add_list})
                    count_add_list += len(filter_add_list)


    rules_delete_url   = []
    filter_delete_url  = []
    count_delete_list  = 0
    for rule_сf_key, rule_сf_value in сf_rules_dict.items():
        if not rule_сf_key in rules_yaml_dict:
            action         = 'delete'
            method_DELETE  = 'DELETE'

            rules_delete_list = []
            for key, value in rule_сf_value.items():
                if key != 'filter':
                    rules_delete_list.append(f"{action} {key}: {value}")

            filter_delete_list = []
            for key, value in rule_сf_value['filter'].items():
                filter_delete_list.append(f"{action} {key}: {value}")

            if rules_delete_list or filter_delete_list:
                if not update_dict.get(rule_сf_key):
                    update_dict.update({rule_сf_key:{}})

                if rules_delete_list:
                    rules_delete_url.append(f"id={rule_сf_value['id']}")
                    update_dict[rule_сf_key].update({'rule': rules_delete_list})
                    count_delete_list += len(rules_delete_list)

                if filter_delete_list:
                    filter_delete_url.append(f"id={rule_сf_value['filter']['id']}")
                    update_dict[rule_сf_key].update({'filter': filter_delete_list})
                    count_delete_list += len(filter_delete_list)


    check_filters_id = []
    for сf_rule in сf_rules:
        check_filters_id.append(сf_rule['filter']['id'])

    for сf_filter in сf_filters:
        if not сf_filter['id'] in check_filters_id:
            action         = 'delete'
            method_DELETE  = 'DELETE'
            filter_delete_list = []
            for key, value in сf_filter.items():
                filter_delete_list.append(f"{action} {key}: {value}")

            if filter_delete_list:
                if not update_dict.get(сf_filter['id']):
                    update_dict.update({сf_filter['id']:{}})
                filter_delete_url.append(f"id={сf_filter['id']}")
                update_dict[сf_filter['id']].update({'filter': filter_delete_list})
                count_delete_list += len(filter_delete_list)


    if count_update_list > 0:
        comment_count_update = f'update:({count_update_list})'
    else:
        comment_count_update = ''

    if count_add_list > 0:
        comment_count_add= f'add:({count_add_list})'
    else:
        comment_count_add = ''

    if count_delete_list > 0:
        comment_count_delete= f'delete:({count_delete_list})'
    else:
        comment_count_delete = ''


    if not test and rules_delete_url:
        rules_delete_url = uri_rules + "?" + "&".join(rules_delete_url)
        resp = _request(rules_delete_url, method=method_DELETE, json=None, auth_email=auth_email, auth_key=auth_key, api_token=api_token)
        data = resp.get('result')
        success = all([success, resp['success']])

    if not test and filter_delete_url:
        filter_delete_url = uri_filters + "?" + "&".join(filter_delete_url)
        resp = _request(filter_delete_url, method=method_DELETE, json=None, auth_email=auth_email, auth_key=auth_key, api_token=api_token)
        data = resp.get('result')
        success = all([success, resp['success']])

    if not test and rules_update_json:
        resp = _request(uri_rules, method=method_PUT, json=rules_update_json, auth_email=auth_email, auth_key=auth_key, api_token=api_token)
        data = resp.get('result')
        success = all([success, resp['success']])

    if not test and filter_update_json:
        resp = _request(uri_filters, method=method_PUT, json=filter_update_json, auth_email=auth_email, auth_key=auth_key, api_token=api_token)
        data = resp.get('result')
        success = all([success, resp['success']])

    if not test and rules_add_json:
        resp = _request(uri_rules, method=method_POST, json=rules_add_json, auth_email=auth_email, auth_key=auth_key, api_token=api_token)
        data = resp.get('result')
        success = all([success, resp['success']])




    if update_dict:
        result["changes"] = {command:update_dict}
        result['comment'] = f'update {command} zone {zone} (id:{zone_id}), apply changes {comment_count_update} {comment_count_add} {comment_count_delete}'
    else:
        result['comment'] = f'ok {command} zone {zone} (id:{zone_id}), no changes required'


    result['result'] = None if test else success
    return result












def zone_settings(
        name,
        zone,
        api_token=None,
        auth_email=None,
        auth_key=None,
        items=None,
        only_get_data=None
    ):

    value_update = {
        'items': items
    }

    command     = 'settings'
    test        = _get_test()
    result      = {"name": name, "changes": {}, "comment": '', "result": None}
    zone_data   = __opts__.get("zones.configs", {}).get(zone, {})
    zone_id     = zone_data.get('id')
    zone_name   = zone_data.get('name')
    zone_delete = zone_data.get('delete')
    zone_action = zone_data.get('zone_action')

    if zone_id and zone_name:
        pass
    else:
        return _return_status_zone(name, zone, test, zone_action, zone_delete)

    if only_get_data == True:
        return _return_only_get_data(zone_id, command, auth_email, auth_key, api_token, result, test)



    method = "GET"
    configs_main = _get_configs_main()
    uri  = f"{configs_main['uri']}/zones/{zone_id}/{command}"
    resp = _request(uri, method=method, json=None, auth_email=auth_email, auth_key=auth_key, api_token=None)
    data = resp.get('result', [])

    update_dict = {}
    count_update_list = 0
    action = 'update'
    method = 'PATCH'
    for value_data in data:
        for item in items:
            if value_data['id'] == item['id']:
                update_list = []
                for key, value in item.items():
                    if value_data[key] != value:
                        update_list.append(f"{action} {key}: {value_data[key]} ---> {value}")
                if update_list:
                    update_dict.update({item['id']:update_list})
                count_update_list += len(update_list)
    if update_dict:
        result["changes"] = {command:update_dict}
        result['comment'] = f'{action} {command} zone {zone} (id:{zone_id}), apply changes ({str(count_update_list)})'
    else:
        action = 'ok'
        result['comment'] = f'{action} {command} zone {zone} (id:{zone_id}), no changes required'

    if not test and count_update_list:
        resp = _request(uri, method=method, json=value_update, auth_email=auth_email, auth_key=auth_key, api_token=None)
        data = resp.get('result')
    result['result'] = None if test else resp['success']

    return result







def dns_records(
        name,
        zone,
        records=None,
        exclude=[],
        api_token=None,
        auth_email=None,
        auth_key=None,
        only_get_data=None
    ):

    value_create = {
        'api_token': api_token,
        'auth_email': auth_email,
        'auth_key': auth_key,
        'records': records,
        'exclude': exclude
    }

    command     = 'dns_records'
    test        = _get_test()
    result      = {"name": name, "changes": {}, "comment": '', "result": None}
    zone_data   = __opts__.get("zones.configs", {}).get(zone, {})
    zone_id     = zone_data.get('id')
    zone_name   = zone_data.get('name')
    zone_delete = zone_data.get('delete')
    zone_action = zone_data.get('zone_action')

    if zone_id and zone_name:
        value_create.update({'zone_id': zone_id})
    else:
        return _return_status_zone(name, zone, test, zone_action, zone_delete)

    if only_get_data == True:
        return _return_only_get_data(zone_id, command, auth_email, auth_key, api_token, result, test)

    if zone_delete:
        value_create['records'] = []


    def manage_zone_records(name, zone):
        managed = Zone(name, zone)

        try:
            managed.sanity_check()
        except salt.exceptions.SaltInvocationError as err:
            return {
                "name": name,
                "changes": {},
                "result": False,
                "comment": "{0}".format(err)
            }

        diff = managed.diff()

        result = {"name": name, "changes": _changes(diff), "result": None}

        if len(diff) == 0:
            result["comment"] = "The state of {0} ({1}) is up to date.".format(
                name, zone["zone_id"]
            )
            result["changes"] = {}
            result["result"] = None if __opts__["test"] == True else True
            return result

        if __opts__["test"] == True:
            result[
                "comment"
            ] = "The state of {0} ({1}) will be changed ({2} changes).".format(
                name, zone["zone_id"], len(diff)
            )
            result["pchanges"] = result["changes"]
            return result

        managed.apply(diff)

        result["comment"] = "The state of {0} ({1}) was changed ({2} changes).".format(
            name, zone["zone_id"], len(diff)
        )
        result["result"] = True

        return result


    def _changes(diff):
        changes = {}
        actions = map(lambda op: "{0} {1}".format(op["action"], str(op["record"])), diff)
        if actions:
            changes['diff'] = "\n".join(actions)
        return changes

    def validate_record(record):
        if "name" not in record:
            raise salt.exceptions.SaltInvocationError("'name' is required")
        if "content" not in record:
            raise salt.exceptions.SaltInvocationError("Required field 'content' is missing for entry <{0}>".format(record["name"]))
        if "type" in record and record["type"] == "MX" and "priority" not in record:
            raise salt.exceptions.SaltInvocationError("Required field 'priority' is missing for MX entry <{0}>".format(record["name"]))

    def record_from_dict(record):
        record.setdefault("type", "A")
        record.setdefault("proxied", False)
        record.setdefault("id", None)
        record.setdefault("ttl", 1)
        record.setdefault("salt_managed", True)
        priority = record["priority"] if record["type"] == "MX" else None
        return Record(
            record["id"],
            record["type"],
            record["name"],
            record["content"],
            priority,
            record["proxied"],
            record["ttl"],
            record["salt_managed"],
        )


    class Record(
        namedtuple(
            "Record", ("id", "type", "name", "content", "priority", "proxied", "ttl", "salt_managed")
        )
    ):
        def pure(self):
            return Record(
                None,
                self.type,
                self.name,
                self.content,
                self.priority,
                self.proxied,
                self.ttl,
                self.salt_managed,
            )

        """
        Cloudflare API expects `data` attribute when you add SRV records
        instead of `content`. This method synthesizes `data` from `content`.
        """

        def data(self):
            if self.type == "SRV":
                service, proto, name = self.name.split(".", 2)
                parts = self.content.split("\t")
                if len(parts) == 3:
                    # record should look like this: "priority weight port target"
                    # cloudflare returns: "weight port target"
                    priority = 10
                    weight, port, target = parts
                else:
                    priority, weight, port, target = parts
                return {
                    "service": service,
                    "proto": proto,
                    "name": name,
                    "priority": int(priority),
                    "weight": int(weight),
                    "port": int(port),
                    "target": target,
                }
            if self.type == "CAA":
                parts = self.content.split(" ")
                flags, tag, value = parts
                return {
                    "name": self.name,
                    "flags": int(flags),
                    "tag": tag,
                    "value": value[1:-1],
                }

        def __str__(self):
            ttl_str = 'auto' if self.ttl == 1 else '{0}s'.format(self.ttl)
            priority_string = 'priority: {0}, '.format(self.priority) if self.type == "MX" else ''
            return "{0} {1} -> '{2}' (proxied: {3}, ttl: {4})".format(
                self.type, self.name, self.content, priority_string, str(self.proxied).lower(), ttl_str
            )

        def json(self):
            dict = {
                "type": self.type,
                "name": self.name,
                "content": self.content,
                "proxied": self.proxied,
                "data": self.data(),
                "ttl": self.ttl,
            }
            if self.type == "MX":
                dict["priority"] = self.priority
            return dict


    class Zone(object):

        ZONES_URI_TEMPLATE = "https://api.cloudflare.com/client/v4/zones/{zone_id}"
        RECORDS_URI_TEMPLATE = "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?page={page}&per_page=50"

        ADD_RECORD_URI_TEMPLATE = (
            "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
        )
        REMOVE_RECORD_URI_TEMPLATE = (
            "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}"
        )
        UPDATE_RECORD_URI_TEMPLATE = (
            "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}"
        )

        ACTION_ADD = "add"
        ACTION_REMOVE = "remove"
        ACTION_UPDATE = "update"

        SPECIAL_APPLY_ORDER = {ACTION_REMOVE: 0, ACTION_ADD: 1, ACTION_UPDATE: 2}

        REGULAR_APPLY_ORDER = {ACTION_ADD: 0, ACTION_UPDATE: 1, ACTION_REMOVE: 2}

        def __init__(self, name, zone):
            self.name = name
            self.api_token = zone.get("api_token", None)
            self.auth_email = zone.get("auth_email", None)
            self.auth_key = zone.get("auth_key", None)
            self.zone_id = zone["zone_id"]
            self.records = zone["records"]
            self.exclude = zone.get('exclude', [])

            if not self.api_token and not (self.auth_email and self.auth_key):
                raise Exception("Either api_token or auth_email and auth_key must be provided")

        def _request(self, uri, method="GET", json=None):
            return _request(uri, method, json, auth_email=self.auth_email, auth_key=self.auth_key, api_token=self.api_token)


        def _add_record(self, record):
            self._request(
                self.ADD_RECORD_URI_TEMPLATE.format(zone_id=self.zone_id),
                method="POST",
                json=record.json(),
            )

        def _remove_record(self, record):
            self._request(
                self.REMOVE_RECORD_URI_TEMPLATE.format(
                    zone_id=self.zone_id, record_id=record.id
                ),
                method="DELETE",
            )

        def _update_record(self, record):
            self._request(
                self.UPDATE_RECORD_URI_TEMPLATE.format(
                    zone_id=self.zone_id, record_id=record.id
                ),
                method="PUT",
                json=record.json(),
            )

        def sanity_check(self):
            found = self._request(self.ZONES_URI_TEMPLATE.format(zone_id=self.zone_id))

            if self.name != found["result"]["name"]:
                raise Exception(
                    "Zone name does not match: {0} != {1}".format(
                        self.name, found["result"]["name"]
                    )
                )

            As = set()
            CNAMEs = set()

            for record in self.desired():
                if (
                    not record.name.endswith("." + self.name)
                    and not record.name == self.name
                ):
                    raise Exception(
                        "Record {0} does not belong to zone {1}".format(
                            record.name, self.name
                        )
                    )

                if record.ttl != 1 and record.ttl < 120:
                    raise Exception(
                        "Record {0} has invalid TTL: {1}".format(record.name, record.ttl)
                    )

                if record.ttl != 1 and record.proxied:
                    raise Exception(
                        "Record {0} has TTL set, but TTL for proxied records is managed by Cloudflare".format(
                            record.name
                        )
                    )

                try:
                    record.data()
                except Exception as e:
                    raise Exception(
                        "Record {0} cannot synthesize data from content: {1}".format(
                            str(record), e
                        )
                    )

                if record.type in ("A", "AAAA"):
                    As.add(record.name)
                    if record.name in CNAMEs:
                        raise Exception(
                            "Record {0} has both A/AAAA and CNAME records".format(
                                record.name
                            )
                        )

                if record.type in ("CNAME",):
                    if record.name in CNAMEs:
                        raise Exception(
                            "Record {0} has serveral CNAME records".format(record.name)
                        )
                    CNAMEs.add(record.name)
                    if record.name in As:
                        raise Exception(
                            "Record {0} has both A/AAAA and CNAME records".format(
                                record.name
                            )
                        )

        def existing(self):
            records = {}

            page = 1
            while True:
                found = self._request(
                    self.RECORDS_URI_TEMPLATE.format(zone_id=self.zone_id, page=page)
                )

                for record_dict in found["result"]:
                    record = record_from_dict(record_dict)
                    excluded = False
                    for pattern in self.exclude:
                        if re.match(pattern, record.name):
                            excluded = True
                            break
                    if not excluded:
                        records[record_dict["id"]] = record

                current_page = found["result_info"]["page"]
                total_pages = found["result_info"]["total_pages"]
                if current_page == total_pages or total_pages == 0:
                    break

                page += 1

            return records.values()

        def desired(self):
            for record in self.records:
                validate_record(record)
            return map(lambda record: record_from_dict(record.copy()), self.records)

        def diff(self):
            existing_tuples = {
                (record.type, record.name, record.content, record.salt_managed): record
                for record in self.existing()
            }
            desired_tuples = {
                (record.type, record.name, record.content, record.salt_managed): record
                for record in self.desired()
            }
            desired_salt_managed = {
                record.name: record.salt_managed for record in self.desired()
            }

            changes = []

            for key in set(desired_tuples).difference(existing_tuples):
                if not desired_tuples[key].salt_managed:
                    continue
                changes.append({"action": self.ACTION_ADD, "record": desired_tuples[key]})

            for key in set(existing_tuples).difference(desired_tuples):
                if key[1] in desired_salt_managed and desired_salt_managed[key[1]] == False:
                    continue
                changes.append(
                    {"action": self.ACTION_REMOVE, "record": existing_tuples[key]}
                )

            for key in set(existing_tuples).intersection(desired_tuples):
                if (
                    existing_tuples[key].pure() == desired_tuples[key]
                    or not desired_tuples[key].salt_managed
                ):
                    continue
                changes.append(
                    {
                        "action": self.ACTION_UPDATE,
                        "record": Record(
                            existing_tuples[key].id,
                            desired_tuples[key].type,
                            desired_tuples[key].name,
                            desired_tuples[key].content,
                            priority=desired_tuples[key].priority,
                            proxied=desired_tuples[key].proxied,
                            ttl=desired_tuples[key].ttl,
                            salt_managed=True,
                        ),
                    }
                )

            return self._order(changes)

        def _order(self, diff):
            groups = {"primary": {}, "rest": {}}

            for op in diff:
                group = "rest"
                if op["record"].type in ("A", "AAAA", "CNAME"):
                    group = "primary"
                if op["record"].name not in groups[group]:
                    groups[group][op["record"].name] = []
                groups[group][op["record"].name].append(op)

            result = []

            def append_in_order(ops, order):
                for op in sorted(ops, key=lambda op: order[op["action"]]):
                    result.append(op)

            for name, ops in groups["primary"].items():
                if any(op["record"].type == "CNAME" for op in ops):
                    # need to remove before adding
                    append_in_order(ops, self.SPECIAL_APPLY_ORDER)
                else:
                    # nothing special about these records
                    append_in_order(ops, self.REGULAR_APPLY_ORDER)

            for name, ops in groups["rest"].items():
                append_in_order(ops, self.REGULAR_APPLY_ORDER)

            return result

        def apply(self, diff):
            for op in diff:
                if op["action"] == self.ACTION_ADD:
                    self._add_record(op["record"])
                elif op["action"] == self.ACTION_REMOVE:
                    self._remove_record(op["record"])
                elif op["action"] == self.ACTION_UPDATE:
                    self._update_record(op["record"])
                else:
                    raise Exception(
                        "Unknown action {0} for record {1}", op["action"], str(op["record"])
                    )

    return manage_zone_records(zone_name, value_create)



def zones_multiprocessing(**kwargs):
    if not __opts__.get("zones.configs.multiprocessing"):
        __opts__.update({"zones.configs.multiprocessing":{}})
    __opts__["zones.configs.multiprocessing"].update({kwargs['name']: kwargs})

    if _get_test():
        result_status = None
    else:
        result_status = True

    result = {"name": kwargs['name'], "changes": {}, "comment": kwargs['name'], "result": result_status}
    return result



def run_all_functions(zone_args):
    result_dict = {zone_args['name']:{}}
    zone_name = zone_args['name']

    try:
        result = zones(
            name          = zone_args['name'],
            account       = zone_args['account'],
            api_token     = zone_args.get('api_token', None),
            auth_email    = zone_args.get('auth_email', None),
            auth_key      = zone_args.get('auth_key', None),
            only_get_data = zone_args.get('only_get_data', None),
            delete        = zone_args.get('delete', None),
            paused        = zone_args.get('paused', None),
            jump_start    = zone_args.get('jump_start', None),
            zone_type     = zone_args.get('zone_type', None)
        )
    except Exception as err:
        result = {"name": zone_name, "changes": {}, "comment": err, "result": False}
    result_dict[zone_args['name']].update({'zones':result})


    if zone_args.get('ssl_universal_settings'):
        try:
            result = ssl_universal_settings(
                name          = f'ssl_universal_settings_for_{zone_name}',
                zone          = zone_name,
                api_token     = zone_args.get('api_token', None),
                auth_email    = zone_args.get('auth_email', None),
                auth_key      = zone_args.get('auth_key', None),
                only_get_data = zone_args.get('only_get_data', None),
                enabled       = zone_args['ssl_universal_settings'].get('enabled', True),
                certificate_authority = zone_args['ssl_universal_settings'].get('certificate_authority', None)
            )
        except Exception as err:
            result = {"name": f'ssl_universal_settings_for_{zone_name}', "changes": {}, "comment": err, "result": False}
        result_dict[zone_args['name']].update({'ssl_universal_settings':result})


    if zone_args.get('firewall_rules'):
        try:
            result = firewall_rules(
                name          = f'firewall_rules_for_{zone_name}',
                zone          = zone_name,
                api_token     = zone_args.get('api_token', None),
                auth_email    = zone_args.get('auth_email', None),
                auth_key      = zone_args.get('auth_key', None),
                rules         = zone_args.get('firewall_rules', None),
                only_get_data = zone_args.get('only_get_data', None)
            )
        except Exception as err:
            result = {"name": f'firewall_rules_for_{zone_name}', "changes": {}, "comment": err, "result": False}
        result_dict[zone_args['name']].update({'firewall_rules':result})


    if zone_args.get('zone_settings'):
        try:
            result = zone_settings(
                name          = f'zone_settings_for_{zone_name}',
                zone          = zone_name,
                api_token     = zone_args.get('api_token', None),
                auth_email    = zone_args.get('auth_email', None),
                auth_key      = zone_args.get('auth_key', None),
                items         = zone_args.get('zone_settings', None),
                only_get_data = zone_args.get('only_get_data', None)
            )
        except Exception as err:
            result = {"name": f'zone_settings_for_{zone_name}', "changes": {}, "comment": err, "result": False}
        result_dict[zone_args['name']].update({'zone_settings':result})


    if zone_args.get('dns_records'):
        try:
            result = dns_records(
                name          = f'dns_records_for_{zone_name}',
                zone          = zone_name,
                records       = zone_args.get('dns_records', None),
                exclude       = [],
                api_token     = zone_args.get('api_token', None),
                auth_email    = zone_args.get('auth_email', None),
                auth_key      = zone_args.get('auth_key', None),
                only_get_data = zone_args.get('only_get_data', None)
            )
        except Exception as err:
            result = {"name": f'dns_records_for_{zone_name}', "changes": {}, "comment": err, "result": False}
        result_dict[zone_args['name']].update({'dns_records':result})


    return result_dict


def run_multiprocessing(name, processes=cpu_count()):

    succeeded = 0
    failed = 0
    changed = 0
    unchanged = 0

    result_list = []
    zones_list = list(__opts__["zones.configs.multiprocessing"].keys())
    for i in range(0, len(zones_list), processes):
        zone_args = []
        for zone_name in zones_list[i:i + processes]:
            zone_args.append(__opts__["zones.configs.multiprocessing"][zone_name])

        with Pool() as pool:
            for result in pool.map(run_all_functions, zone_args):
                result_list.append(result)
                for res_k, res_v in list(result.values())[0].items():
                    if res_v['changes']:
                        changed += 1
                    else:
                        unchanged += 1
                    if res_v['result'] == True or res_v['result'] == None:
                        succeeded += 1
                    else:
                        failed += 1

        if _get_test() and failed == 0:
            result_status = None
        else:
            if failed > 0:
                result_status = False
            else:
                result_status = True
   
    summary = f'Failed: {failed}, Succeeded: {succeeded} (unchanged={unchanged}, changed={changed})'
    result = {"name": name, "changes": {"Result": result_list, "Summary": summary }, "comment": '', "result": result_status}
    return result
