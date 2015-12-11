import xml.etree.cElementTree as ET
import pprint
import re
import codecs
import json
from collections import defaultdict

lower = re.compile(r'^([a-z]|_)*$')
lower_colon = re.compile(r'^([a-z]|_)*:([a-z]|_)*$')
problemchars = re.compile(r'[=\+/&<>;\'"\?%#$@\,\. \t\r\n]')
re_addr = re.compile(r'addr:')
re_addr2 = re.compile(r'addr:[^:]+:')
street_type_re = re.compile(r'\b\S+\.?$', re.IGNORECASE)
zipcode_re = re.compile(r'^\d{5}$')
zipcode_with_extension_re = re.compile(r'^\d{5}-\d{4}$')
zipcode_with_state_re = re.compile(r'^\w\w\s\d{5}$')
canada_zipcode_re = re.compile(r'^\w\d\w \d\w\d$')
canada_zipcode_without_space_re = re.compile(r'^(\w\d){3}$')
canada_zipcode_with_province_re = re.compile(r'^\w\w \w\d\w \d\w\d$')

#Empty list which we will populate in the main function
expected_street_types = [] #["Street", "Avenue", "Boulevard", "Drive", "Court", "Place", "Square", "Lane", "Road", "Trail", "Parkway", "Commons"]

street_type_mapping = { "Ave":"Avenue", "Ave.":"Avenue","ave":"Avenue",
                        "Blvd":"Boulevard","Blvd.":"Boulevard",
                        "Ct":"Court",
                        "DR":"Drive","Dr":"Drive","Dr.":"Drive","dr":"Drive",
                        "E":"East",
                        "Hwy":"Highway",
                        "mile":"Mile",
                        "N":"North",
                        "Pkwy":"Parkway",
                        "Pl":"Place","Pl.":"Place",
                        "Rd":"Road","Rd.":"Road","road":"Road",
                        "St": "Street","St.": "Street",
                        "W":"West","W.":"West",
                        "way":"Way"}

CREATED = [ "version", "changeset", "timestamp", "user", "uid"]
created_attribs_set = {"version","changeset","timestamp","user","uid"}
pos_indicies_dict = {"lat":0,"lon":1}

def count_tags(filename):
    tag_dict = {}
    for event, elem in ET.iterparse(filename):
        if elem.tag in tag_dict:
            tag_dict[elem.tag] += 1
        else:
            tag_dict[elem.tag] = 1
    return tag_dict

#create a dictionary which represents a histogram of the output of a function called on the Elements of an ElementTree
def gen_distribution(func, shaped=False):
    dist_dict = {}
    for event, elem in ET.iterparse("detroit_michigan.osm"):
        func_result = None
        if shaped:
            func_result = func(shape_element(elem))
        else:
            func_result = func(elem)
        if not func_result:
            continue
        elif func_result in dist_dict:
            dist_dict[func_result] += 1
        else:
            dist_dict[func_result] = 1
    return dist_dict

def get_tag(elem):
    return elem.tag

def get_addr_key(elem):
    if elem.tag == "tag" and elem.attrib["k"][0:5] == "addr:":
        return elem.attrib["k"]
    else:
        return False

def get_zipcode(elem):
    if elem.tag == "tag" and elem.attrib["k"] == "addr:postcode":
        return elem.attrib["v"]
    else:
        return False

def get_street_type(elem):
    if elem.tag == "tag" and elem.attrib["k"] == "addr:street":
        m = street_type_re.search(elem.attrib["v"])
        if m:
            return m.group()
    return False

def get_unexpected_shaped_street_type(doc_dict):
    if doc_dict:
        address = doc_dict.get("address")
        if address:
            street = address.get("street")
            if street:
                m = street_type_re.search(street)
                if m and m.group() not in expected_street_types:
                    return m.group()
    return False

def get_shaped_zipcode(doc_dict):
    if doc_dict:
        address = doc_dict.get("address")
        if address:
            postcode = address.get("postcode")
            if postcode:
                return postcode
    return False

def get_unexpected_street_type(elem):
    if elem.tag == "tag" and elem.attrib["k"] == "addr:street":
        m = street_type_re.search(elem.attrib["v"])
        if m and m.group() not in expected_street_types:
            return m.group()
    return False
            

def audit_street_type(street_types, street_name):
    m = street_type_re.search(street_name)
    if m:
        street_type = m.group()
        if street_type not in expected_street_types:
            street_types[street_type].add(street_name)

def is_street_name(elem):
    return (elem.attrib['k'] == "addr:street")

def audit(osmfile):
    osm_file = open(osmfile, "r")
    street_types = defaultdict(set)
    for event, elem in ET.iterparse(osm_file, events=("start",)):

        if elem.tag == "node" or elem.tag == "way":
            for tag in elem.iter("tag"):
                if is_street_name(tag):
                    audit_street_type(street_types, tag.attrib['v'])

    return street_types

def better_name(name):
    street_type_index = name.rfind(' ')
    street_name = name[0:street_type_index]
    street_type = name[street_type_index+1:]
    if street_type in street_type_mapping:
        return street_name + ' ' + street_type_mapping[street_type]
    else:
        return name

def better_postcode(postcode):
    if zipcode_re.match(postcode) or canada_zipcode_re.match(postcode):
        #postcode is formatted properly
        return postcode
    elif zipcode_with_extension_re.match(postcode):
        #remove extension from zipcode
        return postcode[0:5]
    elif zipcode_with_state_re.match(postcode):
        #remove state from zipcode
        return postcode[3:]
    else:
        #perhaps this is a canadian zipcode, lets capitalize it just incase
        postcode = postcode.upper()

    if canada_zipcode_without_space_re.match(postcode):
        #we need to insert the space
        return postcode[0:3] + ' ' + postcode[3:]
    elif canada_zipcode_with_province_re.match(postcode):
        #we need to remove the province
        return postcode[3:]
    else:
        #no idea what this is, lets print it, then just return it
        print 'Weird zipcode: ' + postcode
        return postcode

def shape_element(element):
    node = {}
    if element.tag == "node" or element.tag == "way" :
        node['type'] = element.tag
        #create "created" dict
        node['created'] = {}
        #create "node" list and index_dict
        node['pos'] = [0,0]
        for key in element.attrib:
            if key in created_attribs_set:
                node['created'][key] = element.attrib[key]
            elif key in pos_indicies_dict:
                node['pos'][pos_indicies_dict[key]] = float(element.attrib[key])
            else:
                node[key] = element.attrib[key]
        
        for child in element:
            if child.tag == 'tag':
                k_value = child.attrib['k']
                if problemchars.search(k_value):
                    continue
                elif re_addr2.match(k_value):
                    continue
                elif re_addr.match(k_value):
                    if not 'address' in node:
                        node['address'] = {}
                    trimmed_k_value = k_value.split(':')[1]
                    if trimmed_k_value == "street":
                        node['address'][trimmed_k_value] = better_name(child.attrib['v'])
                    elif trimmed_k_value == "postcode":
                        node['address'][trimmed_k_value] = better_postcode(child.attrib['v'])
                    else:
                        node['address'][trimmed_k_value] = child.attrib['v']
                elif k_value == 'address':
                    print 'Skipping problematic key: ' + k_value + ' and value: ' + child.attrib['v']
                    continue
                else:
                    node[k_value] = child.attrib['v']
             
            if element.tag == "way" and child.tag == "nd":
                if not "node_refs" in node:
                    node["node_refs"] = [child.attrib["ref"]]
                else:
                    node["node_refs"].append(child.attrib["ref"])
        
        return node
    else:
        return None


def process_map(file_in, pretty = False):
    # You do not need to change this file
    file_out = "{0}.json".format(file_in)
    data = []
    with codecs.open(file_out, "w") as fo:
        for _, element in ET.iterparse(file_in):
            el = shape_element(element)
            if el:
                data.append(el)
                if pretty:
                    fo.write(json.dumps(el, indent=2)+"\n")
                else:
                    fo.write(json.dumps(el) + "\n")
    return data



if __name__ == "__main__":
    #populate expected street types
    street_types_file = open("StreetTypesCapitalized.txt")
    for line in street_types_file:
        expected_street_types.append(line.strip())
    #print "Expected Street Types:"
    #pprint.pprint(expected_street_types)
    #pprint.pprint(count_tags("detroit_michigan.osm"))
    #pprint.pprint(gen_distribution(get_tag))
    #pprint.pprint(gen_distribution(get_addr_key))
    #pprint.pprint(gen_distribution(get_unexpected_shaped_street_type,True))
    #pprint.pprint(gen_distribution(get_shaped_zipcode,True))
    #pprint.pprint(gen_distribution(get_zipcode))
    #process_map("detroit_michigan.osm")
    #pprint.pprint(audit("detroit_michigan.osm"))
    from pymongo import MongoClient
    client = MongoClient("mongodb://localhost:27017")
    db = client.detroit
    db.detroit.insert(process_map("detroit_michigan.osm"))
