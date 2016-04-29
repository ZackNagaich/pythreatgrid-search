#!/usr/bin/env python3

import json
from argparse import ArgumentParser
from pythreatgrid.threatgrid import get_analysis, search_samples, requests

#Global to determine depth of recursion
_RECURSION_DEPTH = 3
#Global to limit results of API calls
_LIMIT = 10

def search_samples(options):
	'''Override search_samples in pythreatgrid (direct GET request seems a bit faster, as opposed to generator yields)

	Args:
		options (dict): Options for the API request.

	Returns:
		 json_resp (dict): JSON object for API return 
	'''

	_HOST = 'https://panacea.threatgrid.com'
	'''str: Represents the host that the API will connect to.
	'''
	_APIROOT = '/api/v2'
	'''str: The root URI for the API.
	'''
	_URL = _HOST + _APIROOT
	'''str: Controls where requests will be sent.
	'''
	r = requests.get('%s/samples/search' % (_URL),
		data=options)
	json_resp = json.loads(r.text)

	return json_resp


def dedup(lst):
	'''De-duplicates provided list

	Args:
		lst (list): List that contains duplicates

	Returns:
		 (list): De-duplicated list 
	'''
	seen = set()
	seen_add = seen.add
	return [x for x in lst if not (x in seen or seen_add(x))]


def get_related_ip(options,sample_list):
	'''Retrieves related IPs for each provided sample, using analysis from threatgrid

	Args:
		options (dict): Options for the API request.
		sample_list (list (str)): List of Sample IDs represented as strings

	Returns:
		ips (list (str)): List of IPs represented as strings
	'''
	ips = list()
	for sample in sample_list:
		print("\n[+] Getting related IPs for Sample ID %s" % (sample))
		response = ''
		for r in get_analysis(options,sample):
			response += r.decode('utf-8')
		analysis = json.loads(response)
		for item in analysis[u'network']:
				ips.append(analysis[u'network'][item][u'dst'])
	print("\n[+] De-duplicating discovered IP addresses...")			
	ips = dedup(ips)
	return ips

def get_related_hashes(options,sample_list):
	'''Retrieves related hashes (md5,sha1,sha256) for each provided sample, using analysis from threatgrid

	Args:
		options (dict): Options for the API request.
		sample_list (list (str)): List of Sample IDs represented as strings

	Returns:
		ips (list (str)): List of hashes represented as strings.
	'''
	hashes = list()
	for sample in sample_list:
		print("\n[+] Getting related hashes for Sample ID %s " % (sample))
		response = ''
		for r in get_analysis(options,sample):
			response += r.decode('utf-8')
		analysis = json.loads(response)
		for item in analysis[u'artifacts']:
			hashes.append(analysis[u'artifacts'][item][u'md5'])
			hashes.append(analysis[u'artifacts'][item][u'sha256'])
			hashes.append(analysis[u'artifacts'][item][u'sha1'])
	print("\n[+] De-duplicating related hashes...")
	hashes = dedup(hashes)
	return hashes

def query_samples(options):
	'''Retrieves sample IDs using sample search API request

	Args:
		options (dict): Options for the API request.

	Returns:
		sample_list (list (str)): List of sample IDs
	'''
	sample_list = list()
	resp = search_samples(options)
	if 'data' in resp:
		for item in resp[u'data'][u'items']:
			sample_list.append(item['sample'])

	#print("\n[+] De-duplicating returned samples...")
	sample_list = dedup(sample_list)
	return sample_list

def recursive_search(sample_list,options,depth=0):
	'''Searches for sample IDs, using any identified IOC's (IP, Hash) from a sample to recursively search for other related samples.

	Args:
		sample_list (list (str)): List of sample ID's which act as seed for recursive search
		options (dict): Options for the API request.
		depth (int): Desired depth of recursion

	Returns:
		sample_list (list (str)): List of all related sample IDs
	'''

	if depth != _RECURSION_DEPTH:
		depth += 1
		print("\n[+] Total number of Samples: %s" % str(len(sample_list)))
		#get related ips for each sample in sample_list, limit results to 10 ip's for performance
		ips = get_related_ip(options,sample_list)[:_LIMIT]
		#get related hashes for each sample in sample_list, limit results to 10 hashes for performance
		hashes = get_related_hashes(options,sample_list)[:_LIMIT]

		new_sample_list = list()
		print("\n[+] Searching for samples based off related IOC's...")
		print("\n[+] Searching for samples with %s IP addresses" % str(len(ips)))
		for ip in ips:
			if 'checksum' in options:
				del options[u'checksum']
			options[u'ip']=ip
			print("\n" + str(options))
			new_sample_list.extend(query_samples(options))

		print("\n[+] Searching for samples with %s hashes" % str(len(hashes)))
		for h in hashes:
			if 'ip' in options:
				del options[u'ip']
			options[u'checksum'] = h
			print("\n" + str(options))
			new_sample_list.extend(query_samples(options))

		print("\n[+] De-duplicating new list of samples...")
		new_sample_list = dedup(new_sample_list)
		print("[+] Recursion Depth %s" % str(depth))
		sample_list.extend(recursive_search(new_sample_list,options,depth))
		return sample_list
	else:
		print(sample_list)
		return sample_list


def main():

	parser = ArgumentParser(description='Recursively return samples from provided IOC')
	parser.add_argument('api_key', type=str,
		help='API key for accessing Threatgrid')
	parser.add_argument('--after', type=str,
		help='Start date for query')
	parser.add_argument('--before', type=str,
		help='End date for query')
	parser.add_argument('--org_only', action='store_true',
		default=False)
	parser.add_argument('--user_only', action='store_true',
		default=False)
	parser.add_argument('--checksum', type=str,
		help='SHA1/SHA256/MD5 hash to search for')
	parser.add_argument('--checksum_sample', type=str,
		help='SHA1/SHA256/MD5 hash of sample to search for')
	parser.add_argument('--path', type=str,
		help='File path to search for')
	parser.add_argument('--path_sample', type=str,
		help='File path for sample name')
	parser.add_argument('--path_artifact', type=str,
		help='File path of artifacts on disk')
	parser.add_argument('--path_deleted', type=str,
		help='File path of deleted paths')
	parser.add_argument('--url', type=str,
		help='URL to search for')
	parser.add_argument('--registry_key', type=str,
		help='Registry key to search for')
	parser.add_argument('--domain', type=str,
		help='Domain to search for')
	parser.add_argument('--domain_dns_lookup', type=str,
		help='DNS lookup to search for')
	parser.add_argument('--domain_http_request', type=str,
		help='Domain in HTTP request to search for')
	parser.add_argument('--ip', type=str,
		help='IP to search for')
	parser.add_argument('--ip_dns_lookup', type=str,
		help='DNS IP response to search for')
	parser.add_argument('--ip_src', type=str,
		help='IP source to look for')
	parser.add_argument('--ip_dst', type=str,
		help='IP destination to look for')
	parser.add_argument('--ioc', type=str,
		help='IOC to search for')
	parser.add_argument('--limit', type=str,
		help='Limit API results (Default: 10)')
	parser.add_argument('--tag', type=str,
		help='Tag name to look for')
	parser.add_argument('--depth', type=int,
		help='Desired depth of recursion (Default: 3)')

	args = 	parser.parse_args()

	options = {
		'api_key' : args.api_key,
		'before' : args.before,
		'after' : args.after,
		'checksum' : args.checksum,
		'checksum_sample' : args.checksum_sample,
		'path' : args.path,
		'path_sample' : args.path_sample,
		'path_artifact' : args.path_artifact,
		'path_deleted' : args.path_deleted,
		'url' : args.url,
		'registry_key' : args.registry_key,
		'domain' : args.domain,
		'domain_dns_lookup' : args.domain_dns_lookup,
		'domain_http_request' : args.domain_http_request,
		'ip' : args.ip,
		'ip_dns_lookup' : args.ip_dns_lookup,
		'ip_src' : args.ip_src,
		'ip_dst' : args.ip_dst,
		'ioc' : args.ioc,
		'limit' : args.limit,
		'tag' : args.tag,
		'depth': args.depth
	}

	#remove options that are None, makes API call cleaner
	options = {k:v for k,v in options.items() if v is not None}

	#Limit returned results for API queries, advised for performance/testing reasons
	if 'limit' in options:
		global _LIMIT
		_LIMIT = int(args.limit)
	else:
		options['limit'] = 10

	#Use user supplied recursion depth
	if 'depth' in options:
		global _RECURSION_DEPTH
		_RECURSION_DEPTH = args.depth
		#remove depth from options once we get value, API calls don't need to see this
		del options['depth']

	#query for initial samples with provided IOC's
	sample_list = query_samples(options)
	#start recursive search, grabbing IOCs from seed samples to search for more related samples
	sample_list = dedup(recursive_search(sample_list,options))

	#output samples to file
	fp = open("sample_list.txt","w")
	for sample in sample_list:
		fp.write(sample + "\n")
	fp.close()



if __name__ == '__main__':
	main()