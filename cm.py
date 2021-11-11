import hashlib
import struct
import sys
import os
import time
import numpy
import math
import random
from functools import wraps
from timeit import default_timer as timer


sha512_calculated_values = {}


def timing(f):
	@wraps(f)
	def wrapper(*args, **kwargs):
		start = timer()
		result = f(*args, **kwargs)
		end = timer()
		return result, end-start
	return wrapper

class CMSketch(object):
	def __init__(self, existing_sketch, hash_function_set, w=0,d=0):
		super(CMSketch, self).__init__()
		if existing_sketch is None:
			self.w = w
			self.d = d
			if len(hash_function_set) != d:
				print (len(hash_function_set),d)
				raise Exception("not enough functions")
			self.functions = hash_function_set
			self.sketch = []
			for i in range(d):
				self.sketch.append([0]*w)
		else:
			self.d = len(existing_sketch)
			self.w = len(existing_sketch[0])
			if len(hash_function_set) != self.d:
				print (len(hash_function_set),self.d)
				raise Exception("not enough functions")
			self.functions = hash_function_set
			self.sketch = existing_sketch
		
	def insert(self, insert_key):
		for i in range(self.d):
			curr_index = self.functions[i](insert_key) % self.w
			self.sketch[i][curr_index] += 1
	
	@timing		
	def query(self, query_key):
		m = 1000000000000000000000000000 
		for i in range(self.d):
			curr_index = self.functions[i](query_key) % self.w
			if self.sketch[i][curr_index] < m:
				m = self.sketch[i][curr_index]
		return m
		
	def get_size(self):
		return self.d * self.w * 4
		
class WCompressCMSketch(CMSketch):
	def __init__(self, existing_sketch, original_function_set, new_function_set, orig_w):
		super(WCompressCMSketch, self).__init__(existing_sketch, original_function_set)
		self.new_function_set = new_function_set
		self.orig_w = orig_w
	
	@timing
	def query(self, query_key):
		return min([self.sketch[i][self.new_function_set[i](str(self.functions[i](query_key)%self.orig_w))%self.w] for i in range(self.d)])
		
		
		
def static_vars(**kwargs):
	def decorate(func):
		for k in kwargs:
			setattr(func, k, kwargs[k])
		return func
	return decorate

@static_vars(byte_start=0, byte_end=4)
def new_hash_function():
	@static_vars(s=new_hash_function.byte_start, e=new_hash_function.byte_end)
	def hash_f(hash_value):
		try:
			val = sha512_calculated_values[hash_value]
			return struct.unpack("I", val[hash_f.s:hash_f.e])[0]
		except KeyError:
			encode_hash = hash_value.encode()
			val = hashlib.shake_256(encode_hash).digest(256)
			#if True:
			#	sha512_calculated_values[hash_value] = val
			return struct.unpack("I", val[hash_f.s:hash_f.e])[0]
		return 0
	new_hash_function.byte_start += 4
	new_hash_function.byte_end += 4
	
	return hash_f
	
HASH_FUNCTIONS = [new_hash_function() for _ in range(64)]


def regular_zip(sketch, new_w):
	d = sketch.d
	w = sketch.w
	if w % new_w != 0:
		raise Exception("new_w is not a divider of w")
		
	new_sketch = []
	for i in range(d):
		new_sketch.append([])
		for j in range(new_w):
			m = 0
			for k in range(j, w, new_w):
				if sketch.sketch[i][k] > m:
					m = sketch.sketch[i][k]
		
			new_sketch[i].append(m)

	return CMSketch(new_sketch, sketch.functions)

	
def generic_w_compression(sketch, new_w, hash_function_set):
	d = sketch.d
	w = sketch.w
	if (len(hash_function_set) != d):
		raise Exception("number of new hash_function_set does not equal to d")
	
	new_sketch = []
	for i in range(d):
		new_sketch.append([0] * new_w)
		line_hash_function = hash_function_set[i]
		for k in range(w):
			curr_index = line_hash_function(str(k))%new_w
			if new_sketch[i][curr_index] < sketch.sketch[i][k]:
				new_sketch[i][curr_index] = sketch.sketch[i][k]		
	return WCompressCMSketch(new_sketch, sketch.functions, hash_function_set, w)

@timing
def analyze_lines(lines):
	src_ip_dict = {}
	
	w = 2**17	
	d = 4
	
	sketches = [CMSketch(None, HASH_FUNCTIONS[:d], w/j, d) for j in [1,2,4,8,16,32,64]]
	
	for line in lines:
		src_ip = line.rstrip("\n").split("\t")[0]
		dst_ip = line.rstrip("\n").split("\t")[1]
		k = src_ip+","+dst_ip
		if src_ip not in src_ip_dict:
			src_ip_dict[src_ip] = 0
		src_ip_dict[src_ip] += 1
		
		for sk in sketches:
			sk.insert(src_ip)

	zipped_sketches = [regular_zip(sketches[0], int(w/j)) for j in [2,4,8,16,32,64]]
	compressed_sketches = [generic_w_compression(sketches[0], int(w/j), HASH_FUNCTIONS[d:2*d]) for j in [2,4,8,16,32,64]]
	zip_action_timing = [sk[1] for sk in zipped_sketches]
	compress_action_timing = [sk[1] for sk in compressed_sketches]
	
	sketches_sum = [0.0 for _ in sketches]
	zipped_sum = [0.0 for _ in zipped_sketches]
	zipped_timing = [0.0 for _ in zipped_sketches]
	compress_sum = [0.0 for _ in compressed_sketches]
	compress_timing = [0.0 for _ in compressed_sketches]
		
	for src_ip in src_ip_dict:
		real_f = src_ip_dict[src_ip]
		
		for i, _ in enumerate(sketches):
			sketch_value, _ = sketches[i].query(src_ip)
			sketches_sum[i] += float(sketch_value - real_f)/real_f
			
		for i, _ in enumerate(zipped_sketches):
			zip_value, q_time = zipped_sketches[i][0].query(src_ip)
			zipped_sum[i] += float(zip_value - real_f)/real_f
			zipped_timing[i] += q_time
			
		for i, _ in enumerate(compressed_sketches):
			compress_value, q_time = compressed_sketches[i][0].query(src_ip)
			compress_sum[i] += float(compress_value - real_f)/real_f
			compress_timing[i] += q_time
			
	histogram = [(src_ip_dict[k], k) for k in src_ip_dict]
	histogram.sort()
	histogram.reverse()
	
	top50 = [ip[1] for ip in histogram[:50]]
	
	top_sketches_sum = [0.0 for _ in sketches]
	top_zipped_sum = [0.0 for _ in zipped_sketches]
	top_compress_sum = [0.0 for _ in compressed_sketches]
	
	for src_ip in top50:
		real_f = src_ip_dict[src_ip]
		
		for i, _ in enumerate(sketches):
			sketch_value, _ = sketches[i].query(src_ip)
			top_sketches_sum[i] += float(sketch_value - real_f)/real_f
			
		for i, _ in enumerate(zipped_sketches):
			zip_value, q_time = zipped_sketches[i][0].query(src_ip)
			top_zipped_sum[i] += float(zip_value - real_f)/real_f
			
		for i, _ in enumerate(compressed_sketches):
			compress_value, q_time = compressed_sketches[i][0].query(src_ip)
			top_compress_sum[i] += float(compress_value - real_f)/real_f
		

	return (len(src_ip_dict), sketches_sum, zipped_sum, compress_sum, zipped_timing, compress_timing, zip_action_timing, compress_action_timing, top_sketches_sum, top_zipped_sum, top_compress_sum)

def analyze_lines_multiple_sketches(lines, sigma, ranged):
	src_ip_dict = {}
	w = 2**16 * sigma	
	d = 4
	random.shuffle(HASH_FUNCTIONS)
	base_sketch = CMSketch(None, HASH_FUNCTIONS[:d], w, d)
	compress_sketches = [(i/5,float(i/5)/(i/5+1),
	CMSketch(None, HASH_FUNCTIONS[:d], w, d),
	CMSketch(None, HASH_FUNCTIONS[d:2*d], w, d)) for i in ranged]
	
	non_compress_sketch = CMSketch(None, HASH_FUNCTIONS[:d], 2**16, d)
	
	for line in lines:
		src_ip = line.rstrip("\n").split("\t")[0]
		dst_ip = line.rstrip("\n").split("\t")[1]
		k = src_ip
		if src_ip not in src_ip_dict:
			src_ip_dict[src_ip] = 0
		src_ip_dict[src_ip] += 1
		
		base_sketch.insert(src_ip)
		non_compress_sketch.insert(src_ip)
		for i, _ in enumerate(compress_sketches):
			if random.random() < compress_sketches[i][1]:
				compress_sketches[i][2].insert(src_ip)
					
			else:
				compress_sketches[i][3].insert(src_ip)
					
	
	def calculate_first_compress_ratio(k, sig):
		return float(k+1)/(sig*(k+math.sqrt(k)))	

	def calculate_second_compress_ratio(k, sig):
		return float(k+1)/(sig*(1+math.sqrt(k)))
	
	zipped_sketches = [(regular_zip(sk[2], int(w/sigma)),regular_zip(sk[3], int(w/sigma))) for sk in compress_sketches[:1]]
	compressed_sketches = [(generic_w_compression(sk[2], int(w/calculate_first_compress_ratio(sk[0],float(1)/sigma)),HASH_FUNCTIONS[3*d:4*d]), 
	generic_w_compression(sk[3], int(w/calculate_second_compress_ratio(sk[0], float(1)/sigma)),HASH_FUNCTIONS[3*d:4*d])) for sk in compress_sketches]
	
	zipped_sum = [0.0 for _ in zipped_sketches]
	compress_sum = [0.0 for _ in compressed_sketches]
	base_sketch_sum = 0.0
	non_compress_sketches_sum = 0.0	
	
	for src_ip in src_ip_dict:
		real_f = src_ip_dict[src_ip]
		
		base_sketch_value, _ = base_sketch.query(src_ip)
		base_sketch_sum += float(base_sketch_value - real_f)/real_f
		non_compress_sketch_value, _ = non_compress_sketch.query(src_ip)
		non_compress_sketches_sum += float(non_compress_sketch_value - real_f)/real_f
			
		for i, _ in enumerate(zipped_sketches):
			first_sketch_value, _ = zipped_sketches[i][0].query(src_ip)
			second_sketch_value, _ = zipped_sketches[i][1].query(src_ip)
			total_value = first_sketch_value + second_sketch_value
			zipped_sum[i] += float(total_value - real_f)/real_f
			
		for i, _ in enumerate(compressed_sketches):
			first_sketch_value, _ = compressed_sketches[i][0].query(src_ip)
			second_sketch_value, _ = compressed_sketches[i][1].query(src_ip)
			total_value = first_sketch_value + second_sketch_value
			compress_sum[i] += float(total_value - real_f)/real_f
			
	histogram = [(src_ip_dict[k], k) for k in src_ip_dict]
	histogram.sort()
	histogram.reverse()
	
	top50 = [ip[1] for ip in histogram[:50]]
	
	top_sketches_sum = 0.0
	top_zipped_sum = [0.0 for _ in zipped_sketches]
	top_compress_sum = [0.0 for _ in compressed_sketches]
	top_base_sketch_sum = 0.0

	for src_ip in top50:
		real_f = src_ip_dict[src_ip]
		
		base_sketch_value, _ = base_sketch.query(src_ip)
		top_base_sketch_sum += float(base_sketch_value - real_f)/real_f
		non_compress_sketch_value, _ = non_compress_sketch.query(src_ip)
		top_sketches_sum += float(non_compress_sketch_value - real_f)/real_f
		
		for i, _ in enumerate(zipped_sketches):
			first_sketch_value, _ = zipped_sketches[i][0].query(src_ip)
			second_sketch_value, _ = zipped_sketches[i][1].query(src_ip)
			total_value = first_sketch_value + second_sketch_value
			top_zipped_sum[i] += float(total_value - real_f)/real_f
			
		for i, _ in enumerate(compressed_sketches):
			first_sketch_value, _ = compressed_sketches[i][0].query(src_ip)
			second_sketch_value, _ = compressed_sketches[i][1].query(src_ip)
			total_value = first_sketch_value + second_sketch_value
			top_compress_sum[i] += float(total_value - real_f)/real_f
	
	zipped_sizes = [sk[0].get_size() + sk[1].get_size() for sk in zipped_sketches]
	compressed_sizes = [sk[0].get_size() + sk[1].get_size() for sk in compressed_sketches]
	
	return (sigma, len(src_ip_dict), base_sketch_sum, non_compress_sketches_sum, zipped_sum, compress_sum, top_base_sketch_sum, top_sketches_sum, top_zipped_sum, top_compress_sum, zipped_sizes, compressed_sizes)
		
def analyze_lines_multiple_sketches_const_size(lines, sigma, ranged):
	src_ip_dict = {}
	w = 2**16 * sigma	
	d = 4
	random.shuffle(HASH_FUNCTIONS)
	compress_sketches = [(i,i/(i+1),
	CMSketch(None, HASH_FUNCTIONS[:d], w, d),
	CMSketch(None, HASH_FUNCTIONS[d:2*d], w, d), 2*sigma*(i+1)/((math.sqrt(i)+1)**2)) for i in ranged]
	
	for line in lines:
		src_ip = line.rstrip("\n").split("\t")[0]
		dst_ip = line.rstrip("\n").split("\t")[1]
		k = src_ip
		if src_ip not in src_ip_dict:
			src_ip_dict[src_ip] = 0
		src_ip_dict[src_ip] += 1
		
		for i, _ in enumerate(compress_sketches):
			if random.random() < compress_sketches[i][1]:
				compress_sketches[i][2].insert(src_ip)
			else:
				compress_sketches[i][3].insert(src_ip)
	
	def calculate_first_compress_ratio(k, sig):
		return float(2*math.sqrt(k))/(sig*(math.sqrt(k)+1))

	def calculate_second_compress_ratio(k, sig):
		return float(2)/(sig*(math.sqrt(k)+1))
	
	compressed_sketches = [(generic_w_compression(sk[2], int(w*calculate_first_compress_ratio(sk[0],sigma)),HASH_FUNCTIONS[3*d:4*d]), 
	generic_w_compression(sk[3], int(w*calculate_second_compress_ratio(sk[0], sigma)),HASH_FUNCTIONS[3*d:4*d])) for sk in compress_sketches]
	
	compress_sum = [0.0 for _ in compressed_sketches]
	
	for src_ip in src_ip_dict:
		real_f = src_ip_dict[src_ip]
			
		for i, _ in enumerate(compressed_sketches):
			first_sketch_value, _ = compressed_sketches[i][0].query(src_ip)
			second_sketch_value, _ = compressed_sketches[i][1].query(src_ip)
			total_value = first_sketch_value + second_sketch_value
			compress_sum[i] += float(total_value - real_f)/real_f
			
	compress_errors = [i/len(src_ip_dict) for i in compress_sum]
	compressed_sizes = [sk[0].get_size() + sk[1].get_size() for sk in compressed_sketches]

	return (sigma, len(src_ip_dict), compress_sum, compress_errors, compressed_sizes)


	
def main():
	files_directory = sys.argv[1]
	ip_files = [filename for filename in os.listdir(files_directory) if filename.endswith("tcp")]
	results = []
	times = []
	j = 0
	for file_i, filename in enumerate(ip_files):
		if file_i != 2:
			continue
		full_filename = os.path.join(files_directory, filename)
		with open(full_filename, "r") as f:
			lines = []
			i = 0
			for line in f.readlines():
				i+=1
				lines.append(line)
				if i %1000000 == 0:
					sigmas = [32]
					for k in sigmas:
						res = analyze_lines_multiple_sketches_const_size(lines, k, [100])
						results.append(res)
						print (str(k) + " end round " + str(j))
					i=0
					lines = []
					j+=1
					print(results)
					results = []
					print ("end round " + str(j))
					sha512_calculated_values = {}
			print ("end file " + full_filename)
			results = []			

	print (results)

if __name__ == "__main__":
	main()
	
# Ratio between query time
# Comparison between dividing by optimal and dividing by 1/sigma