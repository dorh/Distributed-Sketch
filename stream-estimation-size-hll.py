import hashlib
import struct
import sys
import os
import time
import math
import random
import pickle
from functools import wraps
from timeit import default_timer as timer
sys.path.append(".")
import hll

key_hashes = {}

def hash_keys_function(hash_key):
    if hash_key in key_hashes:
        return key_hashes[hash_key]
    
    val = struct.unpack("<I", hashlib.md5(hash_key.encode()).digest()[:4])[0]
    key_hashes[hash_key] = val
    return val

def timing(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        start = timer()
        result = f(*args, **kwargs)
        end = timer()
        return result, end-start
    return wrapper

class HLLFlowEstimatorSketch(object):
    def __init__(self, k):
        super(HLLFlowEstimatorSketch, self).__init__()
        self.arr = [0 for i in range(2**k)]
        self.k = k
        self.m = 1<<k
    
    @staticmethod
    def _get_alpha(b):
        if not (4 <= b <= 16):
            raise ValueError("b=%d should be in range [4 : 16]" % b)

        if b == 4:
            return 0.673

        if b == 5:
            return 0.697

        if b == 6:
            return 0.709

        return 0.7213 / (1.0 + 1.079 / (1 << b))
    
    def insert(self, insert_key):
        key_hash = hash_keys_function(insert_key)
        j = key_hash & ((1 << self.k) - 1)
        w = key_hash & (2**32 - ((1 << self.k) - 1) -1)
        bit_count = 0
        bit = 31
        while True:
            if w & (1<<bit) > 0:
                break
            bit-=1
            bit_count+=1
        self.arr[j] = max(self.arr[j], bit_count)
       
    def get_size(self):
        E = self._get_alpha(self.k) * float(self.m ** 2) / sum(math.pow(2.0, -x) for x in self.arr)

        if E <= 2.5 * self.m:             # Small range correction
            V = self.arr.count(0)           #count number or registers equal to 0
            return self.m * math.log(self.m / float(V)) if V > 0 else E
        elif E <= (float(1 << 160) / 30.0): 
            return E
        else:
            return -(1 << 160) * math.log(1.0 - E / (1 << 160))
        
    def get_partial_arr(self, size):
        return self.arr[:size]
        
    def resize(self, new_len):
        if new_len < len(self.arr):
            self.arr = self.arr[:new_len]
        else:
            self.arr = self.arr + [1]*(new_len-len(self.arr))
     
def calculate_hit_rate(base_sketch_arr, aggregated_arr):
    count = 0 
    for i in range(len(base_sketch_arr)):
        if base_sketch_arr[i] == aggregated_arr[i]:
            count += 1
    return count
     
def get_aggregated_estimation(aggregated_arr):
    p_val = int(math.log(len(aggregated_arr),2))
    h = hll.HyperLogLog(p_val)
    h.set_M(aggregated_arr)
    return len(h)
     
def get_prob_method(base_sketch, split_sketches, size):
    base_sketch_arr = base_sketch.get_M()
    aggregated_arr = [0 for _ in range(len(base_sketch_arr))]
    count = 0
    for sk in split_sketches:
        sk_arr = sk.get_M()
        for i in range(len(aggregated_arr)):
            p = random.random()
            if p <= size:
                count += 1
                if sk_arr[i] > aggregated_arr[i]:
                    aggregated_arr[i] = sk_arr[i]
                    
    hit_rate = calculate_hit_rate(base_sketch_arr, aggregated_arr)
    aggregated_estimation = get_aggregated_estimation(aggregated_arr)
    
    return hit_rate, aggregated_estimation, count
    
def get_thresh_method(base_sketch, split_sketches, size):
    base_sketch_arr = base_sketch.get_M()
    histogram = [0 for i in range(32)]
    for sk in split_sketches:
        sk_arr = sk.get_M()
        for i in sk_arr:
            histogram[i] += 1
            
    total = sum(histogram)
    skip = int((1-size)*total)
    for k in range(len(histogram)):
        skip -= histogram[k]
        if skip <= 0:
            prob = 1-float(histogram[k]+skip)/histogram[k]
            break
    aggregated_arr = [0 for _ in range(len(base_sketch_arr))]
    count = 0
    for sk in split_sketches:
        sk_arr = sk.get_M()
        for i in range(len(aggregated_arr)):
            if sk_arr[i] > k:
                count += 1
                if sk_arr[i] > aggregated_arr[i]:
                    aggregated_arr[i] = sk_arr[i]
            if sk_arr[i] == k:
                if random.random() <= prob:
                    count+=1
                    if sk_arr[i] > aggregated_arr[i]:
                        aggregated_arr[i] = sk_arr[i]
    hit_rate = calculate_hit_rate(base_sketch_arr, aggregated_arr)
    for i in range(len(aggregated_arr)):
        if aggregated_arr[i] == 0:
            aggregated_arr[i] = random.randint(0,k-1)
    aggregated_estimation = get_aggregated_estimation(aggregated_arr)
    
    return hit_rate, aggregated_estimation, count

def calculate_our_prob(m, c, Ni):
    return (1-(1.0/m)*2**(-(c-1)))**Ni

def get_prob_value_method(base_sketch, split_sketches, size):
    base_sketch_arr = base_sketch.get_M()

    total = sum([sk.get_total_input() for sk in split_sketches])
    ratios = []
    for sk in split_sketches:
        sk_arr = sk.get_M()
        sk_m = sk.get_m()
        non_sk_total = total - sk.get_total_input()
        probs = []
        for i in sk_arr:
            probs.append(calculate_our_prob(sk_m, i, non_sk_total))
        probs_avg = sum(probs)/len(probs)
        probs_ratio = (size-3.0/128)/probs_avg
        for i in range(1000):
            optional_probs = [min(1,p*probs_ratio) for p in probs]
            probs_avg = sum(optional_probs)/len(optional_probs)
            partial_probs_ratio = (size-3.0/128)/probs_avg

            probs_ratio*= partial_probs_ratio
        ratios.append(probs_ratio)
    aggregated_arr = [-1 for _ in range(len(base_sketch_arr))]
    count = 0
    for j,sk in enumerate(split_sketches):
        sk_arr = sk.get_M()
        sk_m = sk.get_m()
        non_sk_total = total - sk.get_total_input()
        for i in range(len(aggregated_arr)):
            prob = calculate_our_prob(sk_m, sk_arr[i], non_sk_total)*ratios[j]
            p = random.random()
            if p <= prob:
                count += 1
                if sk_arr[i] > aggregated_arr[i]:
                    aggregated_arr[i] = sk_arr[i]
    min_val = min([i for i in aggregated_arr if i>=0])
    hit_rate = calculate_hit_rate(base_sketch_arr, aggregated_arr)
    for i in range(len(aggregated_arr)):
        if aggregated_arr[i] == -1:
            aggregated_arr[i] = random.randint(0,min_val)
                    
    aggregated_estimation = get_aggregated_estimation(aggregated_arr)
    
    return hit_rate, aggregated_estimation, count

def random_sort_func(a):
    return a[0] + random.random()
    
def get_largest_method(base_sketch, split_sketches, size):
    base_sketch_arr = base_sketch.get_M()
    aggregated_arr = [0 for _ in range(len(base_sketch_arr))]
    count = 0

    for sk in split_sketches:
        sk_arr = sk.get_M()
        indices_arr = [(sk_arr[i], i) for i in range(len(sk_arr))]
        indices_arr.sort(reverse=True)
        total_values = int(len(indices_arr)*size)
        for j in range(total_values):
            curr_element = indices_arr[j]
            if curr_element[0] > aggregated_arr[curr_element[1]]:
                aggregated_arr[curr_element[1]] = curr_element[0]
                
        count += total_values
    min_val = min([i for i in aggregated_arr if i>=0])
    hit_rate = calculate_hit_rate(base_sketch_arr, aggregated_arr)    
    aggregated_estimation = get_aggregated_estimation(aggregated_arr)
    
    return hit_rate, aggregated_estimation, count
    
    
     
def analyze_lines_multiple_sketches(lines, distributions, servers):
    src_ip_dict = {}
    p_val = 7
    base_sketch = hll.HyperLogLog(p_val)
    probabilities = []
    for dist in distributions:
        total_ratios = [1]
        for r in dist:
            total_ratios.append(total_ratios[-1]*r)
        probabilities.append([a/sum(total_ratios) for a in total_ratios])
    probabilities = probabilities[0]
    split_sketches = []
    total_ip = 0
    for _ in probabilities:
        split_sketches.append(hll.HyperLogLog(p_val))
    for line in lines:
        src_ip = line.rstrip("\n").split("\t")[0]
        dst_ip = line.rstrip("\n").split("\t")[1]
        
        if src_ip not in src_ip_dict:
            src_ip_dict[src_ip] = []
            for i in range(2):
                x = random.random()
                for j, p in enumerate(probabilities):
                    x-=p
                    if x <=0:
                        src_ip_dict[src_ip].append(j)
                        break
            total_ip+=1
        
        base_sketch.add(src_ip)
        
        split_sketches[random.choice(src_ip_dict[src_ip])].add(src_ip)
    
    base_sketch_estimation = len(base_sketch)

    servers_estimations = [len(s) for s in split_sketches]
    with open(os.path.join("PickleHLL","pickle_hll_{}_{}.bin".format(servers, len(src_ip_dict))), "wb") as f:
        pickle.dump(split_sketches, f)
        
    sizes = [0.1]
    res = []
    for size in sizes:
        hit_rate_prob, estimation_prob, count_prob = get_prob_method(base_sketch, split_sketches, size)
        hit_rate_thresh, estimation_thresh, count_thresh = get_thresh_method(base_sketch, split_sketches, size)
        hit_rate_largest, estimation_largest, count_largest = get_largest_method(base_sketch, split_sketches, size)
        hit_rate_our_prob, estimation_our_prob, count_our_prob = get_prob_value_method(base_sketch, split_sketches, size)
        res.append((size, hit_rate_prob, hit_rate_thresh, hit_rate_largest, hit_rate_our_prob, estimation_prob, estimation_thresh,estimation_largest, estimation_our_prob, count_prob, count_thresh, count_largest, count_our_prob))
    print(res, (total_ip, base_sketch_estimation, servers))
    return
        
def generate_linear_distribution(max_min_ratio, servers):
    c_r = (max_min_ratio*servers-1)/(1-max_min_ratio)
    m = 1/(sum([i for i in range(1, servers+1)]) + servers*c_r)
    c = m*c_r
    k = [m*i+c for i in range(1,servers+1)]
    return [k[i-1]/k[i] for i in range(servers-1,0,-1)]
        
def generate_exponential_distribution(max_min_ratio, servers):
    delta = math.log(max_min_ratio)/(servers-1)
    c = 1/sum([math.e**(-i*delta) for i in range(1,servers+1)])
    k = [c*math.e**(-i*delta) for i in range(1,servers+1)]
    return [k[i-1]/k[i] for i in range(servers-1,0,-1)]
    
def generate_arc_tan_distribution(max_min_ratio, servers):
    c = math.pi*(servers+1)/(2*(servers-1))
    m = -math.pi/(servers-1)
    add_const = (max_min_ratio+1)/(max_min_ratio-1)
    all_sum = sum([math.atan(m*i+c) + add_const for i in range(1,servers+1)])
    k = [(math.atan(m*i+c) + add_const)/all_sum for i in range(1,servers+1)]
    return [k[i-1]/k[i] for i in range(servers-1,0,-1)]

def generate_constant_distribution(servers):
    return [1]*(servers-1)
    
def main():
    files_directory = sys.argv[1]
    ip_files = [filename for filename in os.listdir(files_directory) if filename.endswith("B.tcp")]
    j = 0
    servers = [50,100,200]
    for s in servers:
        distributions = [generate_arc_tan_distribution(10,s)]
        for file_i, filename in enumerate(ip_files):
            full_filename = os.path.join(files_directory, filename)
            with open(full_filename, "r") as f:
                print("Start file " + full_filename)
                lines = []
                i = 0
                for line in f.readlines():
                    i+=1
                    lines.append(line)
                    if i %100000 == 0:
                        analyze_lines_multiple_sketches(lines, distributions, s)
                        i=0
                        lines = []
                        j+=1
                        key_hashes = {}


if __name__ == "__main__":
    main()
    
# Ratio between query time
# Comparison between dividing by optimal and dividing by 1/sigma