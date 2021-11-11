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


key_hashes = {}

def hash_keys_function(hash_key):
    if hash_key in key_hashes:
        return key_hashes[hash_key]
    
    val = struct.unpack("<I", hashlib.md5(hash_key.encode()).digest()[:4])[0]/2**32
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

class FlowEstimatorSketch(object):
    def __init__(self, k):
        super(FlowEstimatorSketch, self).__init__()
        self.arr = [1]*k
        self.data_appearances = {}
        
    def insert(self, insert_key):
        key_hash = hash_keys_function(insert_key)
        if key_hash in self.arr:
            self.data_appearances[key_hash] += 1
            return
        if key_hash > self.arr[-1]:
            return
        if self.arr[-1] != 1:
            del self.data_appearances[self.arr[-1]]
        self.arr[-1] = key_hash
        self.data_appearances[key_hash] = 1
        self.arr.sort()
       
    def get_size(self):
        if self.arr[-1] == 1:
            return len([i for i in self.arr if i != 1])
        return len(self.arr)/self.arr[-1]
        
    def get_partial_arr(self, size):
        return self.arr[:size]
        
    def resize(self, new_len):
        if new_len < len(self.arr):
            self.arr = self.arr[:new_len]
        else:
            self.arr = self.arr + [1]*(new_len-len(self.arr))
            
    def get_appearances(self):
        return self.data_appearances
     
def analyze_lines_multiple_sketches(lines, distributions, servers,prob):
    src_ip_dict = {}
    k = 1024
    base_sketch = FlowEstimatorSketch(k)
    probabilities = []
    for dist in distributions:
        total_ratios = [1]
        for r in dist:
            total_ratios.append(total_ratios[-1]*r)
        probabilities.append([a/sum(total_ratios) for a in total_ratios])

    split_sketches = []
    for i in range(len(probabilities)):
        split_sketches.append([])
        for _ in probabilities[i]:
            split_sketches[i].append(FlowEstimatorSketch(k))

    for line in lines:
        src_ip = line.rstrip("\n").split("\t")[0]
        
        if src_ip not in src_ip_dict:
            src_ip_dict[src_ip] = 0
        src_ip_dict[src_ip] += 1
        
        base_sketch.insert(src_ip)
        
        for i, probs in enumerate(probabilities):
            x = random.random()
            for j, p in enumerate(probs):
                x-=p
                if x <=0:
                    split_sketches[i][j].insert(src_ip)
                    break
    print(prob, len(src_ip_dict), len(lines))
    base_sketch_estimation = base_sketch.get_size()
    sketches_estimations = []
    for sketches in split_sketches:
        
        servers_estimations = [s.get_size() for s in sketches]
        total_servers_estimation = sum(servers_estimations)
    
        servers_needed_ratios = [math.ceil((s*k*math.log(servers))/total_servers_estimation) for s in servers_estimations]
    
        current_mins = set()
        for i, server_ratio in enumerate(servers_needed_ratios):
            part_arr = sketches[i].get_partial_arr(server_ratio)
            current_mins = current_mins.union(set(part_arr))
    
        max_value = max(current_mins)
        sketches_estimations.append((len(current_mins), max_value, len(current_mins)/max_value, k/max_value))
    print (k, len(src_ip_dict), base_sketch_estimation, sketches_estimations)
    with open(os.path.join("Pickle4","pickle_new_{}_{}_{}.bin".format(servers, len(src_ip_dict),prob)), "wb") as f:
        pickle.dump(split_sketches, f)

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
    ip_files = [filename for filename in os.listdir(files_directory) if filename.endswith("chic.tcp")]
    j = 0

    for prob in [0.35, 0.45, 0.6, 0.7, 0.8]:
        for file_i, filename in enumerate(ip_files):
            full_filename = os.path.join(files_directory, filename)
            with open(full_filename, "r") as f:
                print("Start file " + full_filename)
                lines = []
                i = 0
                src_ip_ll = {}
                for line in f.readlines():
                    src_ip = line.rstrip("\n").split("\t")[0]
                    if src_ip not in src_ip_ll:
                        x = random.random()
                        if x < prob:
                            src_ip_ll[src_ip] = True
                        else:
                            src_ip_ll[src_ip] = False
                    if src_ip_ll[src_ip]:
                        i+=1
                        lines.append(line)
                    if i == 1000000:
                        for servers in [10,20,50,100,200]:
                            distributions = [generate_linear_distribution(10,servers)]
                            analyze_lines_multiple_sketches(lines, distributions, servers, prob)
                        i=0
                        lines = []
                        j+=1
                        key_hashes = {}


if __name__ == "__main__":
    main()
    
# Ratio between query time
# Comparison between dividing by optimal and dividing by 1/sigma