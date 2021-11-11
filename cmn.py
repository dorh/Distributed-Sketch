import hashlib
import struct
import sys
import os
import time
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
            if True:
                sha512_calculated_values[hash_value] = val
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
        raise Exception("number of new hash_function_set does not equal to d, " + len(hash_function_set))
    
    new_sketch = []
    for i in range(d):
        new_sketch.append([0] * new_w)
        line_hash_function = hash_function_set[i]
        for k in range(w):
            curr_index = line_hash_function(str(k))%new_w
            if new_sketch[i][curr_index] < sketch.sketch[i][k]:
                new_sketch[i][curr_index] = sketch.sketch[i][k]        
    return WCompressCMSketch(new_sketch, sketch.functions, hash_function_set, w)

def analyze_lines_multiple_sketches(lines, sigma, ratios):
    src_ip_dict = {}
    base_w = 2**11
    w = base_w * sigma    
    d = 4
    base_sketch = CMSketch(None, HASH_FUNCTIONS[:d], w, d)
    total_ratios = [1]
    for r in ratios:
        total_ratios.append(total_ratios[-1]*r)
    probabilities = [a/sum(total_ratios) for a in total_ratios]
    
    cn=(1+(sum([math.prod(ratios[i:]) for i in range(len(ratios))])))/(sigma**(-1)*(1+sum([math.prod([math.sqrt(j) for j in ratios[i:]]) for i in range(len(ratios))])))
    compress_ratios = [cn]
    
    for r in ratios:
        compress_ratios.append(compress_ratios[-1]/math.sqrt(r))
    compress_sketches = [CMSketch(None, HASH_FUNCTIONS[d:2*d], w, d) for i in range(len(compress_ratios))]
    
    non_compress_sketch = CMSketch(None, HASH_FUNCTIONS[:d], base_w, d)

    for line in lines:
        src_ip = line.rstrip("\n").split("\t")[0]
        dst_ip = line.rstrip("\n").split("\t")[1]
        k = src_ip
        if src_ip not in src_ip_dict:
            src_ip_dict[src_ip] = 0
        src_ip_dict[src_ip] += 1
        
        base_sketch.insert(src_ip)
        non_compress_sketch.insert(src_ip)
        x = random.random()
        for i, p in enumerate(probabilities):
            x-=p
            if x <=0:
                compress_sketches[i].insert(src_ip)
                break
                    
    print("finish inserting all")        
    
    zipped_sketches = [regular_zip(sk, int(w/sigma)) for sk in compress_sketches]
    compressed_sketches = [generic_w_compression(sk, math.ceil(w/compress_ratios[i]),HASH_FUNCTIONS[2*d:3*d]) for i,sk in enumerate(compress_sketches)]
    
    zipped_sum = 0.0
    compress_sum = 0.0
    base_sketch_sum = 0.0
    non_compress_sketches_sum = 0.0    
    for src_ip in src_ip_dict:
        real_f = src_ip_dict[src_ip]
        
        base_sketch_value, _ = base_sketch.query(src_ip)
        base_sketch_sum += float(base_sketch_value - real_f)/real_f
        non_compress_sketch_value, _ = non_compress_sketch.query(src_ip)
        non_compress_sketches_sum += float(non_compress_sketch_value - real_f)/real_f
        
        total_value = 0
        for sk in zipped_sketches:
            sketch_value, _ = sk.query(src_ip)
            total_value += sketch_value
        zipped_sum += float(total_value - real_f)/real_f
        
        total_value = 0        
        for sk in compressed_sketches:
            sketch_value, _ = sk.query(src_ip)
            total_value += sketch_value
        
        compress_sum += float(total_value - real_f)/real_f
    histogram = [(src_ip_dict[k], k) for k in src_ip_dict]
    histogram.sort()
    histogram.reverse()
    
    top50 = [ip[1] for ip in histogram[:50]]
    
    top_sketches_sum = 0.0
    top_zipped_sum = 0.0
    top_compress_sum = 0.0
    top_base_sketch_sum = 0.0

    for src_ip in top50:
        real_f = src_ip_dict[src_ip]
        
        base_sketch_value, _ = base_sketch.query(src_ip)
        top_base_sketch_sum += float(base_sketch_value - real_f)/real_f
        non_compress_sketch_value, _ = non_compress_sketch.query(src_ip)
        top_sketches_sum += float(non_compress_sketch_value - real_f)/real_f
        
        total_value = 0
        for sk in zipped_sketches:
            sketch_value, _ = sk.query(src_ip)
            total_value += sketch_value
        top_zipped_sum += float(total_value - real_f)/real_f
        
        total_value = 0        
        for sk in compressed_sketches:
            sketch_value, _ = sk.query(src_ip)
            total_value += sketch_value
        top_compress_sum += float(total_value - real_f)/real_f
    
    zip_size = sum([sk.get_size() for sk in zipped_sketches])
    compress_size = sum([sk.get_size() for sk in compressed_sketches])
    
    return (sigma, len(src_ip_dict), base_sketch_sum/len(src_ip_dict), non_compress_sketches_sum/len(src_ip_dict), zipped_sum/len(src_ip_dict), compress_sum/len(src_ip_dict), top_base_sketch_sum/len(src_ip_dict), top_sketches_sum/len(src_ip_dict), top_zipped_sum/len(src_ip_dict), top_compress_sum/len(src_ip_dict), zip_size, compress_size)
        
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
    ip_files = [filename for filename in os.listdir(files_directory) if filename.endswith("tcp")]
    j = 0
    distributions = [generate_linear_distribution(7,10), generate_exponential_distribution(7,10), generate_arc_tan_distribution(7,10), generate_constant_distribution(10)]
    results = {}
    for i in range(len(distributions)):
        results[i] = []
    
    for file_i, filename in enumerate(ip_files):
        full_filename = os.path.join(files_directory, filename)
        with open(full_filename, "r") as f:
            lines = []
            i = 0
            for line in f.readlines():
                i+=1
                lines.append(line)
                if i %1000000 == 0:
                    sigmas = [2,4,8]
                    for l,dist in enumerate(distributions):
                        res = analyze_lines_multiple_sketches(lines, 32, dist)
                        results[l].append(res)
                        print ("finish dist: " + str(l) + ", round: " + str(j))

                    i=0
                    lines = []
                    j+=1
                    print ("end round " + str(j))
                    sha512_calculated_values = {}
            print(results)
            for i in range(len(distributions)):
                full_results = [[i] + list(results[i][j]) + [results[i][j][a]/results[i][j][1] for a in range(2,len(results[i][j]))] for j in range(len(results[i]))]
                for res in full_results:
                    print(res)
                results[i] = []            
            
    print (results)

def calculate_savings():
    distributions = [generate_linear_distribution(5,10), generate_exponential_distribution(5,10), generate_arc_tan_distribution(5,10), generate_constant_distribution(10)]
    sigma=8
    for ratios in distributions:
        new_ratios = [1] + ratios
        new_ratios.reverse()
        numerator = (sum([math.prod(new_ratios[i:]) for i in range(len(new_ratios))]))
        denom = (sum([math.prod([math.sqrt(j) for j in new_ratios[i:]]) for i in range(len(new_ratios))]))
        cn = numerator/denom
        compress_ratios = [cn]
        
        for r in ratios:
            compress_ratios.append(compress_ratios[-1]/math.sqrt(r))
        print (sum([1/i for i in compress_ratios])/(10))


if __name__ == "__main__":
    calculate_savings()
    #main()
    
# Ratio between query time
# Comparison between dividing by optimal and dividing by 1/sigma