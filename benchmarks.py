import time
from statistics import mean, stdev
import string
import random
from your_code import Server, Client
from os import path, mkdir
import json


def benchmark(func, it=10000, keep_res=False):
    """"
    This function runs a basic benchmark on the function passed as argument. It should be called with a lambda function,
    e.g., benchmark(lambda: 4+4, 300).
    :param keep_res: Indicates if the intermediary results should be kept.
    :param func: The (anonymous) function that is benchmark
    :param it: The number of iteration.
    :return: A dict that contains the mean, the standard deviation, the min and the max (in seconds)

    """
    res = {}
    results = []

    for i in range(it):
        start = time.time()
        func()
        end = time.time()
        results.append(end - start)

    res["mean"] = mean(results)
    res["std"] = stdev(results)
    res["min"] = min(results)
    res["max"] = max(results)

    if keep_res:
        res["results"] = results

    return res


def mkdir_benchmark_folder():
    if not path.exists("benchmark"):
        mkdir("benchmark", 0o777)


def random_attr(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))


def benchmark_gen_ca(nbrs_attr, it=10000):
    """"
    Benchmarks the function generate_ca and save the result in ./benchmark/gen_ca.json
    :param nbrs_attr: list containing the number of attributes for each round of the benchmark
    :param it: the number of iteration
    """
    print("========== generate_ca ==========")
    # Generate inputs attributes
    print("# generating inputs...")
    inputs = []
    for nbr_attr in nbrs_attr:
        if nbr_attr == 0:
            inputs.append("")
        else:
            attrs = [random_attr(5) for i in range(nbr_attr)]
            attrs = ",".join(attrs)
            inputs.append(attrs)

    # benchmarking
    print("# benchmarking...")
    benchmarks = {}
    for i, attr in enumerate(inputs):
        bench = benchmark(lambda: Server.generate_ca(attr), it)
        benchmarks[nbrs_attr[i]] = bench

    print("# benchmarks done, saving...")
    mkdir_benchmark_folder()
    with open("benchmark/gen_ca.json", "w") as json_file:
        json.dump(benchmarks, json_file)


def benchmark_prepare_registration(nbrs_attr, it=10000):
    print("========== prepare registration ==========")
    print("# generating ca and inputs...")
    attrs = [random_attr(5) for i in range(100)]
    server_pk, server_sk = Server.generate_ca(",".join(attrs))
    client = Client()

    inputs = []
    for nbr_attr in nbrs_attr:
        if nbr_attr == 0:
            inputs.append("")
        else:
            client_attrs = ",".join(random.sample(attrs, nbr_attr))
            inputs.append(client_attrs)

    print("# benchmarking...")
    benchmarks = {}
    for i, attr in enumerate(inputs):
        bench = benchmark(lambda: client.prepare_registration(server_pk, "bob", attr), it)
        benchmarks[nbrs_attr[i]] = bench

    print("# benchmarks done, saving...")
    mkdir_benchmark_folder()
    with open("benchmark/prepare_registration.json", "w") as json_file:
        json.dump(benchmarks, json_file)

def benchmark_register(nbrs_attr,it=10000):
    print("========== prepare registration ==========")
    print("# generating ca and inputs...")
    attrs = [random_attr(5) for i in range(100)]
    server_pk, server_sk = Server.generate_ca(",".join(attrs))
    client = Client()
    server = Server()

    inputs = []
    for nbr_attr in nbrs_attr:
        if nbr_attr == 0:
            inputs.append("")
        else:
            client_attrs = ",".join(random.sample(attrs, nbr_attr))
            inputs.append(client_attrs)

    requests = []
    for attr in inputs:
        issuance_request, client_private_state = client.prepare_registration(server_pk, "bob", attr)
        requests.append((issuance_request, client_private_state))
    print("# benchmarking...")
    benchmarks = {}
    for i, req in enumerate(requests):
        bench = benchmark(lambda: server.register(server_sk, req[0], "bob", ",".join(req[1][1])),it)
        benchmarks[i] = bench

    print("# benchmarks done, saving...")
    mkdir_benchmark_folder()
    with open("benchmark/register.json", "w") as json_file:
        json.dump(benchmarks, json_file)

if __name__ == '__main__':
    nbrs_attr = [i * 10 for i in range(10)]
    #benchmark_gen_ca(nbrs_attr, 100)
    #benchmark_prepare_registration(nbrs_attr, 100)
    benchmark_register(nbrs_attr, 100)
