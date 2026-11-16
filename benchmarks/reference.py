"""Independent Python expected outputs for all 15 fixed-input benchmark cases."""
import hashlib
import json

NAMES = ['matrix-multiply', 'integer-sort', 'prime-sieve', 'dijkstra', 'floyd-warshall',
         'knapsack', 'edit-distance', 'kmeans', 'nbody-integer', 'image-convolution', 'pagerank',
         'json-aggregation', 'rle-roundtrip', 'merkle-tree', 'pbkdf2-sha256']


def random_numbers():
    value = 0x12345678
    while True:
        value = (value * 1664525 + 1013904223) & 0xffffffff
        yield value


def checksum(values):
    result = 0
    for value in values:
        result = (result * 31 + value) & 0xffffffffffffffff
    return result


def reference(index):
    rng = random_numbers()
    if index == 0:
        n = 96
        a = [[next(rng) % 100 for _ in range(n)] for _ in range(n)]
        b = [[next(rng) % 100 for _ in range(n)] for _ in range(n)]
        value = checksum(sum(a[i][k] * b[k][j] for k in range(n)) for i in range(n) for j in range(n))
    elif index == 1:
        value = checksum(sorted(next(rng) for _ in range(32768)))
    elif index == 2:
        n = 500000
        prime = bytearray(b'\1') * (n + 1)
        prime[0:2] = b'\0\0'
        for p in range(2, int(n**.5)+1):
            if prime[p]:
                for k in range(p*p, n+1, p):
                    prime[k] = 0
        value = str(sum(prime)) + ',' + str(sum(i for i, flag in enumerate(prime) if flag))
    elif index == 3:
        n = 384
        graph = [[(next(rng) % n, next(rng) % 100 + 1) for _ in range(8)] for _ in range(n)]
        distances, used = [1000000] * n, set()
        distances[0] = 0
        for _ in range(n):
            u = min((i for i in range(n) if i not in used), key=lambda i: (distances[i], i))
            used.add(u)
            for v, weight in graph[u]:
                distances[v] = min(distances[v], distances[u] + weight)
        value = checksum(distances)
    elif index == 4:
        n = 96
        d = [[next(rng) % 1000 + 1 for _ in range(n)] for _ in range(n)]
        for i in range(n):
            d[i][i] = 0
        for k in range(n):
            for i in range(n):
                for j in range(n):
                    d[i][j] = min(d[i][j], d[i][k]+d[k][j])
        value = checksum(x for row in d for x in row)
    elif index == 5:
        best = [0]*20001
        for _ in range(200):
            weight, reward = next(rng) % 400 + 1, next(rng) % 1000 + 1
            for c in range(20000, weight-1, -1):
                best[c] = max(best[c], best[c-weight]+reward)
        value = best[-1]
    elif index == 6:
        a, b = [next(rng) % 23 for _ in range(1024)], [next(rng) % 23 for _ in range(1024)]
        previous = list(range(1025))
        for i, x in enumerate(a, 1):
            current = [i]
            for j, y in enumerate(b, 1):
                current.append(min(previous[j]+1, current[-1]+1, previous[j-1]+int(x != y)))
            previous = current
        value = previous[-1]
    elif index == 7:
        points = [(next(rng) % 10000, next(rng) % 10000) for _ in range(4096)]
        centers = points[:8]
        for _ in range(12):
            sums = [[0, 0, 0] for _ in range(8)]
            for x, y in points:
                k = min(range(8), key=lambda k: ((x-centers[k][0])**2+(y-centers[k][1])**2, k))
                sums[k][0] += x
                sums[k][1] += y
                sums[k][2] += 1
            centers = [(s[0]//s[2], s[1]//s[2]) if s[2] else centers[k] for k, s in enumerate(sums)]
        value = checksum(x for point in centers for x in point)
    elif index == 8:
        def div(a, b):
            return (1 if a >= 0 else -1) * (abs(a)//b)
        n = 128
        points = [[next(rng) % 10000, next(rng) % 10000] for _ in range(n)]
        velocity = [[0, 0] for _ in range(n)]
        for _ in range(30):
            acceleration = [[0, 0] for _ in range(n)]
            for i in range(n):
                for j in range(n):
                    if i != j:
                        dx, dy = points[j][0]-points[i][0], points[j][1]-points[i][1]
                        d = abs(dx)+abs(dy)+100
                        acceleration[i][0] += div(dx*100, d)
                        acceleration[i][1] += div(dy*100, d)
            for i in range(n):
                for axis in range(2):
                    velocity[i][axis] = max(-50, min(50, velocity[i][axis]+div(acceleration[i][axis], 100)))
                    points[i][axis] += velocity[i][axis]
        value = checksum(x for p in points for x in p)
    elif index == 9:
        n = 256
        pixels = [[next(rng) % 256 for _ in range(n)] for _ in range(n)]
        weights = [1, 4, 6, 4, 1]
        value = checksum(sum(pixels[y+ky-2][x+kx-2]*weights[ky]*weights[kx]
                for ky in range(5) for kx in range(5))//256 for y in range(2,n-2) for x in range(2,n-2))
    elif index == 10:
        n = 512
        graph = [[next(rng) % n for _ in range(8)] for _ in range(n)]
        ranks = [1000000000//n]*n
        for _ in range(30):
            new = [150000000//n]*n
            for i in range(n):
                amount = ranks[i]*85//100//8
                for j in graph[i]:
                    new[j] += amount
            ranks = new
        value = checksum(ranks)
    elif index == 11:
        rows = [dict(region=next(rng)%64, amount=next(rng)%100000, active=i%3 != 0, id=i) for i in range(12000)]
        sums = [0]*64
        for row in json.loads(json.dumps(rows)):
            if row['active']:
                sums[row['region']] += row['amount']
        value = checksum(sums)
    elif index == 12:
        raw = bytearray()
        while len(raw) < 65536:
            byte, count = next(rng)%256, next(rng)%32 + 1
            raw.extend(bytes([byte])*min(count, 65536-len(raw)))
        packed, i = [], 0
        while i < len(raw):
            count = 1
            while i+count < len(raw) and raw[i+count] == raw[i] and count < 255:
                count += 1
            packed.append((count, raw[i]))
            i += count
        restored = b''.join(bytes([byte])*count for count, byte in packed)
        assert restored == raw
        value = str(len(packed)*2) + ',' + str(checksum(restored))
    elif index == 13:
        nodes = [hashlib.sha256(bytes(next(rng)>>24 for _ in range(1024))).digest() for _ in range(1024)]
        while len(nodes) > 1:
            nodes = [hashlib.sha256(nodes[i]+nodes[i+1]).digest() for i in range(0, len(nodes), 2)]
        value = nodes[0].hex()
    else:
        value = hashlib.pbkdf2_hmac('sha256', b'hal-benchmark-password', b'hal-benchmark-salt', 10000, 32).hex()
    return NAMES[index] + ':' + str(value)


if __name__ == '__main__':
    for i in range(15):
        print(reference(i))
