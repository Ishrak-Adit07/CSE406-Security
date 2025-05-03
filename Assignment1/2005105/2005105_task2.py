import random
import time
import sympy
from typing import Tuple, Optional

random.seed(20)

class EllipticCurve:

    def __init__(self, a: int, b: int, p: int):

        if not sympy.isprime(p):
            raise ValueError(f"Modulus {p} is not prime")
        
        # Checking for non-singularity
        disc = (4 * (a**3) + 27 * (b**2)) % p
        if disc == 0:
            raise ValueError(f"The curve with a={a}, b={b} is singular")
            
        self.a = a
        self.b = b
        self.p = p
        
    def is_on_curve(self, x: int, y: int) -> bool:
        left = (y * y) % self.p
        right = (x**3 + self.a * x + self.b) % self.p
        return left == right
    
    def add_points(self, p1: Optional[Tuple[int, int]], p2: Optional[Tuple[int, int]]) -> Optional[Tuple[int, int]]:

        if p1 is None:
            return p2
        if p2 is None:
            return p1
        
        x1, y1 = p1
        x2, y2 = p2
        
        if not self.is_on_curve(x1, y1) or not self.is_on_curve(x2, y2):
            raise ValueError("Points must be on the curve")
            
        # if p1 is the negative of p2, we return infinity
        if x1 == x2 and (y1 + y2) % self.p == 0:
            return None
            
        # general case
        if x1 == x2 and y1 == y2:
            numerator = (3 * (x1**2) + self.a) % self.p
            denominator = (2 * y1) % self.p
        else:
            numerator = (y2 - y1) % self.p
            denominator = (x2 - x1) % self.p
            
        denominator_inv = pow(denominator, self.p - 2, self.p)
        slope = (numerator * denominator_inv) % self.p
        
        x3 = (slope**2 - x1 - x2) % self.p
        y3 = (slope * (x1 - x3) - y1) % self.p
        
        return (x3, y3)
    
    def scalar_multiply(self, k: int, point: Optional[Tuple[int, int]]) -> Optional[Tuple[int, int]]:

        if k == 0 or point is None:
            return None
            
        if k < 0:
            x, y = point
            point = (x, (-y) % self.p)
            k = -k
            
        result = None
        addend = point
        
        while k:
            if k & 1:
                result = self.add_points(result, addend)
            addend = self.add_points(addend, addend)
            k >>= 1
            
        return result

def find_point_on_curve(curve: EllipticCurve) -> Tuple[int, int]:

    p = curve.p
    while True:
        x = random.randint(0, p - 1)
        right_side = (x**3 + curve.a * x + curve.b) % p
        
        if pow(right_side, (p - 1) // 2, p) == 1:
            y = tonelli_shanks(right_side, p)

            if random.choice([True, False]):
                y = p - y          

            assert curve.is_on_curve(x, y), "Generated point is not on the curve"
            return (x, y)

def tonelli_shanks(n: int, p: int) -> int:
    
    if p % 4 == 3:
        return pow(n, (p + 1) // 4, p)

    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1

    z = 2
    while pow(z, (p - 1) // 2, p) == 1:
        z += 1

    current_exponent = s
    non_residue_power = pow(z, q, p)
    t = pow(n, q, p)
    root = pow(n, (q + 1) // 2, p)

    while t != 1:
        i = 0
        temp = t
        while temp != 1:
            temp = (temp * temp) % p
            i += 1
            if i == current_exponent:
                return None

        b = pow(non_residue_power, 2 ** (current_exponent - i - 1), p)
        current_exponent = i
        non_residue_power = (b * b) % p
        t = (t * non_residue_power) % p
        root = (root * b) % p

    return root

def generate_parameters(key_size: int) -> Tuple[EllipticCurve, Tuple[int, int]]:

    p = sympy.randprime(2**(key_size-1), 2**key_size)
    while True:
        try:
            a = random.randint(0, p - 1)
            b = random.randint(0, p - 1)
            
            curve = EllipticCurve(a, b, p)
            
            G = find_point_on_curve(curve)
            
            return curve, G
        
        # invalid parameters
        except ValueError:
            continue

def generate_private_key(curve) -> int:
    return random.randint(1, curve.p - 1)

def generate_public_key(private_key: int, G: Tuple[int, int], curve) -> Tuple[int, int]:
    return curve.scalar_multiply(private_key, G)

def generate_shared_key(private_key: int, other_public_key: Tuple[int, int], curve) -> Tuple[int, int]:
    return curve.scalar_multiply(private_key, other_public_key)

def ecdh_key_exchange(curve: EllipticCurve, G: Tuple[int, int]) -> Tuple[int, Tuple[int, int], int, Tuple[int, int], Tuple[int, int]]:
    
    alice_private = random.randint(1, curve.p - 1)
    alice_public = curve.scalar_multiply(alice_private, G)
    
    bob_private = random.randint(1, curve.p - 1)
    bob_public = curve.scalar_multiply(bob_private, G)
    
    alice_shared = curve.scalar_multiply(alice_private, bob_public)
    
    bob_shared = curve.scalar_multiply(bob_private, alice_public)
    
    assert alice_shared == bob_shared, "ECDH key exchange failed: different shared secrets"
    
    return alice_private, alice_public, bob_private, bob_public, alice_shared


def measure_performance(key_sizes: list, num_trials: int = 5) -> dict:
    results = {}

    for key_size in key_sizes:
        private_key_times = []
        public_key_times = []
        shared_key_times = []

        for _ in range(num_trials):
            curve, G = generate_parameters(key_size)

            start = time.time()
            alice_private = random.randint(1, curve.p - 1)
            bob_private = random.randint(1, curve.p - 1)
            private_key_times.append(time.time() - start)

            start = time.time()
            alice_public = curve.scalar_multiply(alice_private, G)
            bob_public = curve.scalar_multiply(bob_private, G)
            public_key_times.append(time.time() - start)

            start = time.time()
            alice_shared = curve.scalar_multiply(alice_private, bob_public)
            bob_shared = curve.scalar_multiply(bob_private, alice_public)
            assert alice_shared == bob_shared, "ECDH key exchange failed"
            shared_key_times.append(time.time() - start)

        results[key_size] = {
            'avg_private_key_gen_time': sum(private_key_times) / num_trials,
            'avg_public_key_gen_time': sum(public_key_times) / num_trials,
            'avg_shared_key_derivation_time': sum(shared_key_times) / num_trials
            }

    return results


def main():
            
    # curve, G = generate_parameters(128)
    # print(f"\nGenerated Curve Parameters:")
    # print(f"p = {curve.p}")
    # print(f"a = {curve.a}")
    # print(f"b = {curve.b}")
    # print(f"Generator point G = {G}")
    
    # alice_private, alice_public, bob_private, bob_public, shared_secret = ecdh_key_exchange(curve, G)
    
    # print(f"\nAlice's private key = {alice_private}")
    # print(f"Alice's public key = {alice_public}")
    # print(f"Bob's private key = {bob_private}")
    # print(f"Bob's public key = {bob_public}")
    # print(f"Shared secret = {shared_secret}")

    key_sizes = [128, 192, 256]
    num_trials = 5
    results = measure_performance(key_sizes, num_trials)

    print("\n")
    print("-"*50)
    print(f"     K      |          Computation Time For          ")
    print(f"            --------------------------------------")
    print(f"            |   Private  |   Public   |  Shared Key  ")
    print("-"*50)
    print(f"    128     |  {results[128]['avg_private_key_gen_time']:.6f}  |  {results[128]['avg_public_key_gen_time']:.6f}  |  {results[128]['avg_shared_key_derivation_time']:.6f}  ")
    print("-"*50)
    print(f"    192     |  {results[192]['avg_private_key_gen_time']:.6f}  |  {results[192]['avg_public_key_gen_time']:.6f}  |  {results[192]['avg_shared_key_derivation_time']:.6f}  ")
    print("-"*50)
    print(f"    256     |  {results[256]['avg_private_key_gen_time']:.6f}  |  {results[256]['avg_public_key_gen_time']:.6f}  |  {results[256]['avg_shared_key_derivation_time']:.6f}  ")
    print("-"*50)
    print("\n")

if __name__ == "__main__":
    main()